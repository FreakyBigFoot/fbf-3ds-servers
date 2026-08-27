package main

import (
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"

	nex "github.com/PretendoNetwork/nex-go/v2"
)

type geoPoint struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

var (
	geoMu       sync.Mutex
	geoCache    = map[string]geoPoint{} // ip -> approx point (zero = private/failed)
	geoInflight = map[string]bool{}
	geoClient   = &http.Client{Timeout: 4 * time.Second}
)

// geoLocate returns a cached approximate location for an IP. It never blocks:
// the first call for a new IP kicks off a background lookup and returns nothing;
// a later call returns the cached coordinates once they arrive.
func geoLocate(ip string) (geoPoint, bool) {
	geoMu.Lock()
	if p, ok := geoCache[ip]; ok {
		geoMu.Unlock()
		return p, p.Lat != 0 || p.Lon != 0
	}
	if geoInflight[ip] {
		geoMu.Unlock()
		return geoPoint{}, false
	}
	geoInflight[ip] = true
	geoMu.Unlock()
	go fetchGeo(ip)
	return geoPoint{}, false
}

func fetchGeo(ip string) {
	p := geoPoint{}
	if parsed := net.ParseIP(ip); parsed != nil && !parsed.IsPrivate() && !parsed.IsLoopback() {
		if resp, err := geoClient.Get("http://ip-api.com/json/" + ip + "?fields=status,lat,lon"); err == nil {
			var r struct {
				Status string  `json:"status"`
				Lat    float64 `json:"lat"`
				Lon    float64 `json:"lon"`
			}
			json.NewDecoder(resp.Body).Decode(&r)
			resp.Body.Close()
			if r.Status == "success" {
				// snap to ~city level (~0.3 deg) so it's a general area, not a pin
				p.Lat = float64(int(r.Lat/0.3)) * 0.3
				p.Lon = float64(int(r.Lon/0.3)) * 0.3
			}
		}
	}
	geoMu.Lock()
	geoCache[ip] = p
	delete(geoInflight, ip)
	geoMu.Unlock()
}

// onlineLocations returns approximate points for every connected console, for
// the dashboard map. No IPs or identities are exposed.
func onlineLocations() []geoPoint {
	ips := map[string]bool{}
	secureEndpointsMu.RLock()
	eps := append([]*nex.PRUDPEndPoint(nil), secureEndpoints...)
	secureEndpointsMu.RUnlock()
	for _, ep := range eps {
		if ep == nil || ep.Connections == nil {
			continue
		}
		ep.Connections.Each(func(_ string, c *nex.PRUDPConnection) bool {
			if uint64(c.PID()) > 2 {
				if addr := c.Address(); addr != nil {
					if host, _, err := net.SplitHostPort(addr.String()); err == nil {
						ips[host] = true
					}
				}
			}
			return false
		})
	}
	pts := []geoPoint{}
	for ip := range ips {
		if p, ok := geoLocate(ip); ok {
			pts = append(pts, p)
		}
	}
	return pts
}
