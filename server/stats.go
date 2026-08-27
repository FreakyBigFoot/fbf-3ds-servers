package main

import (
	"encoding/json"
	"net/http"
	"sync"

	nex "github.com/PretendoNetwork/nex-go/v2"
)

// secureEndpoints holds every game's secure PRUDP endpoint so we can count the
// live authenticated connections for the dashboard.
var (
	secureEndpointsMu sync.RWMutex
	secureEndpoints   []*nex.PRUDPEndPoint
)

func registerSecureEndpoint(ep *nex.PRUDPEndPoint) {
	secureEndpointsMu.Lock()
	secureEndpoints = append(secureEndpoints, ep)
	secureEndpointsMu.Unlock()
}

// onlinePlayers counts distinct real console PIDs connected to a secure server
// right now (excluding the two internal server accounts, pid 1 and 2).
func onlinePlayers() []uint64 {
	seen := map[uint64]bool{}
	secureEndpointsMu.RLock()
	eps := append([]*nex.PRUDPEndPoint(nil), secureEndpoints...)
	secureEndpointsMu.RUnlock()
	for _, ep := range eps {
		if ep == nil || ep.Connections == nil {
			continue
		}
		ep.Connections.Each(func(_ string, c *nex.PRUDPConnection) bool {
			pid := uint64(c.PID())
			if pid > 2 {
				seen[pid] = true
			}
			return false
		})
	}
	out := make([]uint64, 0, len(seen))
	for pid := range seen {
		out = append(out, pid)
	}
	return out
}

func countQuery(q string) int {
	if postgres == nil {
		return 0
	}
	var n int
	if err := postgres.QueryRow(q).Scan(&n); err != nil {
		return 0
	}
	return n
}

type statsResponse struct {
	Online     int        `json:"online"`
	Rooms      int        `json:"rooms"`
	Registered int        `json:"registered"`
	CPU        float64    `json:"cpu"`
	MemUsed    int        `json:"mem_used"`
	MemTotal   int        `json:"mem_total"`
	NetKBps    float64    `json:"net_kbps"`
	Points     []geoPoint `json:"points"`
}

func currentStats() statsResponse {
	m := currentMetrics()
	return statsResponse{
		Online:     len(onlinePlayers()),
		Rooms:      countQuery("SELECT count(*) FROM matchmaking.gatherings WHERE registered = true"),
		Registered: countQuery("SELECT count(*) FROM ffe_accounts"),
		CPU:        m.CPU,
		MemUsed:    m.MemUsedMB,
		MemTotal:   m.MemTotalMB,
		NetKBps:    m.NetKBps,
		Points:     onlineLocations(),
	}
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(currentStats())
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(dashboardHTML))
}
