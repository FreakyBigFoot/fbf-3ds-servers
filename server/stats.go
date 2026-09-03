package main

import (
	"encoding/json"
	"net/http"
	"sync"

	nex "github.com/PretendoNetwork/nex-go/v2"
)

// secureEndpoints holds every hosted game's secure PRUDP endpoint (with a clean
// display name) so we can report per-game live stats on the dashboard.
type namedEndpoint struct {
	Name   string
	GameID string
	EP     *nex.PRUDPEndPoint
}

var (
	secureEndpointsMu sync.RWMutex
	secureEndpoints   []namedEndpoint
)

func registerSecureEndpoint(name, gameID string, ep *nex.PRUDPEndPoint) {
	secureEndpointsMu.Lock()
	secureEndpoints = append(secureEndpoints, namedEndpoint{Name: name, GameID: gameID, EP: ep})
	secureEndpointsMu.Unlock()
}

func endpointsSnapshot() []namedEndpoint {
	secureEndpointsMu.RLock()
	defer secureEndpointsMu.RUnlock()
	return append([]namedEndpoint(nil), secureEndpoints...)
}

// endpointOnlinePIDs returns the distinct real console PIDs (excluding the two
// internal server accounts) connected to one secure endpoint right now.
func endpointOnlinePIDs(ep *nex.PRUDPEndPoint) map[uint64]bool {
	seen := map[uint64]bool{}
	if ep == nil || ep.Connections == nil {
		return seen
	}
	ep.Connections.Each(func(_ string, c *nex.PRUDPConnection) bool {
		if pid := uint64(c.PID()); pid > 2 {
			seen[pid] = true
		}
		return false
	})
	return seen
}

// onlinePlayers counts distinct real console PIDs across all games.
func onlinePlayers() []uint64 {
	seen := map[uint64]bool{}
	for _, ne := range endpointsSnapshot() {
		for pid := range endpointOnlinePIDs(ne.EP) {
			seen[pid] = true
		}
	}
	out := make([]uint64, 0, len(seen))
	for pid := range seen {
		out = append(out, pid)
	}
	return out
}

// registeredGatheringOwners returns the owner PID of every active (registered)
// gathering, so we can attribute rooms to whichever game their host is on.
func registeredGatheringOwners() []uint64 {
	if postgres == nil {
		return nil
	}
	rows, err := postgres.Query("SELECT owner_pid FROM matchmaking.gatherings WHERE registered = true")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []uint64
	for rows.Next() {
		var pid uint64
		if rows.Scan(&pid) == nil {
			out = append(out, pid)
		}
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

type gameStat struct {
	Name   string `json:"name"`
	GameID string `json:"game_id"`
	Online int    `json:"online"`
	Rooms  int    `json:"rooms"`
}

type statsResponse struct {
	Online     int        `json:"online"`
	Rooms      int        `json:"rooms"`
	Registered int        `json:"registered"`
	Games      []gameStat `json:"games"`
	CPU        float64    `json:"cpu"`
	MemUsed    int        `json:"mem_used"`
	MemTotal   int        `json:"mem_total"`
	NetKBps    float64    `json:"net_kbps"`
	Points     []geoPoint `json:"points"`
}

func currentStats() statsResponse {
	m := currentMetrics()
	owners := registeredGatheringOwners()

	eps := endpointsSnapshot()
	games := make([]gameStat, 0, len(eps))
	totalOnline := map[uint64]bool{}
	totalRooms := 0
	for _, ne := range eps {
		pids := endpointOnlinePIDs(ne.EP)
		for p := range pids {
			totalOnline[p] = true
		}
		rooms := 0
		for _, o := range owners {
			if pids[o] {
				rooms++
			}
		}
		totalRooms += rooms
		games = append(games, gameStat{Name: ne.Name, GameID: ne.GameID, Online: len(pids), Rooms: rooms})
	}

	return statsResponse{
		Online:     len(totalOnline),
		Rooms:      totalRooms,
		Registered: countQuery("SELECT count(*) FROM ffe_accounts"),
		Games:      games,
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
