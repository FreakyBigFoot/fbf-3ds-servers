package main

import (
	"fmt"
	"sync"
	"time"

	nex "github.com/PretendoNetwork/nex-go/v2"
)

// Session logging: record every secure-endpoint connect/disconnect so we can tell
// a clean "player left" from a silent network/NAT drop (no DISCONNECT packet).
// Keyed by remote address, which is stable for the life of a PRUDP session and
// present on both the connect packet and the ended connection.
var (
	sessMu       sync.Mutex
	sessStart    = map[string]time.Time{} // addr -> connect time
	sessExplicit = map[string]bool{}      // addr -> saw an explicit DISCONNECT packet
)

func addrOf(c nex.ConnectionInterface) string {
	if a := c.Address(); a != nil {
		return a.String()
	}
	return "?"
}

func pidOf(c nex.ConnectionInterface) string {
	return fmt.Sprintf("%d", uint64(c.PID()))
}

func installSessionLogging(name string, ep *nex.PRUDPEndPoint) {
	ep.OnConnect(func(p nex.PacketInterface) {
		c := p.Sender()
		addr := addrOf(c)
		sessMu.Lock()
		sessStart[addr] = time.Now()
		delete(sessExplicit, addr)
		sessMu.Unlock()
		logf("SESSION [%s] CONNECT    pid=%s from %s", name, pidOf(c), addr)
	})

	ep.OnDisconnect(func(p nex.PacketInterface) {
		addr := addrOf(p.Sender())
		sessMu.Lock()
		sessExplicit[addr] = true
		sessMu.Unlock()
	})

	ep.OnConnectionEnded(func(c *nex.PRUDPConnection) {
		addr := addrOf(c)
		sessMu.Lock()
		start, ok := sessStart[addr]
		explicit := sessExplicit[addr]
		delete(sessStart, addr)
		delete(sessExplicit, addr)
		sessMu.Unlock()

		dur := "unknown"
		if ok {
			dur = time.Since(start).Round(time.Second).String()
		}
		reason := "DROPPED (no disconnect packet - network/NAT timeout)"
		if explicit {
			reason = "client left (clean disconnect)"
		}
		logf("SESSION [%s] DISCONNECT pid=%s from %s  after %s  reason=%s", name, pidOf(c), addr, dur, reason)
	})
}
