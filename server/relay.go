package main

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
)

// Transparent UDP relay for 3DS P2P. Two consoles that can't reach each other
// directly are each handed a UDP endpoint on THIS server as their peer address.
// A packet arriving for one console is forwarded out to the other, so each side
// believes it is talking directly to its peer. Both consoles connect OUTBOUND
// to the relay, so it works through any NAT (and past WiFi client isolation).
// PRUDP per-packet signatures use the exchanged connection signature, not
// addresses, so relaying does not invalidate them.

type relayLink struct {
	pidA, pidB   uint64
	sockA, sockB *net.UDPConn // sockA: B sends here to reach A. sockB: A sends here to reach B.
	portA, portB int
	addrA, addrB atomic.Pointer[net.UDPAddr]
}

type relayManager struct {
	publicHost string
	mu         sync.Mutex
	links      map[string]*relayLink
}

func newRelayManager(publicHost string) *relayManager {
	return &relayManager{publicHost: publicHost, links: map[string]*relayLink{}}
}

func pairKey(a, b uint64) string {
	if a > b {
		a, b = b, a
	}
	return fmt.Sprintf("%d-%d", a, b)
}

func openUDP() (*net.UDPConn, int, error) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, 0, err
	}
	return c, c.LocalAddr().(*net.UDPAddr).Port, nil
}

func (rm *relayManager) link(pidA, pidB uint64) (*relayLink, error) {
	key := pairKey(pidA, pidB)
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if l, ok := rm.links[key]; ok {
		return l, nil
	}
	sa, pa, err := openUDP()
	if err != nil {
		return nil, err
	}
	sb, pb, err := openUDP()
	if err != nil {
		sa.Close()
		return nil, err
	}
	l := &relayLink{pidA: pidA, pidB: pidB, sockA: sa, sockB: sb, portA: pa, portB: pb}
	rm.links[key] = l
	// A sends to sockB (portB) -> forward to B via sockA
	go l.pump(l.sockB, l.sockA, &l.addrA, &l.addrB)
	// B sends to sockA (portA) -> forward to A via sockB
	go l.pump(l.sockA, l.sockB, &l.addrB, &l.addrA)
	logf("RELAY  link %s: reach-%d via udp/%d, reach-%d via udp/%d", key, pidA, pa, pidB, pb)
	return l, nil
}

// linkForPID returns an existing link that involves pid (for the 2-player case
// where only one participant is known).
func (rm *relayManager) linkForPID(pid uint64) *relayLink {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	for _, l := range rm.links {
		if l.pidA == pid || l.pidB == pid {
			return l
		}
	}
	return nil
}

func (l *relayLink) pump(in, out *net.UDPConn, srcAddr, dstAddr *atomic.Pointer[net.UDPAddr]) {
	buf := make([]byte, 2048)
	for {
		n, addr, err := in.ReadFromUDP(buf)
		if err != nil {
			return
		}
		srcAddr.Store(addr)
		if dst := dstAddr.Load(); dst != nil {
			out.WriteToUDP(buf[:n], dst)
		}
	}
}

// endpointFor returns the relay UDP port a caller should use to reach targetPID.
func (l *relayLink) endpointFor(targetPID uint64) uint16 {
	if targetPID == l.pidA {
		return uint16(l.portA)
	}
	return uint16(l.portB)
}
