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
	host         string       // relay IP this link presents to BOTH peers (distinct-IP mode)
	sockA, sockB *net.UDPConn // sockA: B sends here to reach A. sockB: A sends here to reach B.
	portA, portB int
	addrA, addrB atomic.Pointer[net.UDPAddr]
}

type relayManager struct {
	publicHost string
	hosts      []string // pool of relay IPs; empty => single publicHost on 0.0.0.0
	hostSeq    int      // round-robin cursor (guarded by mu)
	mu         sync.Mutex
	links      map[string]*relayLink
}

func newRelayManager(publicHost string) *relayManager {
	return &relayManager{publicHost: publicHost, links: map[string]*relayLink{}}
}

// setHosts enables distinct-IP mode: each peer link is bound to its own IP from
// the pool, so a console sees every peer at a DIFFERENT address (not just a
// different port). This works around the 3DS collapsing multiple peers that
// share one IP. Empty pool => legacy single-IP behaviour.
func (rm *relayManager) setHosts(hosts []string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.hosts = hosts
}

func pairKey(a, b uint64) string {
	if a > b {
		a, b = b, a
	}
	return fmt.Sprintf("%d-%d", a, b)
}

// openUDP binds an ephemeral UDP socket. When ip is non-empty the socket is
// bound to that specific local IP, so packets it sends carry that IP as source
// and the console sees the peer at that address.
func openUDP(ip string) (*net.UDPConn, int, error) {
	bindIP := net.IPv4zero
	if ip != "" {
		if p := net.ParseIP(ip); p != nil {
			bindIP = p
		}
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: bindIP, Port: 0})
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
	// Distinct-IP mode: give this link its own IP from the pool, round-robin.
	// Both sockets of the link bind to that IP so both peers see each other at
	// it. With one link per participant-pair and a pool >= (players-1), every
	// peer a console talks to lands on a different IP.
	host := ""
	if len(rm.hosts) > 0 {
		host = rm.hosts[rm.hostSeq%len(rm.hosts)]
		rm.hostSeq++
	}
	sa, pa, err := openUDP(host)
	if err != nil {
		return nil, err
	}
	sb, pb, err := openUDP(host)
	if err != nil {
		sa.Close()
		return nil, err
	}
	linkHost := host
	if linkHost == "" {
		linkHost = rm.publicHost
	}
	l := &relayLink{pidA: pidA, pidB: pidB, host: linkHost, sockA: sa, sockB: sb, portA: pa, portB: pb}
	rm.links[key] = l
	// A sends to sockB (portB) -> forward to B via sockA
	go l.pump(l.sockB, l.sockA, &l.addrA, &l.addrB)
	// B sends to sockA (portA) -> forward to A via sockB
	go l.pump(l.sockA, l.sockB, &l.addrB, &l.addrA)
	logf("RELAY  link %s on %s: reach-%d via udp/%d, reach-%d via udp/%d", key, linkHost, pidA, pa, pidB, pb)
	return l, nil
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
