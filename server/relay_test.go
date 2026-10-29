package main

import (
	"fmt"
	"testing"
)

// TestRelayMeshAllocation verifies the property the >2-player fix relies on:
// every participant PAIR gets its own link, link() is idempotent per pair
// regardless of argument order, and each participant reaches every distinct
// peer through a DISTINCT relay port. The old code kept a single link per PID,
// which collapsed 3+ players onto one relationship.
func TestRelayMeshAllocation(t *testing.T) {
	rm := newRelayManager("1.2.3.4")
	pids := []uint64{10, 20, 30, 40} // 4 players -> C(4,2)=6 pairs

	// Build the full mesh.
	for i := 0; i < len(pids); i++ {
		for j := i + 1; j < len(pids); j++ {
			if _, err := rm.link(pids[i], pids[j]); err != nil {
				t.Fatalf("link(%d,%d): %v", pids[i], pids[j], err)
			}
		}
	}

	if got, want := len(rm.links), 6; got != want {
		t.Fatalf("mesh link count = %d, want %d", got, want)
	}

	for i := 0; i < len(pids); i++ {
		for j := i + 1; j < len(pids); j++ {
			a, b := pids[i], pids[j]

			// Idempotent + order-independent: same object either way.
			l1, _ := rm.link(a, b)
			l2, _ := rm.link(b, a)
			if l1 != l2 {
				t.Fatalf("link(%d,%d) != link(%d,%d): not idempotent", a, b, b, a)
			}

			// Each side reaches the other via a distinct, nonzero port.
			pa := l1.endpointFor(a)
			pb := l1.endpointFor(b)
			if pa == 0 || pb == 0 {
				t.Fatalf("pair %d-%d has zero port: %d/%d", a, b, pa, pb)
			}
			if pa == pb {
				t.Fatalf("pair %d-%d: endpointFor collides on port %d", a, b, pa)
			}
		}
	}

	// The core regression check: for a single participant, the port used to be
	// reachable by peer X must differ from the port for peer Y. With the old
	// single-link-per-PID design these collapsed to one port.
	for _, self := range pids {
		seen := map[uint16]uint64{}
		for _, peer := range pids {
			if peer == self {
				continue
			}
			l, _ := rm.link(self, peer)
			p := l.endpointFor(self)
			if other, dup := seen[p]; dup {
				t.Fatalf("pid %d reaches peers %d and %d on the SAME relay port %d",
					self, other, peer, p)
			}
			seen[p] = peer
		}
		if got := len(seen); got != len(pids)-1 {
			t.Fatalf("pid %d: %d distinct relay ports, want %d", self, got, len(pids)-1)
		}
	}

	fmt.Printf("mesh OK: %d players -> %d links, per-peer distinct ports\n", len(pids), len(rm.links))
}
