package main

import (
	"net"
	"strings"
	"testing"
)

// FFE_PUBLIC_HOST ends up verbatim inside NEX station URLs, which the 3DS only
// accepts as dotted IPv4. resolvePublicHost must therefore hand back an IPv4
// literal for every accepted input and reject everything else.
func TestResolvePublicHost(t *testing.T) {
	for _, lit := range []string{"203.0.113.10", "127.0.0.1", "209.141.53.207"} {
		if got, err := resolvePublicHost(lit); err != nil || got != lit {
			t.Fatalf("IPv4 literal %s: got %q, %v", lit, got, err)
		}
	}
	if _, err := resolvePublicHost("2001:db8::1"); err == nil || !strings.Contains(err.Error(), "IPv4") {
		t.Fatalf("IPv6 literal must be rejected, got err=%v", err)
	}
	// Live DNS via the public resolver (skipped, not failed, when offline).
	got, err := resolvePublicHost("dns.google")
	if err != nil {
		t.Skipf("no DNS/network available: %v", err)
	}
	if ip := net.ParseIP(got); ip == nil || ip.To4() == nil {
		t.Fatalf("hostname resolved to %q, want a dotted IPv4", got)
	}
	if _, err := resolvePublicHost("nope.invalid"); err == nil {
		t.Fatalf("unresolvable name must be rejected")
	}
}
