package main

// Relay v2: per-console relay identity (TURN-style), opt-in via FFE_RELAY_V2=1.
// See relay-redesign-design.md and the packet analysis in memory ffe-relay-v2-turn.
//
// WHY the earlier v2 (rewrite GetSessionURLs+ProbeInit) still failed for the 3rd
// peer: packet capture proved the host replies to a peer's NAT probe using the
// address it ALREADY HOLDS for that peer. The 2nd joiner's address was learned
// entirely through our rewritten flows (= relay identity, works). But the 3rd
// joiner's address reaches the host through the already-running Pia mesh, which
// carries the peer's REGISTERED station address (its LAN/direct address). So the
// host aimed replies at the 3rd peer's direct address, they died in NAT, and the
// 3rd peer looped its probes forever.
//
// THE FIX: assign each console ONE relay identity at REGISTRATION and OVERWRITE
// connection.StationURLs with it. Everything the server ever distributes about a
// console — GetSessionURLs, the participant list, the Pia mesh handoff — then
// carries the relay identity, so every peer (2nd, 3rd, 4th) reaches every other
// only through the relay. Consoles connect OUTBOUND to the relay, so any NAT works.
//
// Forwarding: a packet arriving at console X's identity from src is matched to a
// sender console by public IP (exact when players are on different networks, the
// case being fixed), src recorded as that console's real P2P address, then
// forwarded to X's real address SENDING FROM the sender's identity socket — so X
// sees the sender at the sender's identity, consistently from every vantage point.

import (
	"database/sql"
	"encoding/binary"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PretendoNetwork/nex-go/v2"
)

type v2Peer struct {
	pid       uint64
	publicIP  string // console public IP as seen by the NEX server (for sender id)
	identity  *net.UDPConn
	port      int
	mu        sync.Mutex
	realTo    map[uint64]*net.UDPAddr // this console's real address WHEN talking to peer <key>
	pending   map[uint64]*pendingPkt  // packet held for peer <key> until we learn our address for it
	seenFlows sync.Map

	// refreshedAtNanos is the last time this identity saw relay traffic or (re)registered,
	// stored atomically. The sweeper frees an identity only after it has been idle for
	// minutes — so a live or briefly-reconnecting console is NEVER swept out from under a join.
	refreshedAtNanos int64

	// Probe parameters learned from this console's own NAT-probe requests, so the
	// relay can synthesize a valid reply on this console's behalf (probe-assist).
	probeKnown bool
	probeSid   uint8  // packet offset 4  (this console's probe session id)
	probeID    uint32 // packet offset 12 (this console's probe connection id)
	probeSeq   uint16 // packet offset 9  (latest sequence, incremented for synth)
}

// pendingPkt is one packet buffered for a target until its socket is learned,
// plus the sender identity socket it must be sent FROM.
type pendingPkt struct {
	data []byte
	via  *net.UDPConn
}

// touch marks this identity as recently active (register or relay traffic).
func (p *v2Peer) touch() { atomic.StoreInt64(&p.refreshedAtNanos, time.Now().UnixNano()) }

// idle reports how long since this identity last saw activity.
func (p *v2Peer) idle() time.Duration {
	return time.Since(time.Unix(0, atomic.LoadInt64(&p.refreshedAtNanos)))
}

// recentlyActive reports whether the console for pid has sent relay (P2P) traffic
// within the given window. During active co-op the pump touches the sender on
// every forwarded packet, so a console still in a live party stays "active" here
// even when it has gone silent toward the NEX server. Used to hold the server
// connection open instead of timing it out mid-game. Returns false for consoles
// that have no relay identity (non-v2), leaving their kick behaviour unchanged.
func (r *relayV2) recentlyActive(pid uint64, within time.Duration) bool {
	r.mu.RLock()
	p, ok := r.byPID[pid]
	r.mu.RUnlock()
	if !ok {
		return false
	}
	return p.idle() < within
}

// stillInSession is the keepalive predicate wired into nex.KeepAliveWhileActive:
// a console counts as in a live party if it has relayed P2P traffic in the last
// 30s. Continuous co-op traffic keeps idle() near zero; once the party truly ends
// and P2P stops, the window lapses and the normal server kick proceeds.
func (r *relayV2) stillInSession(pid uint64) bool {
	return r.recentlyActive(pid, 30*time.Second)
}

func (p *v2Peer) setRealTo(peer uint64, a *net.UDPAddr) {
	p.touch()
	p.mu.Lock()
	if p.realTo == nil {
		p.realTo = map[uint64]*net.UDPAddr{}
	}
	p.realTo[peer] = a
	// Flush any packet that was waiting on this address (fixes the startup race
	// where a peer's first probe would otherwise be dropped).
	var flush *pendingPkt
	if p.pending != nil {
		if pp := p.pending[peer]; pp != nil {
			flush = pp
			delete(p.pending, peer)
		}
	}
	p.mu.Unlock()
	if flush != nil {
		flush.via.WriteToUDP(flush.data, a)
	}
}

// deliverTo returns p's real address for talking to `peer` if known; otherwise it
// buffers the packet (copied, to be flushed by setRealTo the instant the address
// is learned) and returns nil. Check+buffer is atomic under p.mu, so it cannot
// race with a concurrent setRealTo from the peer's pump goroutine.
func (p *v2Peer) deliverTo(peer uint64, data []byte, via *net.UDPConn) *net.UDPAddr {
	p.mu.Lock()
	defer p.mu.Unlock()
	if a := p.realTo[peer]; a != nil {
		return a
	}
	if p.pending == nil {
		p.pending = map[uint64]*pendingPkt{}
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	p.pending[peer] = &pendingPkt{data: cp, via: via}
	return nil
}

// --- Probe-assist: the relay completes the NAT hole-punch itself -------------
//
// FFE's 3+ player mesh fails on the joiner<->joiner link purely on TIMING: each
// console probes the other only briefly, and the two probe windows never overlap
// (proven by capture: pia probes cell once then quits ~3s later; cell doesn't
// probe pia until AFTER pia has left). Per Kinnay's NintendoClients reference, a
// console sends a probe REPLY simply on RECEIVING a probe REQUEST, after which it
// opens the station connection. Since every packet already flows through the relay
// and these probes carry no cryptographic signature (only a 1-byte checksum we can
// recompute), the relay answers each request on the peer's behalf INSTANTLY — so
// neither console has to wait for the other to be probing at the same moment.
//
// Packet layout (25 bytes, verified against real captures):
//   [0:2]=51 51  [2]=05(NAT stream)  [3]=00  [4]=session id  [5:9]=00 00 00 00
//   [9:11]=seq(LE u16)  [11]=type(0=request,1=reply)  [12:16]=conn id(LE u32)
//   [16:20]=echo field (reply copies it verbatim from the request)  [20:24]=0
//   [24]=checksum

func isV0ProbeRequest(b []byte) bool {
	return len(b) >= 25 && b[0] == 0x51 && b[1] == 0x51 && b[2] == 0x05 && b[11] == 0x00
}

// probeChecksum is the PRUDPv0 word-sum checksum used by these Pia probes. Verified
// to reproduce every captured probe's trailing byte exactly (the NEX access-key base
// contributes zero for this stream). data is the whole packet except the checksum.
func probeChecksum(data []byte) byte {
	var temp uint32
	n := len(data) &^ 3
	for i := 0; i < n; i += 4 {
		temp += binary.LittleEndian.Uint32(data[i : i+4])
	}
	var sum uint32
	var tb [4]byte
	binary.LittleEndian.PutUint32(tb[:], temp)
	for _, x := range tb {
		sum += uint32(x)
	}
	for _, x := range data[n:] { // trailing bytes (none for 24-byte body, kept for safety)
		sum += uint32(x)
	}
	return byte(sum & 0xFF)
}

// learnProbe records this console's own probe parameters from one of its requests,
// so the relay can later forge a valid reply on its behalf.
func (p *v2Peer) learnProbe(req []byte) {
	if len(req) < 25 {
		return
	}
	p.mu.Lock()
	p.probeSid = req[4]
	p.probeID = binary.LittleEndian.Uint32(req[12:16])
	p.probeSeq = binary.LittleEndian.Uint16(req[9:11])
	p.probeKnown = true
	p.mu.Unlock()
}

// synthReplyFor builds the probe REPLY that peer p would send in answer to `req`
// (a request from some other console), or nil if p's probe params aren't known yet.
// The reply echoes req's echo field but carries p's own session/conn id and seq.
func (p *v2Peer) synthReplyFor(req []byte) []byte {
	if len(req) < 25 {
		return nil
	}
	p.mu.Lock()
	if !p.probeKnown {
		p.mu.Unlock()
		return nil
	}
	sid, id := p.probeSid, p.probeID
	p.probeSeq++
	seq := p.probeSeq
	p.mu.Unlock()

	out := make([]byte, 25)
	copy(out, req[:24])
	out[4] = sid
	binary.LittleEndian.PutUint16(out[9:11], seq)
	out[11] = 0x01 // reply
	binary.LittleEndian.PutUint32(out[12:16], id)
	// out[16:20] (echo field) already copied from req
	out[24] = probeChecksum(out[:24])
	return out
}

type relayV2 struct {
	publicHost string
	mu         sync.RWMutex
	byPID      map[uint64]*v2Peer

	// SAME-IP disambiguation. Two consoles behind one public IP can't be told apart
	// by IP alone. But each console stamps its own connection id on its NAT-probe
	// packets, and (verified in capture 2026-09-18) uses ONE source port for both its
	// probe and its whole game stream. So: learn (srcIP:srcPort)->console from the
	// self-identifying probe, and every later packet from that port routes correctly.
	//   rvcidToPID: console connection id (RVCID) -> PID, recorded at registration.
	//   flowMap:    "ip:port" -> *v2Peer, learned from probes; checked before IP match.
	rvcidToPID sync.Map // uint32 -> uint64
	flowMap    sync.Map // string  -> *v2Peer

	// natCapable records, per PID, whether the console's NAT can reliably
	// hole-punch directly (endpoint-independent mapping). Learned at register and
	// used to decide direct-vs-relay before any probe. Missing/false => relay.
	natCapable sync.Map // uint64 -> bool
}

var relay2 *relayV2

// Cached at relay init (env is fixed for the process lifetime) so the per-packet
// pump hot path never calls os.Getenv.
var (
	v2Trace       bool // FFE_RELAY_V2_TRACE=1
	v2ProbeAssist bool // probe-assist on unless FFE_RELAY_V2_PROBEASSIST=0
)

func newRelayV2(publicHost string) *relayV2 {
	v2Trace = os.Getenv("FFE_RELAY_V2_TRACE") == "1"
	v2ProbeAssist = os.Getenv("FFE_RELAY_V2_PROBEASSIST") != "0"
	logf("RELAY2 flags: trace=%v probeAssist=%v (cached at init)", v2Trace, v2ProbeAssist)
	return &relayV2{publicHost: publicHost, byPID: map[uint64]*v2Peer{}}
}

// v2Enabled reports whether relay v2 applies to this console PID (gated by
// FFE_RELAY_V2 + optional FFE_RELAY_V2_PIDS allowlist).
func v2Enabled(pid uint64) bool {
	if os.Getenv("FFE_RELAY_V2") != "1" || relay2 == nil {
		return false
	}
	allow := os.Getenv("FFE_RELAY_V2_PIDS")
	if allow == "" {
		return true
	}
	return pidInCSV(pid, allow)
}

// hybridDirect reports whether pid is in FFE_HYBRID_PIDS. Those consoles OPT OUT
// of the forced relay identity and instead advertise their REAL public address,
// so the NAT probe attempts a DIRECT (low-latency) peer connection. Read live per
// call. Empty list = nobody, so every console stays on the proven full-relay path
// — deploying this with the list unset changes nothing. For a direct link to work
// both consoles in the pair must be listed (otherwise one side hands out a relay
// address and the other a real address, and the hole-punch mismatches).
func hybridDirect(pid uint64) bool {
	list := os.Getenv("FFE_HYBRID_PIDS")
	return list != "" && pidInCSV(pid, list)
}

// noteNAT records whether a console can hole-punch directly (endpoint-independent
// mapping), learned from its self-reported NAT type at register.
func (r *relayV2) noteNAT(pid uint64, direct bool) { r.natCapable.Store(pid, direct) }

// directCapable reports whether pid's NAT can reliably hole-punch directly. Both
// ends of a link must be direct-capable for it to safely skip the relay. Unknown
// consoles (never registered NAT info) report false => relay, the safe default.
func (r *relayV2) directCapable(pid uint64) bool {
	if v, ok := r.natCapable.Load(pid); ok {
		return v.(bool)
	}
	return false
}

// canDirect reports whether a console should take the direct path: its detected
// NAT is endpoint-independent (auto, for everyone) OR it's in the FFE_HYBRID_PIDS
// manual test list. A LINK is direct only when BOTH ends canDirect; otherwise it
// stays on the relay. Symmetric/unknown consoles are unaffected — they relay as
// before, so enabling this can't regress the players who need the relay.
func canDirect(pid uint64) bool {
	// Auto-direct is OFF by default: the known-good build relays everyone, any NAT.
	// Only a validated, explicitly-enabled test flips FFE_HYBRID_AUTO=1. With it
	// unset this returns false, so every register/GetSessionURLs/ProbeInit path
	// falls through to the relay exactly as the known-good build did.
	if os.Getenv("FFE_HYBRID_AUTO") != "1" {
		return false
	}
	return relay2 != nil && (relay2.directCapable(pid) || hybridDirect(pid))
}

// identityFor returns (creating if needed) the relay identity for a console, and
// records its current public IP.
func (r *relayV2) identityFor(pid uint64, publicIP string) *v2Peer {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.byPID[pid]
	if !ok {
		conn, port, err := openUDP("")
		if err != nil {
			logf("RELAY2 pid=%d: cannot open identity socket: %v", pid, err)
			return nil
		}
		p = &v2Peer{pid: pid, port: port, identity: conn}
		r.byPID[pid] = p
		go p.pump()
		logf("RELAY2 pid=%d: identity %s:%d", pid, r.publicHost, port)
	}
	if publicIP != "" {
		p.publicIP = publicIP
	}
	p.touch() // register counts as activity, giving reconnects a full idle grace window
	return p
}

func (r *relayV2) portFor(pid uint64) uint16 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if p, ok := r.byPID[pid]; ok {
		return uint16(p.port)
	}
	return 0
}

// senderFor identifies which console sent a packet from src and records src as
// that console's real P2P address. Matches by public IP (unique for players on
// different networks). Returns nil if unidentifiable.
func (r *relayV2) senderFor(src *net.UDPAddr) *v2Peer {
	// A learned per-flow owner (from the self-identifying probe) wins over the IP
	// guess — this is what lets two consoles on one public IP be told apart.
	if v, ok := r.flowMap.Load(src.String()); ok {
		return v.(*v2Peer)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	ip := src.IP.String()
	// Unambiguous when one console has this IP. If two share it we can't pick here,
	// but the probe tags the flow (learnFlow) before game traffic arrives, so this
	// path is only the brief pre-probe window.
	for _, p := range r.byPID {
		if p.publicIP != "" && p.publicIP == ip {
			return p
		}
	}
	return nil
}

// isV0Probe matches a Pia NAT probe (request or reply); both carry the sender's
// connection id at [12:16], which is what we use to attribute same-IP flows.
func isV0Probe(b []byte) bool {
	return len(b) >= 25 && b[0] == 0x51 && b[1] == 0x51 && b[2] == 0x05 && (b[11] == 0x00 || b[11] == 0x01)
}

// noteRVCID records a console's connection id -> PID (called at registration), so a
// probe carrying that id can be attributed to the right console.
func (r *relayV2) noteRVCID(rvcid uint32, pid uint64) {
	if rvcid != 0 {
		r.rvcidToPID.Store(rvcid, pid)
	}
}

func (r *relayV2) peerByRVCID(rvcid uint32) *v2Peer {
	v, ok := r.rvcidToPID.Load(rvcid)
	if !ok {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byPID[v.(uint64)]
}

// learnFlow tags a source (ip:port) with the console that sent this probe from it.
// Because a console uses one source port for its probe AND its game stream, every
// later packet from this port then routes to the right console — even under a shared
// public IP. No-op if the probe's connection id isn't mapped yet (falls back to IP).
func (r *relayV2) learnFlow(src *net.UDPAddr, probe []byte) {
	if len(probe) < 16 {
		return
	}
	rvcid := binary.LittleEndian.Uint32(probe[12:16])
	peer := r.peerByRVCID(rvcid)
	if peer == nil {
		return
	}
	key := src.String()
	prev, existed := r.flowMap.Load(key)
	if !existed || prev.(*v2Peer) != peer {
		r.flowMap.Store(key, peer)
		logf("RELAY2 FLOW-LEARN %s -> pid=%d (rvcid=%d)", key, peer.pid, rvcid)
	}
}

func cloneUDPAddr(a *net.UDPAddr) *net.UDPAddr {
	ip := make(net.IP, len(a.IP))
	copy(ip, a.IP)
	return &net.UDPAddr{IP: ip, Port: a.Port, Zone: a.Zone}
}

func (p *v2Peer) pump() {
	defer func() {
		if r := recover(); r != nil {
			logf("RELAY2 pid=%d: recovered from panic in pump: %v", p.pid, r)
		}
	}()
	buf := make([]byte, 2048)
	for {
		n, src, err := p.identity.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// Tag the flow from its self-identifying probe BEFORE resolving the sender, so
		// even this packet — and all the game traffic that follows on this same port —
		// attributes to the right console under a shared public IP.
		if isV0Probe(buf[:n]) {
			relay2.learnFlow(src, buf[:n])
		}
		sender := relay2.senderFor(src)
		if v2Trace {
			key := src.String()
			if _, seen := p.seenFlows.LoadOrStore(key, true); !seen {
				sp := "?"
				if sender != nil {
					sp = strconv.FormatUint(sender.pid, 10)
				}
				logf("RELAY2 FLOW recv@:%d(target=%d) from=%s sender=%s", p.port, p.pid, src, sp)
			}
		}
		if sender == nil {
			continue
		}
		// Learn the sender's real address FOR THIS FLOW (sender -> p): consoles
		// use a separate UDP socket per peer/stream, so we must key the address by
		// (sender, target), not per console, or replies land on the wrong socket.
		sender.setRealTo(p.pid, cloneUDPAddr(src))

		// Probe-assist: if this is a NAT-probe REQUEST (sender -> p), learn the
		// sender's probe params and immediately answer on p's behalf so the sender's
		// hole-punch to p succeeds without waiting for p to be probing too. The real
		// request is still forwarded below, so the stock handshake also proceeds.
		if v2ProbeAssist && isV0ProbeRequest(buf[:n]) {
			sender.learnProbe(buf[:n])
			if reply := p.synthReplyFor(buf[:n]); reply != nil {
				p.identity.WriteToUDP(reply, src)
				if v2Trace {
					logf("RELAY2 PROBE-ASSIST: answered %d's probe on behalf of %d (@:%d)", sender.pid, p.pid, p.port)
				}
			}
		}
		// Forward to p at the address p uses when talking to this sender. If p
		// hasn't sent to sender yet we don't know p's socket for this flow, so
		// buffer this packet and let setRealTo flush it the instant the address is
		// learned — saves the startup round trip instead of dropping the probe.
		if dst := p.deliverTo(sender.pid, buf[:n], sender.identity); dst != nil {
			sender.identity.WriteToUDP(buf[:n], dst)
		}
	}
}

// rewriteStationURLs replaces a console's registered station URLs with a single
// URL pointing at its relay identity, so the whole mesh distributes the relay
// address for it. Called from the RegisterEx/Register hook.
func (r *relayV2) rewriteStationURLs(connection *nex.PRUDPConnection) {
	pid := uint64(connection.PID())
	publicIP := ""
	if ua, ok := connection.Address().(*net.UDPAddr); ok && ua != nil {
		publicIP = ua.IP.String()
	}
	p := r.identityFor(pid, publicIP)
	if p == nil {
		return
	}
	// Rewrite the PUBLIC station in place to the relay identity, preserving every
	// other param the game set (sid/natf/natm/pmp/upnp/PID/RVCID). Building a
	// fresh URL dropped those and broke the join. The local (LAN) station is left
	// alone; remote peers can't use it anyway, so they fall through to the relay.
	changed := false
	for i := range connection.StationURLs {
		if connection.StationURLs[i].IsPublic() {
			connection.StationURLs[i].SetAddress(r.publicHost)
			connection.StationURLs[i].SetPortNumber(uint16(p.port))
			changed = true
		}
	}
	if changed {
		logf("RELAY2 pid=%d: public station rewritten to identity %s:%d (was %s)", pid, r.publicHost, p.port, publicIP)
	} else {
		logf("RELAY2 pid=%d: no public station to rewrite (identity %s:%d ready)", pid, r.publicHost, p.port)
	}
}

// release closes a console's identity (on disconnect).
func (r *relayV2) release(pid uint64) {
	r.mu.Lock()
	p := r.byPID[pid]
	delete(r.byPID, pid)
	r.mu.Unlock()
	if p != nil {
		p.identity.Close()
		logf("RELAY2 pid=%d: identity released", pid)
	}
}

// startSweeper closes identities whose console is no longer connected anywhere.
// startSweeper frees relay identities that have been idle (no traffic, no
// re-registration) for longer than maxIdentityIdle. This is deliberately based on
// ACTIVITY, not on matchmaking DB state: the previous DB-based sweeper released an
// identity whenever the console momentarily had no registered gathering — which
// happens for a second or two on every reconnect, so it deleted the relay address of
// a console that had JUST re-registered (especially a flaky host), handing joiners a
// dead ":0" address. Activity-based release never touches a live or reconnecting
// console, and it lets identities survive brief network blips so the mesh re-forms on
// the SAME addresses. (db param kept for call-site compatibility; no longer used.)
// startSweeper is intentionally a NO-OP. An earlier idle-based sweep freed a host's
// relay identity when it sat in a lobby with no P2P traffic for a few minutes, which
// then handed joiners a dead ":0" address and kicked them (regression seen 2026-09-13).
// Identities are cheap (one UDP socket each) and now persist for the process lifetime;
// they are cleared on restart. A proper connection-scoped release (free the identity
// only when the console's NEX connection actually ends) can replace this later.
func (r *relayV2) startSweeper(db *sql.DB) {
	_ = db
}
