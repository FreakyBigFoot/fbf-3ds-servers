package main

import "strconv"

// A gameServer is one NEX endpoint pair we answer for. Everything not listed
// here is relayed to Pretendo untouched.
type gameServer struct {
	Name       string
	GameID     string
	AccessKey  string
	AuthPort   int
	SecurePort int

	LibMajor, LibMinor, LibPatch int
	UseStructureHeader           bool
	LegacyConnectionSignature    bool

	Control bool
}

const FFEGameID = "0010E200"

// Candidate NEX configurations for FF Explorers. The console caches its NASC
// token for an hour, so it keeps dialling whichever port it was last given -
// which means we cannot rotate variants per login. Instead exactly one variant
// binds the well-known port, chosen by FFE_VARIANT at startup, and we restart
// the container to test the next one. The console needs no cooperation.
var ffeVariants = []gameServer{
	{Name: "2.0.0", LibMajor: 2, LibMinor: 0, LibPatch: 0},
	{Name: "2.0.0 hdr", LibMajor: 2, LibMinor: 0, LibPatch: 0, UseStructureHeader: true},
	{Name: "2.1.0 hdr", LibMajor: 2, LibMinor: 1, LibPatch: 0, UseStructureHeader: true},
	{Name: "2.3.0 hdr", LibMajor: 2, LibMinor: 3, LibPatch: 0, UseStructureHeader: true},
	{Name: "3.0.0 hdr", LibMajor: 3, LibMinor: 0, LibPatch: 0, UseStructureHeader: true},
	{Name: "3.6.1 hdr", LibMajor: 3, LibMinor: 6, LibPatch: 1, UseStructureHeader: true},
	{Name: "3.6.9 hdr", LibMajor: 3, LibMinor: 6, LibPatch: 9, UseStructureHeader: true},
	{Name: "3.9.0 hdr", LibMajor: 3, LibMinor: 9, LibPatch: 0, UseStructureHeader: true},
	{Name: "4.0.0 hdr", LibMajor: 4, LibMinor: 0, LibPatch: 0, UseStructureHeader: true},
	{Name: "3.6.1 hdr legacy-sig", LibMajor: 3, LibMinor: 6, LibPatch: 1, UseStructureHeader: true, LegacyConnectionSignature: true},
	{Name: "2.0.0 legacy-sig", LibMajor: 2, LibMinor: 0, LibPatch: 0, LegacyConnectionSignature: true},
}

var games []gameServer

func init() {
	idx := 0
	if v, err := strconv.Atoi(env("FFE_VARIANT", "0")); err == nil && v >= 0 && v < len(ffeVariants) {
		idx = v
	}

	ffe := ffeVariants[idx]
	ffe.Name = "FF Explorers [variant " + strconv.Itoa(idx) + ": " + ffe.Name + "]"
	ffe.GameID = FFEGameID
	ffe.AccessKey = env("FFE_ACCESS_KEY", "c624986e")
	ffe.AuthPort = 61001 // the port cached tokens already point at
	ffe.SecurePort = 61002

	// Overrides for RMC-layer structure parsing (AuthenticationInfo etc.),
	// which depends on the exact NEX version and structure-header setting.
	if v := env("FFE_STRUCT_HEADER", ""); v != "" {
		ffe.UseStructureHeader = v == "1"
	}
	if mj := env("FFE_LIB_MAJOR", ""); mj != "" {
		if n, e := strconv.Atoi(mj); e == nil {
			ffe.LibMajor = n
		}
	}
	if mn := env("FFE_LIB_MINOR", ""); mn != "" {
		if n, e := strconv.Atoi(mn); e == nil {
			ffe.LibMinor = n
		}
	}
	if pt := env("FFE_LIB_PATCH", ""); pt != "" {
		if n, e := strconv.Atoi(pt); e == nil {
			ffe.LibPatch = n
		}
	}

	games = []gameServer{
		ffe,
		// Known-good control: this configuration completed a real handshake.
		{Name: "Mario Kart 7 (control)", GameID: "00030600", AccessKey: "6181dff1",
			AuthPort: 61011, SecurePort: 61012, LibMajor: 2, LibMinor: 0, LibPatch: 0, Control: true},
	}
}

func enabled(g *gameServer) bool { return !g.Control || env("FFE_CONTROL_MK7", "") == "1" }

func gameByID(gameID string) *gameServer {
	for i := range games {
		if games[i].GameID == gameID && enabled(&games[i]) {
			return &games[i]
		}
	}
	return nil
}
