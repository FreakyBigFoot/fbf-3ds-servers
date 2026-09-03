// Stub NEX server for Final Fantasy Explorers (3DS).
//
// Credentials recovered by static analysis of the retail US executable
// (see dumps/analysis/findings.md):
//
//	game server ID  0x0010E200   (the JP title's low ID - all regions share one server)
//	access key      c85cdf58
//
// This build answers the authentication handshake and logs every RMC call the
// game makes, so we learn which protocols and methods it actually uses.
package main

import (
	"os"
	"strconv"
	"sync"

	"github.com/PretendoNetwork/nex-go/v2"
	"github.com/PretendoNetwork/nex-go/v2/types"
	"github.com/PretendoNetwork/nex-go/v2/constants"
	common_secure "github.com/PretendoNetwork/nex-protocols-common-go/v2/secure-connection"
	common_ticket_granting "github.com/PretendoNetwork/nex-protocols-common-go/v2/ticket-granting"
	secure "github.com/PretendoNetwork/nex-protocols-go/v2/secure-connection"
	ticket_granting "github.com/PretendoNetwork/nex-protocols-go/v2/ticket-granting"

	"database/sql"

	common_globals "github.com/PretendoNetwork/nex-protocols-common-go/v2/globals"
	common_match_making "github.com/PretendoNetwork/nex-protocols-common-go/v2/match-making"
	common_match_making_ext "github.com/PretendoNetwork/nex-protocols-common-go/v2/match-making-ext"
	common_matchmake_extension "github.com/PretendoNetwork/nex-protocols-common-go/v2/matchmake-extension"
	common_nat_traversal "github.com/PretendoNetwork/nex-protocols-common-go/v2/nat-traversal"
	match_making "github.com/PretendoNetwork/nex-protocols-go/v2/match-making"
	match_making_ext "github.com/PretendoNetwork/nex-protocols-go/v2/match-making-ext"
	matchmake_extension "github.com/PretendoNetwork/nex-protocols-go/v2/matchmake-extension"
	nat_traversal "github.com/PretendoNetwork/nex-protocols-go/v2/nat-traversal"
	_ "github.com/lib/pq"
)

const (
	AccessKey    = "c85cdf58"
	GameServerID = 0x0010E200
)

// Server accounts the NEX library authenticates against. The usernames are
// fixed by the protocol, not chosen by us.
var (
	authServerAccount   *nex.Account
	secureServerAccount *nex.Account
)


// A console's NEX password (dumped, or self-registered via /register) is kept in
// the global `accounts` store (see register.go). The ticket LoginEx builds is
// encrypted with a key derived from this password; the console decrypts with the
// same, so it must match exactly.

// fixedPassword, when set via FFE_FIXED_PASSWORD, makes every real console use
// this one NEX password instead of its per-account dumped secret. It pairs with
// the FFE game patch that forces the console's kerberos derivation to use the
// same fixed string, so nobody has to dump or post their real password.
// REVERT: unset FFE_FIXED_PASSWORD and the per-PID FFE_NEX_ACCOUNTS map is used
// again (the current working behaviour with dumped passwords).
var fixedPassword = os.Getenv("FFE_FIXED_PASSWORD")

func passwordForPID(pid string) string {
	if fixedPassword != "" {
		return fixedPassword
	}
	if pw, ok := accounts.get(pid); ok {
		return pw
	}
	return "guest-password"
}

func accountDetailsByPID(pid types.PID) (*nex.Account, *nex.Error) {
	switch uint64(pid) {
	case 1:
		return authServerAccount, nil
	case 2:
		return secureServerAccount, nil
	}
	// Real console: use its dumped NEX password so the kerberos ticket decrypts.
	// NOTE: pid.String() is a DEBUG format ("PID{ pid: N }"), not the decimal
	// string - use the numeric form for both the username and the password key.
	pidStr := strconv.FormatUint(uint64(pid), 10)
	return nex.NewAccount(pid, pidStr, passwordForPID(pidStr), false), nil
}

func accountDetailsByUsername(username string) (*nex.Account, *nex.Error) {
	switch username {
	case "Quazal Authentication":
		return authServerAccount, nil
	case "Quazal Rendez-Vous":
		return secureServerAccount, nil
	}
	// On 3DS the NEX username IS the PID as a decimal string. Use the real PID
	// (not a placeholder) so the kerberos key the console derives matches ours.
	pidInt, err := strconv.ParseUint(username, 10, 64)
	if err != nil {
		return nil, nex.NewError(nex.ResultCodes.RendezVous.InvalidUsername, "invalid username")
	}
	pid := types.NewPID(pidInt)
	return nex.NewAccount(pid, username, passwordForPID(username), false), nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envPort(key string, fallback int) int {
	if n, err := strconv.Atoi(env(key, "")); err == nil {
		return n
	}
	return fallback
}

var postgres *sql.DB

func openPostgres() {
	uri := env("FFE_POSTGRES_URI", "")
	if uri == "" {
		logf("POSTGRES no FFE_POSTGRES_URI set - matchmaking disabled")
		return
	}
	db, err := sql.Open("postgres", uri)
	if err != nil {
		logf("POSTGRES open failed: %v", err)
		return
	}
	if err := db.Ping(); err != nil {
		logf("POSTGRES ping failed: %v", err)
		return
	}
	postgres = db
	logf("POSTGRES connected - matchmaking enabled")
}

func main() {
	openPostgres()
	startMetricsSampler() // lightweight /proc sampler for the dashboard
	seedAccountsFromEnv() // dumped accounts first...
	ensureAccountsTable()
	loadAccountsFromDB() // ...then registrations from the DB override them
	authServerAccount = nex.NewAccount(types.NewPID(1), "Quazal Authentication", "auth-password", false)
	secureServerAccount = nex.NewAccount(types.NewPID(2), "Quazal Rendez-Vous", "secure-password", false)

	logf("stub NEX server starting")

	var wg sync.WaitGroup
	wg.Add(1)
	go startNASCServer(&wg)
	wg.Add(1)
	go startHTTPRegister(&wg) // plain-http /register for the 3DS patcher app

	for i := range games {
		g := &games[i]
		if !enabled(g) {
			logf("SKIP   %s (set FFE_CONTROL_MK7=1 to enable)", g.Name)
			continue
		}
		wg.Add(2)
		go startAuthenticationServer(&wg, g)
		go startSecureServer(&wg, g)
	}

	wg.Wait()
}

func startAuthenticationServer(wg *sync.WaitGroup, g *gameServer) {
	defer wg.Done()

	server := nex.NewPRUDPServer()
	endpoint := nex.NewPRUDPEndPoint(1)
	endpoint.ServerAccount = authServerAccount
	endpoint.AccountDetailsByPID = accountDetailsByPID
	endpoint.AccountDetailsByUsername = accountDetailsByUsername

	server.BindPRUDPEndPoint(endpoint)
	server.LibraryVersions.SetDefault(nex.NewLibraryVersion(g.LibMajor, g.LibMinor, g.LibPatch))
	server.ByteStreamSettings.UseStructureHeader = g.UseStructureHeader
	server.PRUDPV1Settings.LegacyConnectionSignature = g.LegacyConnectionSignature
	server.AccessKey = g.AccessKey
	if env("FFE_TICKET_V1", "") == "1" {
		server.KerberosTicketVersion = 1
	}

	endpoint.OnData(func(packet nex.PacketInterface) { logRMC("AUTH:"+g.Name, packet) })
	endpoint.OnError(func(err *nex.Error) { logf("AUTH   [%s] error: %v", g.Name, err) })

	// Ticket granting is what hands the console the address of the secure
	// server, so it has to work before anything else can be observed.
	tg := ticket_granting.NewProtocol()
	endpoint.RegisterServiceProtocol(tg)

	common := common_ticket_granting.NewCommonProtocol(tg)
	common.SecureServerAccount = secureServerAccount

	// Local mode: accept any login. The console is already vouched for by our
	// NASC. (Ticket decryption still depends on the NEX password - see notes.)
	common.ValidateLoginData = func(pid types.PID, loginData types.DataHolder) *nex.Error {
		return nil
	}

	// The insecure Login method is normally blocked. We allow it only for local
	// testing with a scripted client; the console uses LoginEx regardless.
	if os.Getenv("FFE_INSECURE_LOGIN") == "1" {
		common.EnableInsecureLogin()
	}

	securePort := g.SecurePort
	secureURL := types.NewStationURL("")
	secureURL.SetURLType(constants.StationURLPRUDPS)
	secureURL.SetAddress(env("FFE_SECURE_HOST", "127.0.0.1"))
	secureURL.SetPortNumber(uint16(securePort))
	secureURL.SetConnectionID(1)
	secureURL.SetPrincipalID(types.NewPID(2))
	secureURL.SetStreamID(1)
	secureURL.SetStreamType(constants.StreamTypeRVSecure)
	secureURL.SetType(uint8(constants.StationURLFlagPublic))
	common.SecureStationURL = secureURL

	port := g.AuthPort
	logf("AUTH   %s listening on udp/%d  -> secure at %s:%d  (key %s)",
		g.Name, port, env("FFE_SECURE_HOST", "127.0.0.1"), securePort, g.AccessKey)
	server.Listen(port)
}

func startSecureServer(wg *sync.WaitGroup, g *gameServer) {
	defer wg.Done()

	server := nex.NewPRUDPServer()
	endpoint := nex.NewPRUDPEndPoint(1)
	endpoint.IsSecureEndPoint = true
	registerSecureEndpoint(g.DisplayName(), g.GameID, endpoint) // per-game dashboard stats
	installSessionLogging(g.Name, endpoint) // connect/disconnect logging (drop vs clean-leave)
	endpoint.ServerAccount = secureServerAccount
	endpoint.AccountDetailsByPID = accountDetailsByPID
	endpoint.AccountDetailsByUsername = accountDetailsByUsername

	server.BindPRUDPEndPoint(endpoint)
	server.LibraryVersions.SetDefault(nex.NewLibraryVersion(g.LibMajor, g.LibMinor, g.LibPatch))
	server.ByteStreamSettings.UseStructureHeader = g.UseStructureHeader
	server.PRUDPV1Settings.LegacyConnectionSignature = g.LegacyConnectionSignature
	server.AccessKey = g.AccessKey
	if env("FFE_TICKET_V1", "") == "1" {
		server.KerberosTicketVersion = 1
	}
	// FFE's MatchMaking structures are pre-3.4.0 (no ProgressScore field in
	// MatchmakeSession). Override just the MatchMaking library version so the
	// struct parser reads the right fields.
	if v := env("FFE_MM_MINOR", ""); v != "" {
		if mn, e := strconv.Atoi(v); e == nil {
			server.LibraryVersions.MatchMaking = nex.NewLibraryVersion(3, mn, 0)
		}
	}

	endpoint.OnData(func(packet nex.PacketInterface) { logRMC("SEC:"+g.Name, packet) })
	endpoint.OnError(func(err *nex.Error) { logf("SECURE [%s] error: %v", g.Name, err) })

	// Register the secure-connection protocol so the console can complete its
	// secure login (Register/RegisterEx) after presenting the kerberos ticket.
	sec := secure.NewProtocol()
	endpoint.RegisterServiceProtocol(sec)
	commonSec := common_secure.NewCommonProtocol(sec)
	commonSec.EnableInsecureRegister()
	commonSec.CreateReportDBRecord = func(pid types.PID, reportID types.UInt32, reportData types.QBuffer) error {
		return nil
	}

	// Matchmaking (create/join rooms) - needs Postgres. The common protocols
	// auto-create their schema on registration.
	if postgres != nil {
		mm := common_globals.NewMatchmakingManager(endpoint, postgres)
		// Friends-only sessions (participation_policy 98, used by Fantasy Life) are
		// only browsable when the owner is in the searcher's friend list. The real
		// friend graph is on Pretendo's friends server, which we don't run - so treat
		// every registered account on this community server as everyone's friend.
		mm.GetUserFriendPIDs = func(pid uint32) []uint32 { return accounts.allPIDs() }

		nt := nat_traversal.NewProtocol()
		endpoint.RegisterServiceProtocol(nt)
		common_nat_traversal.NewCommonProtocol(nt)

		mmp := match_making.NewProtocol()
		endpoint.RegisterServiceProtocol(mmp)
		common_match_making.NewCommonProtocol(mmp).SetManager(mm)

		mmext := match_making_ext.NewProtocol()
		endpoint.RegisterServiceProtocol(mmext)
		common_match_making_ext.NewCommonProtocol(mmext).SetManager(mm)

		mme := matchmake_extension.NewProtocol()
		endpoint.RegisterServiceProtocol(mme)
		common_matchmake_extension.NewCommonProtocol(mme).SetManager(mm)

		// Optional transparent P2P relay (opt-in via FFE_RELAY=1). Overrides the
		// two handlers that hand out peer addresses so both consoles route
		// through us. With FFE_RELAY unset, behaviour is unchanged (direct P2P).
		if os.Getenv("FFE_RELAY") == "1" {
			if relay == nil {
				relay = newRelayManager(env("FFE_PUBLIC_HOST", "10.0.0.95"))
			}
			mmp.SetHandlerGetSessionURLs(relayGetSessionURLs(mm))
			nt.SetHandlerRequestProbeInitiationExt(relayRequestProbeInitiationExt)
			logf("SECURE %s TRANSPARENT RELAY enabled (public host %s)", g.Name, relay.publicHost)
		}

		logf("SECURE %s matchmaking protocols registered", g.Name)
	}

	port := g.SecurePort
	logf("SECURE %s listening on udp/%d", g.Name, port)
	server.Listen(port)
}
