package main

// Self-hosted 3DS Friends server (opt-in via FFE_FRIENDS=1). SCAFFOLD — not yet
// verified on hardware. See friends-server-design.md for the full plan.
//
// Purpose: make FFE online co-op "use Friends list" work by serving the 3DS
// Friends NEX protocol ourselves instead of proxying to Pretendo, and
// SYNTHESIZING presence from the matchmaking DB (a hosting friend => joinable).
//
// This file stands up a friends auth + secure endpoint (access key "ridfebb9")
// and registers the Friends3DS protocol. Handlers log every call so the first
// on-console test reveals FFE's exact call sequence (design Phase 0), while
// GetAllFriends/GetFriendPresence make a best-effort real attempt (Phase 1).
//
// NOTHING here runs unless FFE_FRIENDS=1. The live server is unaffected.

import (
	"database/sql"
	"strconv"
	"sync"

	"github.com/PretendoNetwork/nex-go/v2"
	"github.com/PretendoNetwork/nex-go/v2/constants"
	"github.com/PretendoNetwork/nex-go/v2/types"
	common_secure "github.com/PretendoNetwork/nex-protocols-common-go/v2/secure-connection"
	common_ticket_granting "github.com/PretendoNetwork/nex-protocols-common-go/v2/ticket-granting"
	friends_3ds "github.com/PretendoNetwork/nex-protocols-go/v2/friends-3ds"
	friends_3ds_constants "github.com/PretendoNetwork/nex-protocols-go/v2/friends-3ds/constants"
	friends_3ds_types "github.com/PretendoNetwork/nex-protocols-go/v2/friends-3ds/types"
	secure "github.com/PretendoNetwork/nex-protocols-go/v2/secure-connection"
	ticket_granting "github.com/PretendoNetwork/nex-protocols-go/v2/ticket-granting"
)

// FriendsAccessKey is the standard 3DS Friends NEX access key (same value
// Pretendo's friends server uses). The console derives its kerberos key from
// this + its NEX password, which we already hold in our accounts DB.
const FriendsAccessKey = "ridfebb9"

// FFE title id, used as the GameKey in synthesized presence so FFE recognizes
// "this friend is in FFE and joinable".
const FFETitleID uint64 = 0x000400000016ED00

// startFriendsServers launches the friends auth + secure endpoints if enabled.
func startFriendsServers(wg *sync.WaitGroup) {
	authPort := envPort("FFE_FRIENDS_AUTH_PORT", 61010)
	securePort := envPort("FFE_FRIENDS_SECURE_PORT", 61011)
	// 3DS friends NEX library version. Pretendo's own friends server uses NEX
	// 1.1.0 for both auth + secure (the 3DS Friends service is NEX 1). Using the
	// wrong version made handleConnect misparse the connect packet and panic, so
	// this default matters. Still tunable via env.
	lib := nex.NewLibraryVersion(
		envPort("FFE_FRIENDS_LIB_MAJOR", 1),
		envPort("FFE_FRIENDS_LIB_MINOR", 1),
		envPort("FFE_FRIENDS_LIB_PATCH", 0),
	)

	wg.Add(2)
	go startFriendsAuthServer(wg, authPort, securePort, lib)
	go startFriendsSecureServer(wg, securePort, lib)
}

func startFriendsAuthServer(wg *sync.WaitGroup, authPort, securePort int, lib *nex.LibraryVersion) {
	defer wg.Done()

	server := nex.NewPRUDPServer()
	endpoint := nex.NewPRUDPEndPoint(1)
	endpoint.ServerAccount = authServerAccount
	endpoint.AccountDetailsByPID = accountDetailsByPID
	endpoint.AccountDetailsByUsername = accountDetailsByUsername

	server.BindPRUDPEndPoint(endpoint)
	server.LibraryVersions.SetDefault(lib)
	server.AccessKey = FriendsAccessKey

	endpoint.OnData(func(packet nex.PacketInterface) { logRMC("FRIENDS-AUTH", packet) })
	endpoint.OnError(func(err *nex.Error) { logf("FRIENDS-AUTH error: %v", err) })

	tg := ticket_granting.NewProtocol()
	endpoint.RegisterServiceProtocol(tg)
	common := common_ticket_granting.NewCommonProtocol(tg)
	common.SecureServerAccount = secureServerAccount
	common.ValidateLoginData = func(pid types.PID, loginData types.DataHolder) *nex.Error { return nil }
	// The 3DS Friends sysmodule uses the plain Login (method 1), which the lib
	// blocks by default. Friends servers must allow it (matches PretendoNetwork/
	// friends nex/register_common_authentication_server_protocols.go).
	common.EnableInsecureLogin()

	secureURL := types.NewStationURL("")
	secureURL.SetURLType(constants.StationURLPRUDPS)
	secureURL.SetAddress(secureHostIP())
	secureURL.SetPortNumber(uint16(securePort))
	secureURL.SetConnectionID(1)
	secureURL.SetPrincipalID(types.NewPID(2))
	secureURL.SetStreamID(1)
	secureURL.SetStreamType(constants.StreamTypeRVSecure)
	secureURL.SetType(uint8(constants.StationURLFlagPublic))
	common.SecureStationURL = secureURL

	logf("FRIENDS-AUTH listening on udp/%d -> secure at %s:%d (key %s)",
		authPort, secureHostIP(), securePort, FriendsAccessKey)
	server.Listen(authPort)
}

func startFriendsSecureServer(wg *sync.WaitGroup, securePort int, lib *nex.LibraryVersion) {
	defer wg.Done()

	server := nex.NewPRUDPServer()
	endpoint := nex.NewPRUDPEndPoint(1)
	endpoint.IsSecureEndPoint = true
	endpoint.ServerAccount = secureServerAccount
	endpoint.AccountDetailsByPID = accountDetailsByPID
	endpoint.AccountDetailsByUsername = accountDetailsByUsername

	server.BindPRUDPEndPoint(endpoint)
	server.LibraryVersions.SetDefault(lib)
	server.AccessKey = FriendsAccessKey

	endpoint.OnData(func(packet nex.PacketInterface) { logRMC("FRIENDS-SEC", packet) })
	endpoint.OnError(func(err *nex.Error) { logf("FRIENDS-SEC error: %v", err) })

	sec := secure.NewProtocol()
	endpoint.RegisterServiceProtocol(sec)
	commonSec := common_secure.NewCommonProtocol(sec)
	commonSec.EnableInsecureRegister()
	commonSec.CreateReportDBRecord = func(pid types.PID, reportID types.UInt32, reportData types.QBuffer) error { return nil }

	fp := friends_3ds.NewProtocol()
	endpoint.RegisterServiceProtocol(fp)
	registerFriends3DSHandlers(endpoint, fp)

	logf("FRIENDS-SEC listening on udp/%d (key %s), Friends3DS registered", securePort, FriendsAccessKey)
	server.Listen(securePort)
}

// okResponse builds an RMC success carrying the given already-serialized body.
func friendsOK(endpoint *nex.PRUDPEndPoint, callID uint32, methodID uint32, body []byte) *nex.RMCMessage {
	resp := nex.NewRMCSuccess(endpoint, body)
	resp.ProtocolID = friends_3ds.ProtocolID
	resp.MethodID = methodID
	resp.CallID = callID
	return resp
}

func friendsEmpty(endpoint *nex.PRUDPEndPoint, callID, methodID uint32) *nex.RMCMessage {
	return friendsOK(endpoint, callID, methodID, []byte{})
}

// gatheringForHost returns (gatheringID, gameMode, true) if the given PID is
// hosting a registered FFE MatchmakeSession right now. This is the presence
// source: a hosting friend becomes "joinable".
func gatheringForHost(pid uint64) (uint32, uint32, bool) {
	if postgres == nil {
		return 0, 0, false
	}
	var gid uint32
	var gameMode uint32
	err := postgres.QueryRow(
		`SELECT g.id, ms.game_mode
		   FROM matchmaking.gatherings g
		   JOIN matchmaking.matchmake_sessions ms ON ms.id = g.id
		  WHERE g.registered = true AND g.type = 'MatchmakeSession'
		    AND $1::numeric = g.host_pid
		  ORDER BY g.id DESC LIMIT 1`,
		strconv.FormatUint(pid, 10),
	).Scan(&gid, &gameMode)
	if err != nil {
		if err != sql.ErrNoRows {
			logf("FRIENDS presence query error for pid=%d: %v", pid, err)
		}
		return 0, 0, false
	}
	return gid, gameMode, true
}

// synthPresence builds a joinable NintendoPresence for a host PID + gathering.
func synthPresence(hostPID uint64, gid, gameMode uint32) friends_3ds_types.NintendoPresence {
	np := friends_3ds_types.NewNintendoPresence()
	np.ChangedFlags = friends_3ds_constants.PresenceChangedFlagGameKey
	np.GameKey = friends_3ds_types.NewGameKey()
	np.GameKey.TitleID = types.NewUInt64(FFETitleID)
	np.GameKey.TitleVersion = types.NewUInt16(0)
	np.Message = types.NewString("")
	np.JoinAvailableFlag = types.NewUInt32(1)
	np.MatchmakeType = types.NewUInt8(1)
	np.JoinGameID = types.NewUInt32(gid)
	np.JoinGameMode = types.NewUInt32(gameMode)
	np.OwnerPID = types.NewPID(hostPID)
	np.JoinGroupID = types.NewUInt32(gid)
	np.ApplicationArg = types.NewBuffer([]byte{})
	return np
}

// registerFriends3DSHandlers wires all Friends3DS methods. The two that matter
// for co-op (GetAllFriends, GetFriendPresence) make a real attempt; the rest
// return valid empty responses so the Friends app / FFE don't error. Every call
// is logged via the endpoint OnData logRMC already, plus a per-method note here.
func registerFriends3DSHandlers(endpoint *nex.PRUDPEndPoint, fp *friends_3ds.Protocol) {
	// --- Friend list: seed every other registered account as a complete friend.
	fp.SetHandlerGetAllFriends(func(err error, packet nex.PacketInterface, callID uint32) (*nex.RMCMessage, *nex.Error) {
		if err != nil {
			return nil, nex.NewError(nex.ResultCodes.Core.InvalidArgument, "friends")
		}
		caller := uint64(packet.Sender().(*nex.PRUDPConnection).PID())
		list := types.NewList[friends_3ds_types.FriendRelationship]()
		for _, p := range accounts.allPIDs() {
			if uint64(p) == caller {
				continue
			}
			fr := friends_3ds_types.NewFriendRelationship()
			fr.PID = types.NewPID(uint64(p))
			fr.LFC = types.NewUInt64(0)
			fr.RelationshipType = friends_3ds_constants.RelationshipTypeComplete
			list = append(list, fr)
		}
		stream := nex.NewByteStreamOut(endpoint.LibraryVersions(), endpoint.ByteStreamSettings())
		list.WriteTo(stream)
		logf("FRIENDS GetAllFriends caller=%d -> %d friends", caller, len(list))
		return friendsOK(endpoint, callID, friends_3ds.MethodGetAllFriends, stream.Bytes()), nil
	})

	// --- Presence: synthesize from the matchmaking DB for each requested PID.
	fp.SetHandlerGetFriendPresence(func(err error, packet nex.PacketInterface, callID uint32, pidList types.List[types.PID]) (*nex.RMCMessage, *nex.Error) {
		if err != nil {
			return nil, nex.NewError(nex.ResultCodes.Core.InvalidArgument, "friends")
		}
		presences := types.NewList[friends_3ds_types.FriendPresence]()
		for _, pid := range pidList {
			if gid, gm, ok := gatheringForHost(uint64(pid)); ok {
				fpz := friends_3ds_types.NewFriendPresence()
				fpz.PID = pid.Copy().(types.PID)
				fpz.Presence = synthPresence(uint64(pid), gid, gm)
				presences = append(presences, fpz)
			}
		}
		stream := nex.NewByteStreamOut(endpoint.LibraryVersions(), endpoint.ByteStreamSettings())
		presences.WriteTo(stream)
		logf("FRIENDS GetFriendPresence req=%d -> %d present", len(pidList), len(presences))
		return friendsOK(endpoint, callID, friends_3ds.MethodGetFriendPresence, stream.Bytes()), nil
	})

	// --- Relationships: same seed as GetAllFriends but for a queried PID list.
	fp.SetHandlerGetFriendRelationships(func(err error, packet nex.PacketInterface, callID uint32, pids types.List[types.PID]) (*nex.RMCMessage, *nex.Error) {
		if err != nil {
			return nil, nex.NewError(nex.ResultCodes.Core.InvalidArgument, "friends")
		}
		list := types.NewList[friends_3ds_types.FriendRelationship]()
		for _, p := range pids {
			fr := friends_3ds_types.NewFriendRelationship()
			fr.PID = p.Copy().(types.PID)
			fr.LFC = types.NewUInt64(0)
			fr.RelationshipType = friends_3ds_constants.RelationshipTypeComplete
			list = append(list, fr)
		}
		stream := nex.NewByteStreamOut(endpoint.LibraryVersions(), endpoint.ByteStreamSettings())
		list.WriteTo(stream)
		return friendsOK(endpoint, callID, friends_3ds.MethodGetFriendRelationships, stream.Bytes()), nil
	})

	// --- Presence update from the console: accept, no-op (synth is our source).
	fp.SetHandlerUpdatePresence(func(err error, packet nex.PacketInterface, callID uint32, presence friends_3ds_types.NintendoPresence, showGame types.Bool) (*nex.RMCMessage, *nex.Error) {
		caller := uint64(packet.Sender().(*nex.PRUDPConnection).PID())
		logf("FRIENDS UpdatePresence caller=%d joinGID=%d title=0x%X", caller,
			uint32(presence.JoinGroupID), uint64(presence.GameKey.TitleID))
		return friendsEmpty(endpoint, callID, friends_3ds.MethodUpdatePresence), nil
	})

	// --- Everything else: valid empty responses so nothing errors. These are
	// the methods the Friends app calls on startup; returning empty keeps it
	// happy until we flesh out Miis/profiles. Logged via logRMC.
	fp.SetHandlerUpdateProfile(func(err error, p nex.PacketInterface, c uint32, _ friends_3ds_types.MyProfile) (*nex.RMCMessage, *nex.Error) {
		return friendsEmpty(endpoint, c, friends_3ds.MethodUpdateProfile), nil
	})
	fp.SetHandlerUpdateMii(func(err error, p nex.PacketInterface, c uint32, _ friends_3ds_types.Mii) (*nex.RMCMessage, *nex.Error) {
		return friendsEmpty(endpoint, c, friends_3ds.MethodUpdateMii), nil
	})
	fp.SetHandlerUpdateMiiList(func(err error, p nex.PacketInterface, c uint32, _ friends_3ds_types.MiiList) (*nex.RMCMessage, *nex.Error) {
		return friendsEmpty(endpoint, c, friends_3ds.MethodUpdateMiiList), nil
	})
	fp.SetHandlerUpdatePlayedGames(func(err error, p nex.PacketInterface, c uint32, _ types.List[friends_3ds_types.PlayedGame]) (*nex.RMCMessage, *nex.Error) {
		return friendsEmpty(endpoint, c, friends_3ds.MethodUpdatePlayedGames), nil
	})
	fp.SetHandlerUpdatePreference(func(err error, p nex.PacketInterface, c uint32, _ types.Bool, _ types.Bool, _ types.Bool) (*nex.RMCMessage, *nex.Error) {
		return friendsEmpty(endpoint, c, friends_3ds.MethodUpdatePreference), nil
	})
	fp.SetHandlerGetFriendMii(func(err error, p nex.PacketInterface, c uint32, _ types.List[friends_3ds_types.FriendInfo]) (*nex.RMCMessage, *nex.Error) {
		return friendsEmpty(endpoint, c, friends_3ds.MethodGetFriendMii), nil
	})
	fp.SetHandlerGetFriendMiiList(func(err error, p nex.PacketInterface, c uint32, _ types.List[friends_3ds_types.FriendInfo]) (*nex.RMCMessage, *nex.Error) {
		return friendsEmpty(endpoint, c, friends_3ds.MethodGetFriendMiiList), nil
	})
	fp.SetHandlerUpdateComment(func(err error, p nex.PacketInterface, c uint32, _ types.String) (*nex.RMCMessage, *nex.Error) {
		return friendsEmpty(endpoint, c, friends_3ds.MethodUpdateComment), nil
	})
	fp.SetHandlerSyncFriend(func(err error, p nex.PacketInterface, c uint32, _ types.UInt64, _ types.List[types.PID], _ types.List[types.UInt64]) (*nex.RMCMessage, *nex.Error) {
		return friendsEmpty(endpoint, c, friends_3ds.MethodSyncFriend), nil
	})
	fp.SetHandlerUpdateFavoriteGameKey(func(err error, p nex.PacketInterface, c uint32, _ friends_3ds_types.GameKey) (*nex.RMCMessage, *nex.Error) {
		return friendsEmpty(endpoint, c, friends_3ds.MethodUpdateFavoriteGameKey), nil
	})
}
