package main

import (
	"os"
	"strconv"
	"strings"

	"github.com/PretendoNetwork/nex-go/v2"
	"github.com/PretendoNetwork/nex-go/v2/constants"
	"github.com/PretendoNetwork/nex-go/v2/types"
	common_globals "github.com/PretendoNetwork/nex-protocols-common-go/v2/globals"
	mm_database "github.com/PretendoNetwork/nex-protocols-common-go/v2/match-making/database"
	match_making "github.com/PretendoNetwork/nex-protocols-go/v2/match-making"
	nat_traversal "github.com/PretendoNetwork/nex-protocols-go/v2/nat-traversal"
)

var relay *relayManager

// relayGetSessionURLs returns the host's station URLs with address/port rewritten
// to the relay, so the caller connects to us instead of directly to the host.
func relayGetSessionURLs(mm *common_globals.MatchmakingManager) func(error, nex.PacketInterface, uint32, types.UInt32) (*nex.RMCMessage, *nex.Error) {
	return func(err error, packet nex.PacketInterface, callID uint32, gid types.UInt32) (*nex.RMCMessage, *nex.Error) {
		if err != nil {
			return nil, nex.NewError(nex.ResultCodes.Core.InvalidArgument, "change_error")
		}

		mm.Mutex.RLock()
		gathering, _, participants, _, nexErr := mm_database.FindGatheringByID(mm, uint32(gid))
		if nexErr != nil {
			mm.Mutex.RUnlock()
			return nil, nexErr
		}
		connection := packet.Sender().(*nex.PRUDPConnection)
		endpoint := connection.Endpoint().(*nex.PRUDPEndPoint)
		callerPID := uint64(connection.PID())
		hostPID := uint64(gathering.HostPID)
		peers := append([]uint64(nil), participants...)
		mm.Mutex.RUnlock()

		_ = peers
		stream := nex.NewByteStreamOut(endpoint.LibraryVersions(), endpoint.ByteStreamSettings())
		urls := types.NewList[types.StationURL]()

		// GetSessionURLs must return ONLY the host: the game treats these as "the
		// session" and a second URL breaks it. Rewrite the host to the relay.
		host := endpoint.FindConnectionByPID(hostPID)
		if host != nil {
			if canDirect(hostPID) && canDirect(callerPID) {
				// HYBRID: both ends can hole-punch directly — hand the joiner the
				// host's REAL station URLs so it connects directly (low latency).
				for _, u := range host.StationURLs {
					urls = append(urls, u.Copy().(types.StationURL))
				}
				logf("HYBRID GetSessionURLs: joiner %d -> host %d DIRECT (both EIM)", callerPID, hostPID)
			} else if v2Enabled(hostPID) {
				// Relay v2: host.StationURLs were already rewritten to the host's
				// relay identity at registration, so just return them as-is. Fall
				// back to portFor if for any reason they weren't.
				port := relay2.portFor(hostPID)
				for _, u := range host.StationURLs {
					ru := u.Copy().(types.StationURL)
					if port != 0 {
						ru.SetAddress(relay2.publicHost)
						ru.SetPortNumber(port)
					}
					urls = append(urls, ru)
				}
				logf("RELAY2 GetSessionURLs: joiner %d -> host %d at identity %s:%d", callerPID, hostPID, relay2.publicHost, port)
			} else {
				link, lerr := relay.link(hostPID, callerPID)
				for _, u := range host.StationURLs {
					ru := u.Copy().(types.StationURL)
					if lerr == nil {
						ru.SetAddress(link.host)
						ru.SetPortNumber(link.endpointFor(hostPID))
					}
					urls = append(urls, ru)
				}
				logf("RELAY  GetSessionURLs: joiner %d -> host %d via relay", callerPID, hostPID)
			}
		}

		urls.WriteTo(stream)

		resp := nex.NewRMCSuccess(endpoint, stream.Bytes())
		resp.ProtocolID = match_making.ProtocolID
		resp.MethodID = match_making.MethodGetSessionURLs
		resp.CallID = callID
		return resp, nil
	}
}

// relayRequestProbeInitiationExt rewrites the caller's own station to the relay
// endpoint ONLY for the host<->joiner link, and forwards InitiateProbe to each
// target. Joiner<->joiner pairs are passed through UNTOUCHED so they connect
// directly. Reason: we can only rewrite one side of a pair (the other side uses
// the address it learned over the Pia mesh, which we can't see), so relaying a
// joiner<->joiner pair guarantees an address MISMATCH that breaks the hole-punch.
// host<->joiner is safe because the joiner also gets the host's relay address
// from GetSessionURLs, so both ends agree on the relay.
func relayRequestProbeInitiationExt(mm *common_globals.MatchmakingManager) func(error, nex.PacketInterface, uint32, types.List[types.String], types.String) (*nex.RMCMessage, *nex.Error) {
	return func(err error, packet nex.PacketInterface, callID uint32, targetList types.List[types.String], stationToProbe types.String) (*nex.RMCMessage, *nex.Error) {
		if err != nil {
			return nil, nex.NewError(nex.ResultCodes.Core.InvalidArgument, "change_error")
		}

		connection := packet.Sender().(*nex.PRUDPConnection)
		endpoint := connection.Endpoint().(*nex.PRUDPEndPoint)
		server := endpoint.Server
		callerPID := uint64(connection.PID())
		hostPID := gatheringHostForPID(mm, callerPID)

		// Relay v2: the caller has ONE identity (relayIP, P_caller) that every
		// target — host or joiner — probes. Same address from every vantage
		// point, so the host's observed/distributed address is valid for all.
		useV2 := v2Enabled(callerPID)
		var callerIdentityPort uint16
		if useV2 {
			callerIdentityPort = relay2.portFor(callerPID)
			if callerIdentityPort == 0 {
				useV2 = false // no identity yet: degrade to v1 rather than break the join
				logf("RELAY2: no identity for caller %d, falling back to v1 for this probe", callerPID)
			}
		}

		resp := nex.NewRMCSuccess(endpoint, nil)
		resp.ProtocolID = nat_traversal.ProtocolID
		resp.MethodID = nat_traversal.MethodRequestProbeInitiationExt
		resp.CallID = callID

		for _, target := range targetList {
			targetStation := types.NewStationURL(target)
			connectionID, ok := targetStation.RVConnectionID()
			if !ok {
				continue
			}
			t := endpoint.FindConnectionByID(connectionID)
			if t == nil {
				continue
			}
			targetPID := uint64(t.PID())

			// Relay the HOST link always. Joiner<->joiner is normally left DIRECT
			// (a direct hole-punch), which works on friendly NATs but FAILS when a
			// joiner is behind cellular CGNAT / symmetric NAT. FFE_RELAY_JOINERS=1
			// (gated to FFE_RELAY_JOINER_PIDS) also routes joiner<->joiner through
			// the relay, so no console needs a direct peer connection. EXPERIMENT:
			// if both joiners honor the relay address we hand them here, this fixes
			// 3-player across any NAT; if one side instead uses the peer address it
			// learned via the Pia mesh, we'll see the mismatch and know we must also
			// rewrite the mesh handoff.
			isHostLink := hostPID != 0 && (callerPID == hostPID || targetPID == hostPID)
			relayPair := isHostLink || relayJoinerPair(callerPID, targetPID)
			perTargetStation := stationToProbe
			// HYBRID: probe directly only when BOTH ends can hole-punch (EIM);
			// otherwise the link stays on the relay.
			direct := canDirect(callerPID) && canDirect(targetPID)
			if direct {
				// Leave perTargetStation as the target's real address — direct.
				logf("HYBRID ProbeInit: caller %d -> target %d DIRECT (both EIM)", callerPID, targetPID)
			} else if useV2 {
				// v2: every target probes the caller at the caller's single identity.
				st := types.NewStationURL(stationToProbe)
				st.SetAddress(relay2.publicHost)
				st.SetPortNumber(callerIdentityPort)
				perTargetStation = types.String(st.URL())
				logf("RELAY2 ProbeInit: caller %d -> target %d at caller identity %s:%d", callerPID, targetPID, relay2.publicHost, callerIdentityPort)
			} else if relayPair {
				if link, lerr := relay.link(callerPID, targetPID); lerr == nil {
					st := types.NewStationURL(stationToProbe)
					st.SetAddress(link.host)
					st.SetPortNumber(link.endpointFor(callerPID))
					perTargetStation = types.String(st.URL())
					kind := "host-link"
					if !isHostLink {
						kind = "JOINER<->JOINER"
					}
					logf("RELAY  ProbeInit: caller %d -> %s target %d via relay", callerPID, kind, targetPID)
				}
			} else {
				logf("RELAY  ProbeInit: caller %d -> target %d DIRECT (joiner<->joiner, host=%d)", callerPID, targetPID, hostPID)
			}

			reqStream := nex.NewByteStreamOut(endpoint.LibraryVersions(), endpoint.ByteStreamSettings())
			perTargetStation.WriteTo(reqStream)

			rmcRequest := nex.NewRMCRequest(endpoint)
			rmcRequest.ProtocolID = nat_traversal.ProtocolID
			rmcRequest.CallID = 0xFFFF0000 + callID
			rmcRequest.MethodID = nat_traversal.MethodInitiateProbe
			rmcRequest.Parameters = reqStream.Bytes()
			rmcRequestBytes := rmcRequest.Bytes()

			var mp nex.PRUDPPacketInterface
			switch t.DefaultPRUDPVersion {
			case 0:
				mp, _ = nex.NewPRUDPPacketV0(server, t, nil)
			case 1:
				mp, _ = nex.NewPRUDPPacketV1(server, t, nil)
			default:
				continue
			}
			mp.SetType(constants.DataPacket)
			mp.AddFlag(constants.PacketFlagNeedsAck)
			mp.AddFlag(constants.PacketFlagReliable)
			mp.SetSourceVirtualPortStreamType(t.StreamType)
			mp.SetSourceVirtualPortStreamID(endpoint.StreamID)
			mp.SetDestinationVirtualPortStreamType(t.StreamType)
			mp.SetDestinationVirtualPortStreamID(t.StreamID)
			mp.SetPayload(rmcRequestBytes)
			server.Send(mp)
		}

		return resp, nil
	}
}

// relayJoinerPair reports whether a joiner<->joiner probe pair should be routed
// through the relay (experimental). Requires FFE_RELAY_JOINERS=1, and if
// FFE_RELAY_JOINER_PIDS is set (comma list), BOTH consoles must be allowlisted
// so real players keep the stock direct behaviour untouched.
func relayJoinerPair(a, b uint64) bool {
	if os.Getenv("FFE_RELAY_JOINERS") != "1" {
		return false
	}
	allow := os.Getenv("FFE_RELAY_JOINER_PIDS")
	if allow == "" {
		return true
	}
	return pidInCSV(a, allow) && pidInCSV(b, allow)
}

func pidInCSV(pid uint64, csv string) bool {
	want := strconv.FormatUint(pid, 10)
	for _, p := range strings.Split(csv, ",") {
		if strings.TrimSpace(p) == want {
			return true
		}
	}
	return false
}

// gatheringHostForPID returns the host PID of the (most recent) gathering that
// pid participates in, or 0 if none / unknown. Used to decide which probe pairs
// are host-links (relay) versus joiner<->joiner (leave direct).
func gatheringHostForPID(mm *common_globals.MatchmakingManager, pid uint64) uint64 {
	if mm == nil || mm.Database == nil {
		return 0
	}
	var hostText string
	err := mm.Database.QueryRow(
		`SELECT host_pid::text FROM matchmaking.gatherings
		 WHERE $1::numeric = ANY(participants) ORDER BY id DESC LIMIT 1`,
		strconv.FormatUint(pid, 10),
	).Scan(&hostText)
	if err != nil {
		return 0
	}
	h, _ := strconv.ParseUint(hostText, 10, 64)
	return h
}
