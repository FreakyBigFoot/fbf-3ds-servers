package main

import (
	"strconv"

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

			// Only relay the HOST link. Leave joiner<->joiner untouched (direct).
			isHostLink := hostPID != 0 && (callerPID == hostPID || targetPID == hostPID)
			perTargetStation := stationToProbe
			if isHostLink {
				if link, lerr := relay.link(callerPID, targetPID); lerr == nil {
					st := types.NewStationURL(stationToProbe)
					st.SetAddress(link.host)
					st.SetPortNumber(link.endpointFor(callerPID))
					perTargetStation = types.String(st.URL())
					logf("RELAY  ProbeInit: caller %d -> host-link target %d via relay", callerPID, targetPID)
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
