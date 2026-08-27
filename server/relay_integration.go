package main

import (
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
		gathering, _, _, _, nexErr := mm_database.FindGatheringByID(mm, uint32(gid))
		if nexErr != nil {
			mm.Mutex.RUnlock()
			return nil, nexErr
		}
		connection := packet.Sender().(*nex.PRUDPConnection)
		endpoint := connection.Endpoint().(*nex.PRUDPEndPoint)
		callerPID := uint64(connection.PID())
		hostPID := uint64(gathering.HostPID)
		host := endpoint.FindConnectionByPID(hostPID)
		mm.Mutex.RUnlock()

		stream := nex.NewByteStreamOut(endpoint.LibraryVersions(), endpoint.ByteStreamSettings())
		urls := types.NewList[types.StationURL]()

		if host != nil {
			link, lerr := relay.link(hostPID, callerPID)
			for _, u := range host.StationURLs {
				ru := u.Copy().(types.StationURL)
				if lerr == nil {
					ru.SetAddress(relay.publicHost)
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

// relayRequestProbeInitiationExt rewrites the caller's own station (the address
// peers are told to probe) to the relay endpoint, then forwards InitiateProbe to
// each target - so peers probe the relay instead of the caller directly.
func relayRequestProbeInitiationExt(err error, packet nex.PacketInterface, callID uint32, targetList types.List[types.String], stationToProbe types.String) (*nex.RMCMessage, *nex.Error) {
	if err != nil {
		return nil, nex.NewError(nex.ResultCodes.Core.InvalidArgument, "change_error")
	}

	connection := packet.Sender().(*nex.PRUDPConnection)
	endpoint := connection.Endpoint().(*nex.PRUDPEndPoint)
	server := endpoint.Server
	callerPID := uint64(connection.PID())

	if link := relay.linkForPID(callerPID); link != nil {
		st := types.NewStationURL(stationToProbe)
		st.SetAddress(relay.publicHost)
		st.SetPortNumber(link.endpointFor(callerPID))
		stationToProbe = types.String(st.URL())
		logf("RELAY  ProbeInit: caller %d station -> relay", callerPID)
	}

	resp := nex.NewRMCSuccess(endpoint, nil)
	resp.ProtocolID = nat_traversal.ProtocolID
	resp.MethodID = nat_traversal.MethodRequestProbeInitiationExt
	resp.CallID = callID

	reqStream := nex.NewByteStreamOut(endpoint.LibraryVersions(), endpoint.ByteStreamSettings())
	stationToProbe.WriteTo(reqStream)

	rmcRequest := nex.NewRMCRequest(endpoint)
	rmcRequest.ProtocolID = nat_traversal.ProtocolID
	rmcRequest.CallID = 0xFFFF0000 + callID
	rmcRequest.MethodID = nat_traversal.MethodInitiateProbe
	rmcRequest.Parameters = reqStream.Bytes()
	rmcRequestBytes := rmcRequest.Bytes()

	for _, target := range targetList {
		targetStation := types.NewStationURL(target)
		if connectionID, ok := targetStation.RVConnectionID(); ok {
			t := endpoint.FindConnectionByID(connectionID)
			if t == nil {
				continue
			}
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
	}

	return resp, nil
}
