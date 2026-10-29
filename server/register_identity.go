package main

// Relay v2, part 2: make each console advertise its RELAY IDENTITY as its own
// public address at registration.
//
// WHY this is needed on top of the station-URL rewrite: the stock
// SecureConnection::Register(Ex) builds its response (urlPublic = "your public
// address") from the console's REAL observed address BEFORE the OnAfterRegister
// hook runs — and that hook is where relay v2 rewrote connection.StationURLs. So
// the participant list / probe target correctly carried the relay identity (the
// 3rd peer even probed the right identity), but the value the console got back as
// "your own public address" was its REAL address. Packet capture proved the
// consequence: joiners complete the joiner<->joiner NAT probe against the relay
// identity, then try to open the actual game (station) connection to each other's
// REAL address — which never traverses the relay and dies on cellular/VPN NAT.
//
// THE FIX: override Register/RegisterEx so publicStation is rewritten to the
// console's relay identity BEFORE urlPublic is built. Now the console reports the
// identity as its own address, so every peer — host AND joiner — reaches it only
// through the relay, for the probe AND the game connection. Gated to v2 PIDs; for
// non-v2 consoles it reproduces stock behaviour exactly.

import (
	"net"

	"github.com/PretendoNetwork/nex-go/v2"
	"github.com/PretendoNetwork/nex-go/v2/constants"
	"github.com/PretendoNetwork/nex-go/v2/types"
	secure "github.com/PretendoNetwork/nex-protocols-go/v2/secure-connection"
)

// installIdentityRegister overrides the secure-connection Register/RegisterEx
// handlers so v2 consoles advertise their relay identity as their public address.
func installIdentityRegister(sec *secure.Protocol) {
	sec.SetHandlerRegister(func(err error, packet nex.PacketInterface, callID uint32, vecMyURLs types.List[types.StationURL]) (*nex.RMCMessage, *nex.Error) {
		return buildRegisterResponse(packet, callID, vecMyURLs, secure.MethodRegister)
	})
	sec.SetHandlerRegisterEx(func(err error, packet nex.PacketInterface, callID uint32, vecMyURLs types.List[types.StationURL], hCustomData types.DataHolder) (*nex.RMCMessage, *nex.Error) {
		return buildRegisterResponse(packet, callID, vecMyURLs, secure.MethodRegisterEx)
	})
	logf("RELAY2 identity-register override installed (urlPublic -> relay identity for v2 PIDs)")
}

// buildRegisterResponse reproduces the stock SecureConnection register logic, but
// rewrites the public station to the console's relay identity (for v2 PIDs) before
// forming the returned urlPublic.
func buildRegisterResponse(packet nex.PacketInterface, callID uint32, vecMyURLs types.List[types.StationURL], methodID uint32) (*nex.RMCMessage, *nex.Error) {
	connection := packet.Sender().(*nex.PRUDPConnection)
	endpoint := connection.Endpoint()

	var localStation *types.StationURL
	var publicStation *types.StationURL
	for _, stationURL := range vecMyURLs {
		natf, ok := stationURL.NATFiltering()
		if !ok {
			continue
		}
		natm, ok := stationURL.NATMapping()
		if !ok {
			continue
		}
		if localStation == nil && !stationURL.IsPublic() {
			localStation = stationURL.CopyRef().(*types.StationURL)
		}
		if localStation == nil && natf == constants.UnknownNATFiltering && natm == constants.UnknownNATMapping {
			localStation = stationURL.CopyRef().(*types.StationURL)
		}
		if publicStation == nil && stationURL.IsPublic() {
			publicStation = stationURL.CopyRef().(*types.StationURL)
		}
	}

	if localStation == nil {
		return nil, nex.NewError(nex.ResultCodes.Core.InvalidArgument, "change_error")
	}

	if publicStation == nil {
		publicStation = localStation.CopyRef().(*types.StationURL)
		var address string
		var port uint16
		switch clientAddress := connection.Address().(type) {
		case *net.UDPAddr:
			address = clientAddress.IP.String()
			port = uint16(clientAddress.Port)
		case *net.TCPAddr:
			address = clientAddress.IP.String()
			port = uint16(clientAddress.Port)
		}
		publicStation.SetAddress(address)
		publicStation.SetPortNumber(port)
		publicStation.SetNATFiltering(constants.UnknownNATFiltering)
		publicStation.SetNATMapping(constants.UnknownNATMapping)
		publicStation.SetType(uint8(constants.StationURLFlagPublic) | uint8(constants.StationURLFlagBehindNAT))
	}

	localStation.SetPrincipalID(connection.PID())
	publicStation.SetPrincipalID(connection.PID())
	localStation.SetRVConnectionID(connection.ID)
	publicStation.SetRVConnectionID(connection.ID)

	// THE FIX: rewrite the public station to this console's relay identity, so the
	// value returned to the console (and thus self-reported to its peers) is the
	// relay address. Preserves every other station param, mirroring
	// relay2.rewriteStationURLs. Non-v2 consoles are untouched.
	pid := uint64(connection.PID())
	if relay2 != nil && v2Enabled(pid) {
		clientIP := ""
		if ua, ok := connection.Address().(*net.UDPAddr); ok && ua != nil {
			clientIP = ua.IP.String()
		}
		// ALWAYS create the relay identity and record the RVCID: even a
		// direct-capable (EIM) console keeps a relay identity so its links to
		// symmetric peers can still fall back to the relay (GetSessionURLs /
		// ProbeInit route those per-link).
		if p := relay2.identityFor(pid, clientIP); p != nil {
			relay2.noteRVCID(connection.ID, pid)
			if canDirect(pid) {
				// HYBRID: this console can hole-punch directly — advertise its REAL
				// public address so EIM peers reach it directly (low latency).
				logf("HYBRID register: pid=%d rvcid=%d directCapable -> real urlPublic", pid, connection.ID)
			} else {
				// Symmetric/unknown: advertise the relay identity as its own public
				// address, so every peer reaches it through the relay (works on any NAT).
				publicStation.SetAddress(relay2.publicHost)
				publicStation.SetPortNumber(uint16(p.port))
				logf("RELAY2 register: pid=%d rvcid=%d urlPublic -> identity %s:%d", pid, connection.ID, relay2.publicHost, p.port)
			}
		}
	}

	connection.StationURLs = append(connection.StationURLs, *localStation)
	connection.StationURLs = append(connection.StationURLs, *publicStation)

	pidConnectionID := types.NewUInt32(connection.ID)
	urlPublic := types.NewString(publicStation.URL())
	retval := types.NewQResultSuccess(nex.ResultCodes.Core.Unknown)

	rmcResponseStream := nex.NewByteStreamOut(endpoint.LibraryVersions(), endpoint.ByteStreamSettings())
	retval.WriteTo(rmcResponseStream)
	pidConnectionID.WriteTo(rmcResponseStream)
	urlPublic.WriteTo(rmcResponseStream)

	rmcResponse := nex.NewRMCSuccess(endpoint, rmcResponseStream.Bytes())
	rmcResponse.ProtocolID = secure.ProtocolID
	rmcResponse.MethodID = methodID
	rmcResponse.CallID = callID
	return rmcResponse, nil
}
