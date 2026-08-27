package main

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/PretendoNetwork/nex-go/v2"
)

// Protocol IDs as registered in nex-protocols-go. Names here are what we print
// in the log, so an unimplemented call is still readable.
var protocolNames = map[uint16]string{
	0x01: "RemoteLogDevice", 0x03: "NATTraversal", 0x0A: "TicketGranting",
	0x0B: "SecureConnection", 0x0E: "Notifications", 0x12: "Health",
	0x13: "Monitoring", 0x14: "Friends", 0x15: "MatchMaking",
	0x17: "Messaging", 0x18: "PersistentStore", 0x19: "AccountManagement",
	0x1B: "MessageDelivery", 0x32: "MatchMakingExt", 0x64: "NintendoNotifications",
	0x65: "Friends3DS", 0x6D: "MatchmakeExtension", 0x6E: "Utility",
	0x70: "Ranking", 0x73: "DataStore", 0x74: "Debug", 0x75: "Subscription",
	0x76: "Rating", 0x78: "MatchmakeReferee", 0x7A: "Ranking2",
}

var logMu sync.Mutex

func logf(format string, args ...any) {
	line := fmt.Sprintf("%s  %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
	logMu.Lock()
	defer logMu.Unlock()
	fmt.Print(line)
	if f, err := os.OpenFile("rmc.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		f.WriteString(line)
		f.Close()
	}
}

// logRMC records every call the game makes. This log is the whole point of the
// stub: it tells us exactly which protocols and methods to implement next.
func logRMC(server string, packet nex.PacketInterface) {
	request := packet.RMCMessage()

	name, known := protocolNames[request.ProtocolID]
	if !known {
		name = "UNKNOWN"
	}

	logf("*** RMC *** %s  protocol=0x%02X (%s)  method=%d  params=%d bytes",
		server, request.ProtocolID, name, request.MethodID, len(request.Parameters))
	if len(request.Parameters) > 0 {
		logf("       RAW PARAMS: %x", request.Parameters)
	}
}
