package nex

import (
	"crypto/md5"
	"net"
	"sync"
	"time"

	"github.com/PretendoNetwork/nex-go/v2/constants"
	"github.com/PretendoNetwork/nex-go/v2/types"
)

// PRUDPConnection implements an individual PRUDP virtual connection.
// Does not necessarily represent a socket connection.
// A single network socket may be used to open multiple PRUDP virtual connections
type PRUDPConnection struct {
	Socket                              *SocketConnection // * The connections parent socket
	endpoint                            *PRUDPEndPoint    // * The PRUDP endpoint the connection is connected to
	ConnectionState                     ConnectionState
	ID                                  uint32                                 // * Connection ID
	SessionID                           uint8                                  // * Random value generated at the start of the session. Client and server IDs do not need to match
	ServerSessionID                     uint8                                  // * Random value generated at the start of the session. Client and server IDs do not need to match
	SessionKey                          []byte                                 // * Secret key generated at the start of the session. Used for encrypting packets to the secure server
	pid                                 types.PID                              // * PID of the user
	DefaultPRUDPVersion                 int                                    // * The PRUDP version the connection was established with. Used for sending PING packets
	StreamType                          constants.StreamType                   // * rdv::Stream::Type used in this connection
	StreamID                            uint8                                  // * rdv::Stream ID, also called the "port number", used in this connection. 0-15 on PRUDPv0/v1, and 0-31 on PRUDPLite
	StreamSettings                      *StreamSettings                        // * Settings for this virtual connection
	Signature                           []byte                                 // * Connection signature for packets coming from the client, as seen by the server
	ServerConnectionSignature           []byte                                 // * Connection signature for packets coming from the server, as seen by the client
	UnreliablePacketBaseKey             []byte                                 // * The base key used for encrypting unreliable DATA packets
	rtt                                 *RTT                                   // * The round-trip transmission time of this connection
	slidingWindows                      *MutexMap[uint8, *SlidingWindow]       // * Outbound reliable packet substreams
	packetDispatchQueues                *MutexMap[uint8, *PacketDispatchQueue] // * Inbound reliable packet substreams
	incomingFragmentBuffers             *MutexMap[uint8, []byte]               // * Buffers which store the incoming payloads from fragmented DATA packets
	OutgoingUnreliableSequenceIDCounter *Counter[uint16]
	outgoingPingSequenceIDCounter       *Counter[uint16]
	lastSentPingTime                    time.Time
	heartbeatTimer                      *time.Timer
	pingKickTimer                       *time.Timer
	StationURLs                         types.List[types.StationURL]
	mutex                               *sync.Mutex
}

// Endpoint returns the PRUDP endpoint the connections socket is connected to
func (pc *PRUDPConnection) Endpoint() EndpointInterface {
	return pc.endpoint
}

// Address returns the socket address of the connection
func (pc *PRUDPConnection) Address() net.Addr {
	return pc.Socket.Address
}

// PID returns the clients unique PID
func (pc *PRUDPConnection) PID() types.PID {
	return pc.pid
}

// SetPID sets the clients unique PID
func (pc *PRUDPConnection) SetPID(pid types.PID) {
	pc.pid = pid
}

// Reset resets the connection state to all zero values
func (pc *PRUDPConnection) Reset() {
	pc.ConnectionState = StateNotConnected
	pc.packetDispatchQueues.Clear(func(_ uint8, packetDispatchQueue *PacketDispatchQueue) {
		packetDispatchQueue.Purge()
	})

	pc.slidingWindows.Clear(func(_ uint8, slidingWindow *SlidingWindow) {
		slidingWindow.TimeoutManager.Stop()
	})

	pc.Signature = make([]byte, 0)
	pc.ServerConnectionSignature = make([]byte, 0)
	pc.SessionKey = make([]byte, 0)
	pc.OutgoingUnreliableSequenceIDCounter = NewCounter[uint16](1)
	pc.outgoingPingSequenceIDCounter = NewCounter[uint16](0)
}

// cleanup resets the connection state and cleans up some resources. Used when a client is considered dead and to be removed from the endpoint
func (pc *PRUDPConnection) cleanup() {
	pc.Reset()

	pc.stopHeartbeatTimers()

	pc.endpoint.emitConnectionEnded(pc)
}

// InitializeSlidingWindows initializes the SlidingWindows for all substreams
func (pc *PRUDPConnection) InitializeSlidingWindows(maxSubstreamID uint8) {
	// * Nuke any existing SlidingWindows
	pc.slidingWindows = NewMutexMap[uint8, *SlidingWindow]()

	for i := 0; i < int(maxSubstreamID+1); i++ {
		pc.CreateSlidingWindow(uint8(i))
	}
}

// InitializePacketDispatchQueues initializes the PacketDispatchQueues for all substreams
func (pc *PRUDPConnection) InitializePacketDispatchQueues(maxSubstreamID uint8) {
	// * Nuke any existing PacketDispatchQueues
	pc.packetDispatchQueues = NewMutexMap[uint8, *PacketDispatchQueue]()

	for i := 0; i < int(maxSubstreamID+1); i++ {
		pc.CreatePacketDispatchQueue(uint8(i))
	}
}

// CreateSlidingWindow creates a new SlidingWindow for the given substream and returns it
// if there is not a SlidingWindow for the given substream id it creates a new one
func (pc *PRUDPConnection) CreateSlidingWindow(substreamID uint8) *SlidingWindow {
	slidingWindow := NewSlidingWindow()
	slidingWindow.sequenceIDCounter = NewCounter[uint16](0) // * First DATA packet from the server has sequence ID 1 (start counter at 0 and is incremeneted)
	slidingWindow.streamSettings = pc.StreamSettings.Copy()

	pc.slidingWindows.Set(substreamID, slidingWindow)

	return slidingWindow
}

// SlidingWindow returns the SlidingWindow for the given substream
func (pc *PRUDPConnection) SlidingWindow(substreamID uint8) *SlidingWindow {
	slidingWindow, ok := pc.slidingWindows.Get(substreamID)
	if !ok {
		// * Fail-safe. The connection may not always have
		// * the correct number of substreams. See the
		// * comment in handleSocketMessage of PRUDPEndPoint
		// * for more details
		slidingWindow = pc.CreateSlidingWindow(substreamID)
	}

	return slidingWindow
}

// CreatePacketDispatchQueue creates a new PacketDispatchQueue for the given substream and returns it
func (pc *PRUDPConnection) CreatePacketDispatchQueue(substreamID uint8) *PacketDispatchQueue {
	pdq := NewPacketDispatchQueue()
	pc.packetDispatchQueues.Set(substreamID, pdq)
	return pdq
}

// PacketDispatchQueue returns the PacketDispatchQueue for the given substream
// if there is not a PacketDispatchQueue for the given substream it creates a new one
func (pc *PRUDPConnection) PacketDispatchQueue(substreamID uint8) *PacketDispatchQueue {
	packetDispatchQueue, ok := pc.packetDispatchQueues.Get(substreamID)
	if !ok {
		// * Fail-safe. The connection may not always have
		// * the correct number of substreams. See the
		// * comment in handleSocketMessage of PRUDPEndPoint
		// * for more details
		packetDispatchQueue = pc.CreatePacketDispatchQueue(substreamID)
	}

	return packetDispatchQueue
}

// SetSessionKey sets the connection's session key and updates the SlidingWindows
func (pc *PRUDPConnection) SetSessionKey(sessionKey []byte) {
	pc.SessionKey = sessionKey

	pc.slidingWindows.Each(func(substreamID uint8, slidingWindow *SlidingWindow) bool {
		// * Only the first substream uses the session key directly.
		// * All other substreams modify the key before it so that
		// * all substreams have a unique cipher key

		if substreamID == 0 {
			slidingWindow.SetCipherKey(sessionKey)
		} else {
			modifier := len(sessionKey)/2 + 1

			// * Create a new slice to avoid modifying past keys
			sessionKey = append(make([]byte, 0), sessionKey...)

			// * Only the first half of the key is modified
			for i := 0; i < len(sessionKey)/2; i++ {
				sessionKey[i] = (sessionKey[i] + byte(modifier-i)) & 0xFF
			}

			slidingWindow.SetCipherKey(sessionKey)
		}

		return false
	})

	// * Init the base key used for unreliable DATA packets.
	// *
	// * Since unreliable DATA packets can come in out of
	// * order, each packet uses a dedicated RC4 stream. The
	// * key of each RC4 stream is made up by using this base
	// * key, modified using the packets sequence/session IDs
	unreliableBaseKeyPart1 := md5.Sum(append(sessionKey, []byte{0x18, 0xD8, 0x23, 0x34, 0x37, 0xE4, 0xE3, 0xFE}...))
	unreliableBaseKeyPart2 := md5.Sum(append(sessionKey, []byte{0x23, 0x3E, 0x60, 0x01, 0x23, 0xCD, 0xAB, 0x80}...))

	pc.UnreliablePacketBaseKey = append(unreliableBaseKeyPart1[:], unreliableBaseKeyPart2[:]...)
}

// ResetHeartbeat is called whenever we hear from the client. It pushes out both
// the next keepalive ping and the silence-based kick deadline (see StartHeartbeat).
func (pc *PRUDPConnection) ResetHeartbeat() {
	if pc.heartbeatTimer != nil {
		pc.heartbeatTimer.Reset(ffePingInterval)
	}

	if pc.pingKickTimer != nil {
		pc.pingKickTimer.Reset(ffeSilenceKick)
	}
}

// Lock locks the inner mutex for the Connection
// This is used internally when reordering incoming fragmented packets to prevent
// race conditions when multiple packets for the same fragmented message are processed at once
func (pc *PRUDPConnection) Lock() {
	pc.mutex.Lock()
}

// Unlock unlocks the inner mutex for the Connection
// This is used internally when reordering incoming fragmented packets to prevent
// race conditions when multiple packets for the same fragmented message are processed at once
func (pc *PRUDPConnection) Unlock() {
	pc.mutex.Unlock()
}

// Gets the incoming fragment buffer for the given substream
func (pc *PRUDPConnection) GetIncomingFragmentBuffer(substreamID uint8) []byte {
	buffer, ok := pc.incomingFragmentBuffers.Get(substreamID)
	if !ok {
		buffer = make([]byte, 0)
		pc.incomingFragmentBuffers.Set(substreamID, buffer)
	}

	return buffer
}

// Sets the incoming fragment buffer for a given substream
func (pc *PRUDPConnection) SetIncomingFragmentBuffer(substreamID uint8, buffer []byte) {
	pc.incomingFragmentBuffers.Set(substreamID, buffer)
}

// Clears the outgoing buffer for a given substream
func (pc *PRUDPConnection) ClearOutgoingBuffer(substreamID uint8) {
	pc.incomingFragmentBuffers.Set(substreamID, make([]byte, 0))
}

// FFE keepalive tuning (see StartHeartbeat). During 3-4 player co-op the game
// traffic flows peer-to-peer through the relay, so the console<->server link
// goes idle. Strict home NATs then drop that idle UDP mapping and the console
// silently falls off, collapsing the whole party after a couple of minutes.
// Fix: ping often to keep the mapping warm, but be patient before declaring
// the connection dead. These replace the old single MaxSilenceTime (10s ping /
// 20s kick) which was too tight to survive a strict NAT during gameplay.
const (
	ffePingInterval = 5 * time.Second
	ffeSilenceKick  = 45 * time.Second
)


// StartHeartbeat initializes the connection's heartbeat timer.
func (pc *PRUDPConnection) StartHeartbeat() {
	endpoint := pc.endpoint

	// heartbeatTimer fires after ffePingInterval of client silence, sends a
	// PING, and re-arms itself so we keep prodding the console every interval.
	// The console ACKs the ping, which resets both timers (ResetHeartbeat) and
	// refreshes its NAT mapping. If we are already hearing from the console the
	// timer is pushed out, so we only ping when the link is actually idle.
	pc.heartbeatTimer = time.AfterFunc(ffePingInterval, func() {
		endpoint.sendPing(pc)
		if pc.heartbeatTimer != nil {
			pc.heartbeatTimer.Reset(ffePingInterval)
		}
	})

	// pingKickTimer is an independent deadline: only clean up the connection
	// after ffeSilenceKick of continuous silence (no packets at all from the
	// console, ping ACKs included). Reset in ResetHeartbeat on every receive.
	pc.pingKickTimer = time.AfterFunc(ffeSilenceKick, func() {
		endpoint.CleanupConnection(pc)
	})
}

func (pc *PRUDPConnection) stopHeartbeatTimers() {
	if pc.pingKickTimer != nil {
		pc.pingKickTimer.Stop()
	}

	if pc.heartbeatTimer != nil {
		pc.heartbeatTimer.Stop()
	}
}

// NewPRUDPConnection creates a new PRUDPConnection for a given socket
func NewPRUDPConnection(socket *SocketConnection) *PRUDPConnection {
	pc := &PRUDPConnection{
		Socket:                              socket,
		ConnectionState:                     StateNotConnected,
		rtt:                                 NewRTT(),
		pid:                                 types.NewPID(0),
		slidingWindows:                      NewMutexMap[uint8, *SlidingWindow](),
		packetDispatchQueues:                NewMutexMap[uint8, *PacketDispatchQueue](),
		OutgoingUnreliableSequenceIDCounter: NewCounter[uint16](1),
		outgoingPingSequenceIDCounter:       NewCounter[uint16](0),
		incomingFragmentBuffers:             NewMutexMap[uint8, []byte](),
		StationURLs:                         types.NewList[types.StationURL](),
		mutex:                               &sync.Mutex{},
		UnreliablePacketBaseKey:             make([]byte, md5.Size*2), // * Gets updated to the real value in SetSessionKey
	}

	return pc
}
