package enet

import "core:mem"
import "core:net"
import "core:fmt"
import "core:time"
import "core:intrinsics"

// TODO add compressor

/*
enet 
~1k lines definitions + forward decls
~200 lines atomics
~2k packet + protocol
~1k peer
~1k host
~1k platform specific

~5k * 0.8 = 4k odin?
*/

// TODO allow custom
BUFFER_MAXIMUM :: 1 + 2 * PROTOCOL_MAXIMUM_PACKET_COMMANDS

PROTOCOL_MINIMUM_MTU             :: 576
PROTOCOL_MAXIMUM_MTU             :: 4096
PROTOCOL_MAXIMUM_PACKET_COMMANDS :: 32
PROTOCOL_MINIMUM_WINDOW_SIZE     :: 4096
PROTOCOL_MAXIMUM_WINDOW_SIZE     :: 65536
PROTOCOL_MINIMUM_CHANNEL_COUNT   :: 1
PROTOCOL_MAXIMUM_CHANNEL_COUNT   :: 255
PROTOCOL_MAXIMUM_PEER_ID         :: 0xFFF
PROTOCOL_MAXIMUM_FRAGMENT_COUNT  :: 1024 * 1024

HOST_RECEIVE_BUFFER_SIZE          :: 256 * 1024
HOST_SEND_BUFFER_SIZE             :: 256 * 1024
HOST_BANDWIDTH_THROTTLE_INTERVAL  :: 1000 * time.Millisecond
HOST_DEFAULT_MTU                  :: 1400
HOST_DEFAULT_MAXIMUM_PACKET_SIZE  :: 32 * 1024 * 1024
HOST_DEFAULT_MAXIMUM_WAITING_DATA :: 32 * 1024 * 1024

PEER_DEFAULT_ROUND_TRIP_TIME      :: 500 * time.Millisecond
PEER_DEFAULT_PACKET_THROTTLE      :: 32
PEER_PACKET_THROTTLE_SCALE        :: 32
PEER_PACKET_THROTTLE_COUNTER      :: 7
PEER_PACKET_THROTTLE_ACCELERATION :: 2
PEER_PACKET_THROTTLE_DECELERATION :: 2
PEER_PACKET_THROTTLE_INTERVAL     :: 5000
PEER_PACKET_LOSS_SCALE            :: (1 << 16)
PEER_PACKET_LOSS_INTERVAL         :: 10000 * time.Millisecond
PEER_WINDOW_SIZE_SCALE            :: 64 * 1024
PEER_TIMEOUT_LIMIT                :: 32 * time.Millisecond
PEER_TIMEOUT_MINIMUM              :: 5000 * time.Millisecond
PEER_TIMEOUT_MAXIMUM              :: 30000 * time.Millisecond
PEER_PING_INTERVAL                :: 500 * time.Millisecond
PEER_UNSEQUENCED_WINDOWS          :: 64
PEER_UNSEQUENCED_WINDOW_SIZE      :: 1024
PEER_FREE_UNSEQUENCED_WINDOWS     :: 32
PEER_RELIABLE_WINDOWS             :: 16
PEER_RELIABLE_WINDOW_SIZE         :: 0x1000
PEER_FREE_RELIABLE_WINDOWS        :: 8

PROTOCOL_COMMAND_NONE                     :: 0
PROTOCOL_COMMAND_ACKNOWLEDGE              :: 1
PROTOCOL_COMMAND_CONNECT                  :: 2
PROTOCOL_COMMAND_VERIFY_CONNECT           :: 3
PROTOCOL_COMMAND_DISCONNECT               :: 4
PROTOCOL_COMMAND_PING                     :: 5
PROTOCOL_COMMAND_SEND_RELIABLE            :: 6
PROTOCOL_COMMAND_SEND_UNRELIABLE          :: 7
PROTOCOL_COMMAND_SEND_FRAGMENT            :: 8
PROTOCOL_COMMAND_SEND_UNSEQUENCED         :: 9
PROTOCOL_COMMAND_BANDWIDTH_LIMIT          :: 10
PROTOCOL_COMMAND_THROTTLE_CONFIGURE       :: 11
PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT :: 12
PROTOCOL_COMMAND_COUNT                    :: 13
PROTOCOL_COMMAND_MASK                     :: 0x0F

commandSizes := [?]int {
	0,
	size_of(ProtocolAcknowledge),
	size_of(ProtocolConnect),
	size_of(ProtocolVerifyConnect),
	size_of(ProtocolDisconnect),
	size_of(ProtocolPing),
	size_of(ProtocolSendReliable),
	size_of(ProtocolSendUnreliable),
	size_of(ProtocolSendFragment),
	size_of(ProtocolSendUnsequenced),
	size_of(ProtocolBandwidthLimit),
	size_of(ProtocolThrottleConfigure),
	size_of(ProtocolSendFragment),
	0,
}

// const is better than enum in this case
PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE :: (1 << 7)
PROTOCOL_COMMAND_FLAG_UNSEQUENCED :: (1 << 6)

PROTOCOL_HEADER_FLAG_COMPRESSED :: (1 << 14)
PROTOCOL_HEADER_FLAG_SENT_TIME  :: (1 << 15)
PROTOCOL_HEADER_FLAG_MASK :: PROTOCOL_HEADER_FLAG_COMPRESSED | PROTOCOL_HEADER_FLAG_SENT_TIME

PROTOCOL_HEADER_SESSION_MASK  :: (3 << 12)
PROTOCOL_HEADER_SESSION_SHIFT :: 12

ProtocolHeader :: struct #packed {
	peerID: u16be,
	sentTime: u32be,
}

ProtocolCommandHeader :: struct #packed {
	command: u8,
	channelID: u8,
	reliableSequenceNumber: u16be,
}

ProtocolAcknowledge :: struct #packed {
	header: ProtocolCommandHeader,
	receivedReliableSequenceNumber: u16be,
	receivedSentTime: u32be,
}

ProtocolConnect :: struct #packed {
	header: ProtocolCommandHeader,
	outgoingPeerID: u16be,
	incomingSessionID: u8,
	outgoingSessionID: u8,
	mtu: u32be,
	windowSize: u32be,
	channelCount: u32be,
	incomingBandwidth: u32be,
	outgoingBandwidth: u32be,
	packetThrottleInterval: u32be,
	packetThrottleAcceleration: u32be,
	packetThrottleDeceleration: u32be,
	connectID: u32be,
	data: u32be,
}

ProtocolVerifyConnect :: struct #packed {
	header: ProtocolCommandHeader,
	outgoingPeerID: u16be,
	incomingSessionID: u8,
	outgoingSessionID: u8,
	mtu: u32be,
	windowSize: u32be,
	channelCount: u32be,
	incomingBandwidth: u32be,
	outgoingBandwidth: u32be,
	packetThrottleInterval: u32be,
	packetThrottleAcceleration: u32be,
	packetThrottleDeceleration: u32be,
	connectID: u32be,
}

ProtocolBandwidthLimit :: struct #packed {
	header: ProtocolCommandHeader,
	incomingBandwidth: u32be,
	outgoingBandwidth: u32be,
}

ProtocolThrottleConfigure :: struct #packed {
	header: ProtocolCommandHeader,
	packetThrottleInterval: u32be,
	packetThrottleAcceleration: u32be,
	packetThrottleDeceleration: u32be,
}

ProtocolDisconnect :: struct #packed {
	header: ProtocolCommandHeader,
	data: u32be,
}

ProtocolPing :: struct #packed {
	header: ProtocolCommandHeader,
}

ProtocolSendReliable :: struct #packed {
	header: ProtocolCommandHeader,
	dataLength: u16be,
}

ProtocolSendUnreliable :: struct #packed {
	header: ProtocolCommandHeader,
	unreliableSequenceNumber: u16be,
	dataLength: u16be,
}

ProtocolSendUnsequenced :: struct #packed {
	header: ProtocolCommandHeader,
	unsequencedGroup: u16be,
	dataLength: u16be,
}

ProtocolSendFragment :: struct #packed {
	header: ProtocolCommandHeader,
	startSequenceNumber: u16be,
	dataLength: u16be,
	fragmentCount: u32be,
	fragmentNumber: u32be,
	totalLength: u32be,
	fragmentOffset: u32be,
}

Protocol :: struct #raw_union {
	header: ProtocolCommandHeader,
	acknowledge: ProtocolAcknowledge,
	connect: ProtocolConnect,
	verifyConnect: ProtocolVerifyConnect,
	disconnect: ProtocolDisconnect,
	ping: ProtocolPing,
	sendReliable: ProtocolSendReliable,
	sendUnreliable: ProtocolSendUnreliable,
	sendUnsequenced: ProtocolSendUnsequenced,
	sendFragment: ProtocolSendFragment,
	bandwidthLimit: ProtocolBandwidthLimit,
	throttleConfigure: ProtocolThrottleConfigure,
}

PACKET_FLAG_RELIABLE            :: (1 << 0) // packet must be received by the target peer and resend attempts should be made until the packet is delivered
PACKET_FLAG_UNSEQUENCED         :: (1 << 1) // packet will not be sequenced with other packets not supported for reliable packets
PACKET_FLAG_NO_ALLOCATE         :: (1 << 2) // packet will not allocate data, and user must supply it instead
PACKET_FLAG_UNRELIABLE_FRAGMENT :: (1 << 3) // packet will be fragmented using unreliable (instead of reliable) sends if it exceeds the MTU
PACKET_FLAG_SENT                :: (1 << 8) // whether the packet has been sent from all queues it has been entered into

Packet :: struct {
	referenceCount: int,
	flags: u32,
	data: rawptr,
	dataLength: int,
	userData: rawptr,
}

Acknowledgement :: struct {
	using acknowledgementList: ListNode,
	sentTime: time.Time,
	command: Protocol,
}

OutgoingCommand :: struct {
	using outgoingCommandList: ListNode,
	reliableSequenceNumber: u16,
	unreliableSequenceNumber: u16,
	sentTime: time.Time,
	roundTripTimeout: time.Duration,
	roundTripTimeoutLimit: time.Duration,
	fragmentOffset: u32,
	fragmentLength: u16,
	sendAttempts: u16,
	command: Protocol,
	packet: ^Packet,
}

IncomingCommand :: struct {
	using incomingCommandList: ListNode,
	reliableSequenceNumber: u16,
	unreliableSequenceNumber: u16,
	command: Protocol,
	fragmentCount: u32,
	fragmentsRemaining: u32,
	fragments: ^u32, // TODO slice
	packet: ^Packet,
}

PeerState :: enum {
	DISCONNECTED             = 0,
	CONNECTING               = 1,
	ACKNOWLEDGING_CONNECT    = 2,
	CONNECTION_PENDING       = 3,
	CONNECTION_SUCCEEDED     = 4,
	CONNECTED                = 5,
	DISCONNECT_LATER         = 6,
	DISCONNECTING            = 7,
	ACKNOWLEDGING_DISCONNECT = 8,
	ZOMBIE                   = 9,
}

State :: struct {
	hosts: Stack(Host, 8),
}
__state: ^State

Host :: struct {
	socket: net.UDP_Socket,
	incomingBandwidth: u32, // downstream bandwidth of the host
	outgoingBandwidth: u32, // upstream bandwidth of the host
	bandwidthThrottleEpoch: time.Time,
	mtu: u32,
	randomSeed: u32,
	recalculateBandwidthLimits: bool,
	peers: []Peer,
	channelLimit: int, // maximum number of channels allowed for connected peers
	serviceTime: time.Time,
	continueSending: bool,
	packetSize: int,
	headerFlags: u16,
	dispatchQueue: List,
	
	buffers: [BUFFER_MAXIMUM][]byte,
	bufferCount: int,

	commands: [PROTOCOL_MAXIMUM_PACKET_COMMANDS]Protocol,
	commandCount: int,

	// checksum: ChecksumCallback, // callback the user can set to enable packet checksums for this host
	intercept: InterceptCallback, // callback the user can set to intercept received raw UDP packets

	// ENetCompressor        compressor,
	packetData: [PROTOCOL_MAXIMUM_MTU * 2]byte,

	receivedEndpoint: net.Endpoint,
	receivedData: []byte,

	totalSentData: u32,        // total data sent, user should reset to 0 as needed to prevent overflow
	totalSentPackets: u32,     // total UDP packets sent, user should reset to 0 as needed to prevent overflow
	totalReceivedData: u32,    // total data received, user should reset to 0 as needed to prevent overflow
	totalReceivedPackets: u32, // total UDP packets received, user should reset to 0 as needed to prevent overflow
	connectedPeers: int,
	bandwidthLimitedPeers: int,
	duplicatePeers: int,     // optional number of allowed peers from duplicate IPs, defaults to PROTOCOL_MAXIMUM_PEER_ID
	maximumPacketSize: int,  // the maximum allowable packet size that may be sent or received on a peer
	maximumWaitingData: int, // the maximum aggregate amount of buffer space a peer may use waiting for packets to be delivered
}

Peer :: struct {
	dispatchList: ListNode,
	host: ^Host,
	outgoingPeerID: u16,
	incomingPeerID: u16,
	connectID: u32,
	outgoingSessionID: u8,
	incomingSessionID: u8,
	endpoint: net.Endpoint, // Internet address of the peer
	data: rawptr,    // Application private data, may be freely modified
	state: PeerState,
	channels: []Channel,
	incomingBandwidth: u32, // Downstream bandwidth of the client in bytes/second
	outgoingBandwidth: u32, // Upstream bandwidth of the client in bytes/second
	incomingBandwidthThrottleEpoch: time.Time,
	outgoingBandwidthThrottleEpoch: time.Time,
	incomingDataTotal: u32,
	totalDataReceived: u64,
	outgoingDataTotal: u32,
	totalDataSent: u64,
	lastSendTime: time.Time,
	lastReceiveTime: time.Time,
	nextTimeout: time.Time,
	earliestTimeout: time.Time,
	packetLossEpoch: time.Time,
	packetsSent: u32,
	totalPacketsSent: u64, // total number of packets sent during a session
	packetsLost: u32,
	totalPacketsLost: u32,     // total number of packets lost during a session
	packetLoss: u32, // mean packet loss of reliable packets as a ratio with respect to the constant PEER_PACKET_LOSS_SCALE
	packetLossVariance: u32,
	packetThrottle: time.Duration,
	packetThrottleLimit: time.Duration,
	packetThrottleCounter: time.Duration,
	packetThrottleEpoch: time.Time,
	packetThrottleAcceleration: time.Duration,
	packetThrottleDeceleration: time.Duration,
	packetThrottleInterval: time.Duration,
	pingInterval: time.Duration,
	timeoutLimit: time.Duration,
	timeoutMinimum: time.Duration,
	timeoutMaximum: time.Duration,
	lastRoundTripTime: time.Duration,
	lowestRoundTripTime: time.Duration,
	lastRoundTripTimeVariance: time.Duration,
	highestRoundTripTimeVariance: time.Duration,
	roundTripTime: time.Duration, // mean round trip time (RTT), in milliseconds, between sending a reliable packet and receiving its acknowledgement
	roundTripTimeVariance: time.Duration,
	mtu: u32,
	windowSize: u32,
	reliableDataInTransit: u32,
	outgoingReliableSequenceNumber: u16,
	acknowledgements: List,
	sentReliableCommands: List,
	sentUnreliableCommands: List,
	outgoingReliableCommands: List,
	outgoingUnreliableCommands: List,
	dispatchedCommands: List,
	needsDispatch: bool,
	incomingUnsequencedGroup: u16,
	outgoingUnsequencedGroup: u16,
	unsequencedWindow: [PEER_UNSEQUENCED_WINDOW_SIZE / 32]u32,
	eventData: u32,
	totalWaitingData: int,
}

Channel :: struct {
	outgoingReliableSequenceNumber: u16,
	outgoingUnreliableSequenceNumber: u16,
	usedReliableWindows: u16,
	reliableWindows: [PEER_RELIABLE_WINDOWS]u16,
	incomingReliableSequenceNumber: u16,
	incomingUnreliableSequenceNumber: u16,
	incomingReliableCommands: List,
	incomingUnreliableCommands: List,
}

EventType :: enum {
	NONE = 0,
	CONNECT = 1,
	DISCONNECT = 2,
	RECEIVE = 3,
	DISCONNECT_TIMEOUT = 4,
}

Event :: struct {
	type: EventType, // type of the event
	peer: ^Peer, // peer that generated a connect, disconnect or receive event
	channelID: u8, // channel on the peer that generated the event, if appropriate
	data: u32, // data associated with the event, if appropriate
	packet: ^Packet, // packet associated with the event, if appropriate
}

// Compressor :. struct {
// 	userData: rawptr,


// }

// Callback that computes the checksum of the data held in buffers[0:bufferCount-1]
// ChecksumCallback :: proc(buffers: [])

// Callback for intercepting received raw UDP packets. Should return 1 to intercept, 0 to ignore, or -1 to propagate an error.
InterceptCallback :: proc(host: ^Host, event: rawptr)

initialize :: proc() {
	__state = new(State)
}

deinitialize :: proc() {
	free(__state)
}

// TEMP
net_err_panic :: proc(err: net.Network_Error, loc := #caller_location) {
	if err != nil {
		fmt.panicf("NET ERR: %v at %v\n", err, loc)
	}
}
net_err_print :: proc(err: net.Network_Error, loc := #caller_location) {
	if err != nil {
		fmt.printf("NET ERR: %v at %v\n", err, loc)
	}
}

host_flush :: proc(host: ^Host) {
	host.serviceTime = time.now()
	protocol_send_outgoing_commands(host, nil, false)
}

host_check_events :: proc(host: ^Host, event: ^Event) -> bool {
	if event == nil {
		return false
	}

	event.type = .NONE
	event.peer = nil
	event.packet = nil

	return protocol_dispatch_incoming_commands(host, event)
}

host_service :: proc(host: ^Host, event: ^Event, timeout: time.Duration) -> bool {
	if event != nil {
		event.type = .NONE
		event.peer = nil 
		event.packet = nil

		if protocol_dispatch_incoming_commands(host, event) {
			return true
		}
	}

	host.serviceTime = time.now()
	wanted_timeout := time.time_add(host.serviceTime, timeout)

	for {
		if time.diff(host.serviceTime, host.bandwidthThrottleEpoch) >= HOST_BANDWIDTH_THROTTLE_INTERVAL {
			host_bandwidth_throttle(host)
		}

		if protocol_send_outgoing_commands(host, event, true) {
			return true
		}

		if protocol_receive_incoming_commands(host, event) {
			return true
		}

		if protocol_send_outgoing_commands(host, event, true) {
			return true
		}

		if event != nil {
			if protocol_dispatch_incoming_commands(host, event) {
				return true
			}
		}

		if host.serviceTime._nsec >= wanted_timeout._nsec {
			return false
		}

		host.serviceTime = time.now()
	}
}

// ! HOST

host_create :: proc(
	endpoint: net.Endpoint,
	peerCount: int,
	channelLimit: int,
	incomingBandwidth: u32,
	outgoingBandwidth: u32,
) -> (host: ^Host) {
	if peerCount > PROTOCOL_MAXIMUM_PEER_ID {
		return
	}

	host = stack_push(&__state.hosts)
	host.peers = make([]Peer, peerCount)

	skt, skt_err := net.make_bound_udp_socket(endpoint.address, endpoint.port)
	net.set_blocking(skt, false)
	net.set_option(skt, .Receive_Buffer_Size, HOST_RECEIVE_BUFFER_SIZE)
	net.set_option(skt, .Send_Buffer_Size, HOST_SEND_BUFFER_SIZE)
	// TODO add broadcast option
	net_err_print(skt_err)
	host.socket = skt

	channelLimit := channelLimit
	if channelLimit > PROTOCOL_MAXIMUM_CHANNEL_COUNT {
		channelLimit = PROTOCOL_MAXIMUM_CHANNEL_COUNT
	}

	host.randomSeed = u32(uintptr(host) % max(uintptr))
	host.randomSeed += u32(intrinsics.read_cycle_counter())
	host.randomSeed = (host.randomSeed << 16) | (host.randomSeed >> 16)
	host.channelLimit = channelLimit
	host.incomingBandwidth = incomingBandwidth
	host.outgoingBandwidth = outgoingBandwidth
	host.mtu = HOST_DEFAULT_MTU
	host.receivedEndpoint = { net.IP4_Any, 0 }
	host.duplicatePeers = PROTOCOL_MAXIMUM_PEER_ID
	host.maximumPacketSize = HOST_DEFAULT_MAXIMUM_PACKET_SIZE
	host.maximumWaitingData = HOST_DEFAULT_MAXIMUM_WAITING_DATA

	list_clear(&host.dispatchQueue)

	for peer, i in &host.peers {
		peer.host = host
		peer.incomingPeerID = u16(i)
		peer.outgoingSessionID = 0xFF
		peer.incomingSessionID = 0xFF
		
		list_clear(&peer.acknowledgements)
		list_clear(&peer.sentReliableCommands)
		list_clear(&peer.sentUnreliableCommands)
		list_clear(&peer.outgoingReliableCommands)
		list_clear(&peer.outgoingUnreliableCommands)
		list_clear(&peer.dispatchedCommands)
		
		peer_reset(&peer)
	}

	return
}

host_destroy :: proc(host: ^Host) {
	net.close(host.socket)
	delete(host.peers)
}

host_connect :: proc(
	host: ^Host,
	endpoint: net.Endpoint,
	channelCount: int,
	data: u32,
) -> (result: ^Peer) {
	channelCount := clamp(channelCount, PROTOCOL_MINIMUM_CHANNEL_COUNT, PROTOCOL_MAXIMUM_CHANNEL_COUNT)
	currentPeer: ^Peer

	for peer in &host.peers {
		if peer.state == .DISCONNECTED {
			currentPeer = &peer
			break
		}
	}

	if currentPeer == nil {
		return
	}

	currentPeer.channels = make([]Channel, channelCount)
	currentPeer.state = .CONNECTING
	currentPeer.endpoint = endpoint
	currentPeer.connectID += 1
	currentPeer.connectID = host.randomSeed

	if host.outgoingBandwidth == 0 {
		currentPeer.windowSize = PROTOCOL_MAXIMUM_WINDOW_SIZE
	} else {
		currentPeer.windowSize = (host.outgoingBandwidth / PEER_WINDOW_SIZE_SCALE) * PROTOCOL_MINIMUM_WINDOW_SIZE
	}
	currentPeer.windowSize = clamp(currentPeer.windowSize, PROTOCOL_MINIMUM_WINDOW_SIZE, PROTOCOL_MAXIMUM_WINDOW_SIZE)

	for channel in &currentPeer.channels {
		list_clear(&channel.incomingReliableCommands)
		list_clear(&channel.incomingUnreliableCommands)
	}

	command: Protocol
	command.header.command = PROTOCOL_COMMAND_CONNECT | PROTOCOL_COMMAND_ACKNOWLEDGE
	command.header.channelID = 0xFF
	command.connect.outgoingPeerID             = u16be(currentPeer.incomingPeerID)
	command.connect.incomingSessionID          = currentPeer.incomingSessionID
	command.connect.outgoingSessionID          = currentPeer.outgoingSessionID
	command.connect.mtu                        = u32be(currentPeer.mtu)
	command.connect.windowSize                 = u32be(currentPeer.windowSize)
	command.connect.channelCount               = u32be(channelCount)
	command.connect.incomingBandwidth          = u32be(host.incomingBandwidth)
	command.connect.outgoingBandwidth          = u32be(host.outgoingBandwidth)
	command.connect.packetThrottleInterval     = u32be(currentPeer.packetThrottleInterval)
	command.connect.packetThrottleAcceleration = u32be(currentPeer.packetThrottleAcceleration)
	command.connect.packetThrottleDeceleration = u32be(currentPeer.packetThrottleDeceleration)
	command.connect.connectID                  = u32be(currentPeer.connectID)
	command.connect.data                       = u32be(data)

	peer_queue_outgoing_command(currentPeer, command, nil, 0, 0)
	return
}

host_broadcast :: proc(host: ^Host, channelID: u8, packet: ^Packet) {
	for currentPeer in &host.peers {
		if currentPeer.state != .CONNECTED {
			continue
		}

		peer_send(&currentPeer, channelID, packet)
	}

	if packet.referenceCount == 0 {
		// TODO callback
		packet_destroy(packet)
	}
}

// NOTE can be removed
host_send_raw :: #force_inline proc(host: ^Host, endpoint: net.Endpoint, data: []byte) {
	sentLength, err := net.send_udp(host.socket, data, endpoint)
	if err != nil {
		fmt.eprintln("ERR SEND", err, sentLength)
	}
}

host_channel_limit :: proc(host: ^Host, channelLimit: int) {
	channelLimit := channelLimit
	if channelLimit == 0 || channelLimit > PROTOCOL_MAXIMUM_CHANNEL_COUNT {
		channelLimit = PROTOCOL_MAXIMUM_CHANNEL_COUNT
	}
	host.channelLimit = channelLimit
}

host_bandwidth_limit :: proc(host: ^Host, incomingBandwidth, outgoingBandwidth: u32) {
	host.incomingBandwidth = incomingBandwidth
	host.outgoingBandwidth = outgoingBandwidth
	host.recalculateBandwidthLimits = true
}

host_bandwidth_throttle :: proc(host: ^Host) {
	timeCurrent := time.now()
	elapsedTime := time.diff(timeCurrent, host.bandwidthThrottleEpoch)
	peersRemaining := host.connectedPeers
	dataTotal: u32 = 0
	bandwidth: u32 = 0
	throttle: u32 = 0
	bandwidthLimit: u32 = 0
	needsAdjustment := host.bandwidthLimitedPeers > 0

	if elapsedTime < HOST_BANDWIDTH_THROTTLE_INTERVAL {
		return
	}

	if host.outgoingBandwidth == 0 && host.incomingBandwidth == 0 {
		return
	}

	host.bandwidthThrottleEpoch = timeCurrent

	if peersRemaining == 0 {
		return
	}

	if host.outgoingBandwidth != 0 {
		dataTotal = 0
		bandwidth = (host.outgoingBandwidth * u32(elapsedTime)) / 1000

		for peer in &host.peers {
			if peer.state != .CONNECTED && peer.state != .DISCONNECT_LATER {
				continue
			}

			dataTotal += peer.outgoingDataTotal
		}
	}

	for peersRemaining > 0 && needsAdjustment {
		needsAdjustment = false

		if dataTotal <= bandwidth {
			throttle = u32(PEER_PACKET_THROTTLE_SCALE)
		} else {
			throttle = (bandwidth * u32(PEER_PACKET_THROTTLE_SCALE)) / dataTotal
		}

		for peer in &host.peers {
			peerBandwidth: u32

			if (peer.state != .CONNECTED && peer.state != .DISCONNECT_LATER) ||
				peer.incomingBandwidth == 0 ||
				peer.outgoingBandwidthThrottleEpoch == timeCurrent
			{
				continue
			}

			peerBandwidth = (peer.incomingBandwidth * u32(elapsedTime)) / 1000
			if (throttle * peer.outgoingDataTotal) / PEER_PACKET_THROTTLE_SCALE <= peerBandwidth {
				continue
			}

			peer.packetThrottleLimit = time.Duration((u32(peerBandwidth) * PEER_PACKET_THROTTLE_SCALE) / peer.outgoingDataTotal)

			if peer.packetThrottleLimit == 0 {
				peer.packetThrottleLimit = 1
			}

			if peer.packetThrottle > peer.packetThrottleLimit {
				peer.packetThrottle = peer.packetThrottleLimit
			}

			peer.outgoingBandwidthThrottleEpoch = timeCurrent

			peer.incomingDataTotal = 0
			peer.outgoingDataTotal = 0

			needsAdjustment = true
			peersRemaining -= 1
			bandwidth -= peerBandwidth
			dataTotal -= peerBandwidth
		}
	}

	if peersRemaining > 0 {
		if dataTotal <= bandwidth {
			throttle = PEER_PACKET_THROTTLE_SCALE
		} else {
			throttle = (bandwidth * PEER_PACKET_THROTTLE_SCALE) / dataTotal
		}

		for peer in &host.peers {
			if (peer.state != .CONNECTED && peer.state != .DISCONNECT_LATER) || peer.outgoingBandwidthThrottleEpoch == timeCurrent {
				continue
			}

			peer.packetThrottleLimit = time.Millisecond * time.Duration(throttle)

			if peer.packetThrottle > peer.packetThrottleLimit {
				peer.packetThrottle = peer.packetThrottleLimit
			}

			peer.incomingDataTotal = 0
			peer.outgoingDataTotal = 0
		}
	}

	if host.recalculateBandwidthLimits {
		host.recalculateBandwidthLimits = false

		peersRemaining  = host.connectedPeers
		bandwidth       = host.incomingBandwidth
		needsAdjustment = true

		if bandwidth == 0 {
			bandwidthLimit = 0
		} else {
			for peersRemaining > 0 && needsAdjustment {
				needsAdjustment = false
				bandwidthLimit  = bandwidth / u32(peersRemaining)

				for peer in &host.peers {
					if (peer.state != .CONNECTED && peer.state != .DISCONNECT_LATER) ||
						peer.incomingBandwidthThrottleEpoch == timeCurrent
					{
						continue
					}

					if peer.outgoingBandwidth > 0 && peer.outgoingBandwidth >= bandwidthLimit {
						continue
					}

					peer.incomingBandwidthThrottleEpoch = timeCurrent

					needsAdjustment = true
					peersRemaining -= 1
					bandwidth -= peer.outgoingBandwidth
				}
			}
		}

		for peer in &host.peers {
			if peer.state != .CONNECTED && peer.state != .DISCONNECT_LATER {
				continue
			}

			command: Protocol
			command.header.command   = PROTOCOL_COMMAND_BANDWIDTH_LIMIT | PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE
			command.header.channelID = 0xFF
			command.bandwidthLimit.outgoingBandwidth = u32be(host.outgoingBandwidth)

			if peer.incomingBandwidthThrottleEpoch == timeCurrent {
				command.bandwidthLimit.incomingBandwidth = u32be(peer.outgoingBandwidth)
			} else {
				command.bandwidthLimit.incomingBandwidth = u32be(bandwidthLimit)
			}

			peer_queue_outgoing_command(&peer, command, nil, 0, 0)
		}
	}
}

// ! PEER

peer_throttle_configure :: proc(peer: ^Peer, interval, acceleration, deceleration: time.Duration) {
	peer.packetThrottleInterval     = interval
	peer.packetThrottleAcceleration = acceleration
	peer.packetThrottleDeceleration = deceleration

	command: Protocol
	command.header.command   = PROTOCOL_COMMAND_THROTTLE_CONFIGURE | PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE
	command.header.channelID = 0xFF

	command.throttleConfigure.packetThrottleInterval     = u32be(interval)
	command.throttleConfigure.packetThrottleAcceleration = u32be(acceleration)
	command.throttleConfigure.packetThrottleDeceleration = u32be(deceleration)

	peer_queue_outgoing_command(peer, command, nil, 0, 0)
}

peer_throttle :: proc(peer: ^Peer, rtt: time.Duration) -> int {
	if peer.lastRoundTripTime <= peer.lastRoundTripTimeVariance {
		peer.packetThrottle = peer.packetThrottleLimit
	}	else if rtt < peer.lastRoundTripTime {
		peer.packetThrottle += peer.packetThrottleAcceleration

		if peer.packetThrottle > peer.packetThrottleLimit {
			peer.packetThrottle = peer.packetThrottleLimit
		}

		return 1
	}	else if rtt > peer.lastRoundTripTime + 2 * peer.lastRoundTripTimeVariance {
		if peer.packetThrottle > peer.packetThrottleDeceleration {
			peer.packetThrottle -= peer.packetThrottleDeceleration
		} else {
			peer.packetThrottle = 0
		}

		return -1
	}

	return 0
}

peer_send :: proc(peer: ^Peer, channelID: u8, packet: ^Packet) -> bool {
	channel := peer.channels[channelID]

	if peer.state != .CONNECTED || channelID >= u8(len(peer.channels)) || packet.dataLength > peer.host.maximumPacketSize {
		return false
	}

	fragmentLength := int(peer.mtu - size_of(ProtocolHeader) - size_of(ProtocolSendFragment))
	// TODO checksum
	// if peer.host.checksum != nil {
	// 	fragmentLength -= size_of(u32)
	// }

	if packet.dataLength > fragmentLength {
		fragmentCount := (packet.dataLength + fragmentLength - 1) / fragmentLength
		commandNumber: u8
		startSequenceNumber: u16be
		fragments: List
		fragment: ^OutgoingCommand

		if fragmentCount > PROTOCOL_MAXIMUM_FRAGMENT_COUNT {
			return false
		}

		if (packet.flags & (PACKET_FLAG_RELIABLE | PACKET_FLAG_UNRELIABLE_FRAGMENT)) == PACKET_FLAG_UNRELIABLE_FRAGMENT && 
			channel.outgoingUnreliableSequenceNumber < 0xFFFF {
			commandNumber       = PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT
			startSequenceNumber = u16be(channel.outgoingUnreliableSequenceNumber + 1)
		} else {
			commandNumber       = PROTOCOL_COMMAND_SEND_FRAGMENT | PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE
			startSequenceNumber = u16be(channel.outgoingReliableSequenceNumber + 1)
		}

		list_clear(&fragments)
		fragmentNumber := 0
		fragmentOffset := 0
		
		for fragmentOffset < packet.dataLength {
			if packet.dataLength - fragmentOffset < fragmentLength {
				fragmentLength = packet.dataLength - fragmentOffset
			}

			fragment = new(OutgoingCommand)
			fragment.fragmentOffset           = u32(fragmentOffset)
			fragment.fragmentLength           = u16(fragmentLength)
			fragment.packet                   = packet
			fragment.command.header.command   = commandNumber
			fragment.command.header.channelID = channelID

			fragment.command.sendFragment.startSequenceNumber = startSequenceNumber

			fragment.command.sendFragment.dataLength     = u16be(fragmentLength)
			fragment.command.sendFragment.fragmentCount  = u32be(fragmentCount)
			fragment.command.sendFragment.fragmentNumber = u32be(fragmentNumber)
			fragment.command.sendFragment.totalLength    = u32be(packet.dataLength)
			fragment.command.sendFragment.fragmentOffset = u32be(fragmentOffset)

			list_insert(list_end(&fragments), fragment)

			fragmentNumber += 1
			fragmentOffset += fragmentLength
		}

		packet.referenceCount += fragmentNumber

		for !list_empty(&fragments) {
			fragment = cast(^OutgoingCommand) list_remove(list_begin(&fragments))
			peer_setup_outgoing_command(peer, fragment)
		}

		return false
	}

	command: Protocol
	command.header.channelID = channelID

	if (packet.flags & (PACKET_FLAG_RELIABLE | PACKET_FLAG_UNSEQUENCED)) == PACKET_FLAG_UNSEQUENCED {
		command.header.command = PROTOCOL_COMMAND_SEND_UNSEQUENCED | PROTOCOL_COMMAND_FLAG_UNSEQUENCED
		command.sendUnsequenced.dataLength = u16be(packet.dataLength)
	}	else if (packet.flags & PACKET_FLAG_RELIABLE == PACKET_FLAG_RELIABLE) || channel.outgoingUnreliableSequenceNumber >= 0xFFFF {
		command.header.command = PROTOCOL_COMMAND_SEND_RELIABLE | PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE
		command.sendReliable.dataLength = u16be(packet.dataLength)
	}
	else {
		command.header.command = PROTOCOL_COMMAND_SEND_UNRELIABLE
		command.sendUnreliable.dataLength = u16be(packet.dataLength)
	}

	if peer_queue_outgoing_command(peer, command, packet, 0, u16(packet.dataLength)) == nil {
		return false
	}

	return true
}

peer_receive :: proc(peer: ^Peer, channelID: ^u8) -> (packet: ^Packet) {
	if list_empty(&peer.dispatchedCommands) {
		return
	}

	incomingCommand := cast(^IncomingCommand) list_remove(list_begin(&peer.dispatchedCommands))

	if channelID != nil {
		channelID^ = incomingCommand.command.header.channelID
	}

	packet = incomingCommand.packet
	packet.referenceCount -= 1

	if incomingCommand.fragments != nil {
		free(incomingCommand.fragments)
	}

	free(incomingCommand)
	peer.totalWaitingData -= packet.dataLength
	return
}

peer_reset_outgoing_commands :: proc(queue: ^List) {
	for !list_empty(queue) {
		outgoingCommand := cast(^OutgoingCommand) list_remove(list_begin(queue))

		if outgoingCommand.packet != nil {
			outgoingCommand.packet.referenceCount -= 1

			if outgoingCommand.packet.referenceCount == 0 {
				// TODO destroy packet
				packet_destroy(outgoingCommand.packet)
			}
		}

		free(outgoingCommand)
	}
}

peer_remove_incoming_commands :: proc(startCommand, endCommand: ListIterator) {
	currentCommand := startCommand

	for currentCommand != endCommand {
		incomingCommand := cast(^IncomingCommand) currentCommand

		currentCommand = list_next(currentCommand)
		list_remove(&incomingCommand.incomingCommandList)

		if incomingCommand.packet != nil {
			incomingCommand.packet.referenceCount -= 1

			if incomingCommand.packet.referenceCount == 0 {
				// TODO callbacks?
				packet_destroy(incomingCommand.packet)
			}
		}

		if incomingCommand.fragments != nil {
			free(incomingCommand.fragments)
		}

		free(incomingCommand)
	}
}

peer_reset_incoming_commands :: proc(queue: ^List) {
	peer_remove_incoming_commands(list_begin(queue), list_end(queue))
}

peer_reset_queues :: proc(peer: ^Peer) {
	if peer.needsDispatch {
		list_remove(&peer.dispatchList)
		peer.needsDispatch = false
	}

	for !list_empty(&peer.acknowledgements) {
		list_remove(list_begin(&peer.acknowledgements))
	}

	peer_reset_outgoing_commands(&peer.sentReliableCommands)
	peer_reset_outgoing_commands(&peer.sentUnreliableCommands)
	peer_reset_outgoing_commands(&peer.outgoingReliableCommands)
	peer_reset_outgoing_commands(&peer.outgoingUnreliableCommands)
	peer_reset_incoming_commands(&peer.dispatchedCommands)

	if peer.channels != nil && len(peer.channels) > 0 {
		for channel in &peer.channels {
			peer_reset_incoming_commands(&channel.incomingReliableCommands)
			peer_reset_incoming_commands(&channel.incomingUnreliableCommands)
		}
	}

	delete(peer.channels)
	peer.channels = nil
}

peer_on_connect :: proc(using peer: ^Peer) {
	if peer.state != .CONNECTED && peer.state != .DISCONNECT_LATER {
		if peer.incomingBandwidth != 0 {
			peer.host.bandwidthLimitedPeers += 1
		}
		
		peer.host.connectedPeers += 1
	}
}

peer_on_disconnect :: proc(using peer: ^Peer) {
	if peer.state == .CONNECTED || peer.state == .DISCONNECT_LATER {
		if peer.incomingBandwidth != 0 {
			peer.host.bandwidthLimitedPeers -= 1
		}
		
		peer.host.connectedPeers -= 1
	}
}

peer_reset :: proc(peer: ^Peer) {
	peer_on_disconnect(peer)
	
	peer.outgoingPeerID                 = PROTOCOL_MAXIMUM_PEER_ID
	peer.state                          = .DISCONNECTED
	peer.incomingBandwidth              = 0
	peer.outgoingBandwidth              = 0
	peer.incomingBandwidthThrottleEpoch = {}
	peer.outgoingBandwidthThrottleEpoch = {}
	peer.incomingDataTotal              = 0
	peer.totalDataReceived              = 0
	peer.outgoingDataTotal              = 0
	peer.totalDataSent                  = 0
	peer.lastSendTime                   = {}
	peer.lastReceiveTime                = {}
	peer.nextTimeout                    = {}
	peer.earliestTimeout                = {}
	peer.packetLossEpoch                = {}
	peer.packetsSent                    = 0
	peer.totalPacketsSent               = 0
	peer.packetsLost                    = 0
	peer.totalPacketsLost               = 0
	peer.packetLoss                     = 0
	peer.packetLossVariance             = 0
	peer.packetThrottle                 = PEER_DEFAULT_PACKET_THROTTLE
	peer.packetThrottleLimit            = PEER_PACKET_THROTTLE_SCALE
	peer.packetThrottleCounter          = 0
	peer.packetThrottleEpoch            = {}
	peer.packetThrottleAcceleration     = PEER_PACKET_THROTTLE_ACCELERATION
	peer.packetThrottleDeceleration     = PEER_PACKET_THROTTLE_DECELERATION
	peer.packetThrottleInterval         = PEER_PACKET_THROTTLE_INTERVAL
	peer.timeoutLimit                   = PEER_TIMEOUT_LIMIT
	peer.timeoutMinimum                 = PEER_TIMEOUT_MINIMUM
	peer.timeoutMaximum                 = PEER_TIMEOUT_MAXIMUM
	peer.lastRoundTripTime              = PEER_DEFAULT_ROUND_TRIP_TIME
	peer.lowestRoundTripTime            = PEER_DEFAULT_ROUND_TRIP_TIME
	peer.lastRoundTripTimeVariance      = 0
	peer.highestRoundTripTimeVariance   = 0
	peer.roundTripTime                  = PEER_DEFAULT_ROUND_TRIP_TIME
	peer.roundTripTimeVariance          = 0
	peer.mtu                            = peer.host.mtu
	peer.reliableDataInTransit          = 0
	peer.outgoingReliableSequenceNumber = 0
	peer.windowSize                     = PROTOCOL_MAXIMUM_WINDOW_SIZE
	peer.incomingUnsequencedGroup       = 0
	peer.outgoingUnsequencedGroup       = 0
	peer.eventData                      = 0
	peer.totalWaitingData               = 0
	peer.unsequencedWindow              = {}

	peer_reset_queues(peer)
}

peer_ping :: proc(peer: ^Peer) {
	if peer.state != .CONNECTED {
		return
	}

	command: Protocol
	command.header.command   = PROTOCOL_COMMAND_PING | PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE
	command.header.channelID = 0xFF
	peer_queue_outgoing_command(peer, command, nil, 0, 0)
}

peer_ping_interval :: proc(peer: ^Peer, pingInterval: time.Duration) {
	peer.pingInterval = pingInterval != 0 ? pingInterval : PEER_PING_INTERVAL
}

peer_peer_timeout :: proc(peer: ^Peer, timeoutLimit, timeoutMinimum, timeoutMaximum: time.Duration) {
	peer.timeoutLimit   = timeoutLimit != 0 ? timeoutLimit : PEER_TIMEOUT_LIMIT
	peer.timeoutMinimum = timeoutMinimum != 0 ? timeoutMinimum : PEER_TIMEOUT_MINIMUM
	peer.timeoutMaximum = timeoutMaximum != 0 ? timeoutMaximum : PEER_TIMEOUT_MAXIMUM
}

peer_disconnect_now :: proc(peer: ^Peer, data: u32) {
	if peer.state == .DISCONNECTED {
		return
	}

	if peer.state != .ZOMBIE && peer.state != .DISCONNECTING {
		peer_reset_queues(peer)

		command: Protocol
		command.header.command   = PROTOCOL_COMMAND_DISCONNECT | PROTOCOL_COMMAND_FLAG_UNSEQUENCED
		command.header.channelID = 0xFF
		command.disconnect.data  = u32be(data)

		peer_queue_outgoing_command(peer, command, nil, 0, 0)
		host_flush(peer.host)
	}

	peer_reset(peer)
}

peer_disconnect :: proc(peer: ^Peer, data: u32) {
	if peer.state == .DISCONNECTING ||
		peer.state == .DISCONNECTED ||
		peer.state == .ACKNOWLEDGING_DISCONNECT ||
		peer.state == .ZOMBIE {
		return
	}

	peer_reset_queues(peer)

	command: Protocol
	command.header.command   = PROTOCOL_COMMAND_DISCONNECT
	command.header.channelID = 0xFF
	command.disconnect.data  = u32be(data)

	if peer.state == .CONNECTED || peer.state == .DISCONNECT_LATER {
		command.header.command |= PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE
	} else {
		command.header.command |= PROTOCOL_COMMAND_FLAG_UNSEQUENCED
	}

	peer_queue_outgoing_command(peer, command, nil, 0, 0)

	if peer.state == .CONNECTED || peer.state == .DISCONNECT_LATER {
		peer_on_disconnect(peer)
		peer.state = .DISCONNECTING
	} else {
		host_flush(peer.host)
		peer_reset(peer)
	}
}

peer_disconnect_later :: proc(peer: ^Peer, data: u32) {
	if (peer.state == .CONNECTED || peer.state == .DISCONNECT_LATER) &&
		!(list_empty(&peer.outgoingReliableCommands) &&
		list_empty(&peer.outgoingUnreliableCommands) &&
		list_empty(&peer.sentReliableCommands)) {
		peer.state     = .DISCONNECT_LATER
		peer.eventData = data
	} else {
		peer_disconnect(peer, data)
	}
}

peer_queue_acknowledgement :: proc(
	peer: ^Peer,
	command: Protocol,
	sentTime: time.Time,
) -> (acknowledgement: ^Acknowledgement) {
	if command.header.channelID < u8(len(peer.channels)) {
		channel := &peer.channels[command.header.channelID]
		reliableWindow := u16(command.header.reliableSequenceNumber) / PEER_RELIABLE_WINDOW_SIZE
		currentWindow := channel.incomingReliableSequenceNumber / PEER_RELIABLE_WINDOW_SIZE

		if u16(command.header.reliableSequenceNumber) < channel.incomingReliableSequenceNumber {
			reliableWindow += PEER_RELIABLE_WINDOWS
		}

		if reliableWindow >= currentWindow + PEER_FREE_RELIABLE_WINDOWS - 1 && reliableWindow <= currentWindow + PEER_FREE_RELIABLE_WINDOWS {
			return
		}
	}

	acknowledgement = new(Acknowledgement)
	if acknowledgement == nil {
		return
	}

	peer.outgoingDataTotal += size_of(ProtocolAcknowledge)
	acknowledgement.sentTime = sentTime
	acknowledgement.command  = command

	list_insert(list_end(&peer.acknowledgements), acknowledgement)
	return
}

peer_setup_outgoing_command :: proc(peer: ^Peer, outgoingCommand: ^OutgoingCommand) {
	channel := peer.channels[outgoingCommand.command.header.channelID]
	peer.outgoingDataTotal += u32(protocol_command_size(outgoingCommand.command.header.command)) + u32(outgoingCommand.fragmentLength)

	if (outgoingCommand.command.header.channelID == 0xFF) {
		peer.outgoingReliableSequenceNumber += 1
		outgoingCommand.reliableSequenceNumber = peer.outgoingReliableSequenceNumber
		outgoingCommand.unreliableSequenceNumber = 0
	} else if outgoingCommand.command.header.command & PROTOCOL_COMMAND_ACKNOWLEDGE == PROTOCOL_COMMAND_ACKNOWLEDGE {
		channel.outgoingReliableSequenceNumber += 1
		channel.outgoingUnreliableSequenceNumber = 0

		outgoingCommand.reliableSequenceNumber   = channel.outgoingReliableSequenceNumber
		outgoingCommand.unreliableSequenceNumber = 0
	}	else if outgoingCommand.command.header.command & PROTOCOL_COMMAND_SEND_UNSEQUENCED == PROTOCOL_COMMAND_SEND_UNSEQUENCED {
		peer.outgoingUnsequencedGroup += 1

		outgoingCommand.reliableSequenceNumber   = 0
		outgoingCommand.unreliableSequenceNumber = 0
	}	else {
		if (outgoingCommand.fragmentOffset == 0) {
			channel.outgoingUnreliableSequenceNumber += 1
		}

		outgoingCommand.reliableSequenceNumber   = channel.outgoingReliableSequenceNumber
		outgoingCommand.unreliableSequenceNumber = channel.outgoingUnreliableSequenceNumber
	}

	outgoingCommand.sendAttempts          = 0
	outgoingCommand.sentTime              = {}
	outgoingCommand.roundTripTimeout      = 0
	outgoingCommand.roundTripTimeoutLimit = 0
	outgoingCommand.command.header.reliableSequenceNumber = u16be(outgoingCommand.reliableSequenceNumber)

	temp := outgoingCommand.command.header.command & PROTOCOL_COMMAND_MASK

	if temp == PROTOCOL_COMMAND_SEND_UNRELIABLE {
		outgoingCommand.command.sendUnreliable.unreliableSequenceNumber = u16be(outgoingCommand.unreliableSequenceNumber)
	} else if temp == PROTOCOL_COMMAND_SEND_UNSEQUENCED {
		outgoingCommand.command.sendUnsequenced.unsequencedGroup = u16be(peer.outgoingUnsequencedGroup)
	}

	if outgoingCommand.command.header.command & PROTOCOL_COMMAND_ACKNOWLEDGE == PROTOCOL_COMMAND_ACKNOWLEDGE {
		list_insert(list_end(&peer.outgoingReliableCommands), outgoingCommand)
	} else {
		list_insert(list_end(&peer.outgoingUnreliableCommands), outgoingCommand)
	}
}

peer_queue_outgoing_command :: proc(
	peer: ^Peer,
	command: Protocol,
	packet: ^Packet,
	offset: u32,
	length: u16,
) -> ^OutgoingCommand {
	outgoingCommand := new(OutgoingCommand)
	outgoingCommand.command = command
	outgoingCommand.fragmentOffset = offset
	outgoingCommand.fragmentLength = length
	outgoingCommand.packet = packet

	if packet != nil {
		packet.referenceCount += 1
	}

	peer_setup_outgoing_command(peer, outgoingCommand)
	return outgoingCommand
}

peer_dispatch_incoming_unreliable_commands :: proc(peer: ^Peer, channel: ^Channel) {
	droppedCommand := list_begin(&channel.incomingUnreliableCommands)
	startCommand := list_begin(&channel.incomingUnreliableCommands)
	currentCommand := list_begin(&channel.incomingUnreliableCommands)

	for ; currentCommand != list_end(&channel.incomingUnreliableCommands); currentCommand = list_next(currentCommand) {
		incomingCommand := cast(^IncomingCommand) currentCommand

		if (incomingCommand.command.header.command & PROTOCOL_COMMAND_MASK) == PROTOCOL_COMMAND_SEND_UNSEQUENCED {
			continue
		}

		if incomingCommand.reliableSequenceNumber == channel.incomingReliableSequenceNumber {
			if incomingCommand.fragmentsRemaining <= 0 {
				channel.incomingUnreliableSequenceNumber = incomingCommand.unreliableSequenceNumber
				continue
			}

			if startCommand != currentCommand {
				list_move(list_end(&peer.dispatchedCommands), startCommand, list_previous(currentCommand))

				if !peer.needsDispatch {
					list_insert(list_end(&peer.host.dispatchQueue), &peer.dispatchList)
					peer.needsDispatch = true
				}

				droppedCommand = currentCommand
			} else if (droppedCommand != currentCommand) {
				droppedCommand = list_previous(currentCommand)
			}
		} else {
			reliableWindow := incomingCommand.reliableSequenceNumber / PEER_RELIABLE_WINDOW_SIZE
			currentWindow  := channel.incomingReliableSequenceNumber / PEER_RELIABLE_WINDOW_SIZE

			if (incomingCommand.reliableSequenceNumber < channel.incomingReliableSequenceNumber) {
				reliableWindow += PEER_RELIABLE_WINDOWS
			}

			if (reliableWindow >= currentWindow && reliableWindow < currentWindow + PEER_FREE_RELIABLE_WINDOWS - 1) {
				break
			}

			droppedCommand = list_next(currentCommand)

			if startCommand != currentCommand {
				list_move(list_end(&peer.dispatchedCommands), startCommand, list_previous(currentCommand))

				if !peer.needsDispatch {
					list_insert(list_end(&peer.host.dispatchQueue), &peer.dispatchList)
					peer.needsDispatch = true
				}
			}
		}

		startCommand = list_next(currentCommand)
	}

	if startCommand != currentCommand {
		list_move(list_end(&peer.dispatchedCommands), startCommand, list_previous(currentCommand))

		if !peer.needsDispatch {
			list_insert(list_end(&peer.host.dispatchQueue), &peer.dispatchList)
			peer.needsDispatch = true
		}

		droppedCommand = currentCommand
	}

	peer_remove_incoming_commands(list_begin(&channel.incomingUnreliableCommands), droppedCommand)
}

peer_dispatch_incoming_reliable_commands :: proc(peer: ^Peer, channel: ^Channel) {
	currentCommand: ListIterator

	for currentCommand = list_begin(&channel.incomingReliableCommands);
		currentCommand != list_end(&channel.incomingReliableCommands);
		currentCommand = list_next(currentCommand) {
		incomingCommand := cast(^IncomingCommand) currentCommand

		if incomingCommand.fragmentsRemaining > 0 || incomingCommand.reliableSequenceNumber != (channel.incomingReliableSequenceNumber + 1) {
			break
		}

		channel.incomingReliableSequenceNumber = incomingCommand.reliableSequenceNumber

		if incomingCommand.fragmentCount > 0 {
			channel.incomingReliableSequenceNumber += u16(incomingCommand.fragmentCount - 1)
		}
	}

	if currentCommand == list_begin(&channel.incomingReliableCommands) {
		return
	}

	channel.incomingUnreliableSequenceNumber = 0
	list_move(list_end(&peer.dispatchedCommands), list_begin(&channel.incomingReliableCommands), list_previous(currentCommand))

	if !peer.needsDispatch {
		list_insert(list_end(&peer.host.dispatchQueue), &peer.dispatchList)
		peer.needsDispatch = true
	}

	if !list_empty(&channel.incomingUnreliableCommands) {
		peer_dispatch_incoming_unreliable_commands(peer, channel)
	}
}

peer_queue_incoming_command :: proc(
	peer: ^Peer,
	command: Protocol,
	data: []byte,
	flags: u32,
	fragmentCount: u32,
) -> ^IncomingCommand {
	dummyCommand: IncomingCommand
	channel := &peer.channels[command.header.channelID]
	unreliableSequenceNumber: u32
	reliableSequenceNumber: u32
	reliableWindow: u16
	currentWindow: u16
	incomingCommand: ^IncomingCommand
	currentCommand: ListIterator

	if peer.state == .DISCONNECT_LATER {
		// goto discardCommand
		// TODO goto
	}

	if (command.header.command & PROTOCOL_COMMAND_MASK) != PROTOCOL_COMMAND_SEND_UNSEQUENCED {
		reliableSequenceNumber = u32(command.header.reliableSequenceNumber)
		reliableWindow = u16(reliableSequenceNumber / PEER_RELIABLE_WINDOW_SIZE)
		currentWindow = channel.incomingReliableSequenceNumber / PEER_RELIABLE_WINDOW_SIZE

		if reliableSequenceNumber < u32(channel.incomingReliableSequenceNumber) {
			reliableWindow += PEER_RELIABLE_WINDOWS
		}

		if reliableWindow < currentWindow || reliableWindow >= currentWindow + PEER_FREE_RELIABLE_WINDOWS - 1 {
			// TODO goto
			// goto discardCommand
		}
	}

	switch command.header.command & PROTOCOL_COMMAND_MASK {
		case PROTOCOL_COMMAND_SEND_RELIABLE, PROTOCOL_COMMAND_SEND_FRAGMENT:
			if reliableSequenceNumber == u32(channel.incomingReliableSequenceNumber) {
				// TODO goto
				// goto discardCommand
			}

			for currentCommand = list_previous(list_end(&channel.incomingReliableCommands));
				currentCommand != list_end(&channel.incomingReliableCommands);
				currentCommand = list_previous(currentCommand)
			{
				incomingCommand = cast(^IncomingCommand) currentCommand

				if reliableSequenceNumber >= u32(channel.incomingReliableSequenceNumber) {
					if incomingCommand.reliableSequenceNumber < channel.incomingReliableSequenceNumber {
						continue
					}
				} else if incomingCommand.reliableSequenceNumber >= channel.incomingReliableSequenceNumber {
					break
				}

				if u32(incomingCommand.reliableSequenceNumber) <= reliableSequenceNumber {
					if u32(incomingCommand.reliableSequenceNumber) < reliableSequenceNumber {
						break
					}

					// goto discardCommand
				}
			}

		case PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT, PROTOCOL_COMMAND_SEND_UNRELIABLE:
			unreliableSequenceNumber = u32(command.sendUnreliable.unreliableSequenceNumber)

			if reliableSequenceNumber == u32(channel.incomingReliableSequenceNumber) && unreliableSequenceNumber <= u32(channel.incomingUnreliableSequenceNumber) {
				// goto discardCommand
			}

			for currentCommand = list_previous(list_end(&channel.incomingUnreliableCommands));
				currentCommand != list_end(&channel.incomingUnreliableCommands);
				currentCommand = list_previous(currentCommand)
			{
				incomingCommand = cast(^IncomingCommand) currentCommand

				if (command.header.command & PROTOCOL_COMMAND_MASK) == PROTOCOL_COMMAND_SEND_UNSEQUENCED {
					continue
				}

				if reliableSequenceNumber >= u32(channel.incomingReliableSequenceNumber) {
					if incomingCommand.reliableSequenceNumber < channel.incomingReliableSequenceNumber {
						continue
					}
				} else if incomingCommand.reliableSequenceNumber >= channel.incomingReliableSequenceNumber {
					break
				}

				if u32(incomingCommand.reliableSequenceNumber) < reliableSequenceNumber {
					break
				}

				if u32(incomingCommand.reliableSequenceNumber) > reliableSequenceNumber {
					continue
				}

				if u32(incomingCommand.unreliableSequenceNumber) <= unreliableSequenceNumber {
					if u32(incomingCommand.unreliableSequenceNumber) < unreliableSequenceNumber {
						break
					}

					// goto discardCommand
				}
			}

		case PROTOCOL_COMMAND_SEND_UNSEQUENCED:
			currentCommand = list_end(&channel.incomingUnreliableCommands);

		case:
			// goto discardCommand;
	}

	if peer.totalWaitingData >= peer.host.maximumWaitingData {
		// goto notifyError;
	}

	// TODO callbacks
	packet := packet_create(data, flags)
	incomingCommand = new(IncomingCommand)
	incomingCommand.reliableSequenceNumber     = u16(command.header.reliableSequenceNumber)
	incomingCommand.unreliableSequenceNumber   = u16(unreliableSequenceNumber & 0xFFFF)
	incomingCommand.command                    = command
	incomingCommand.fragmentCount              = fragmentCount
	incomingCommand.fragmentsRemaining         = fragmentCount
	incomingCommand.packet                     = packet
	incomingCommand.fragments                  = nil

	if fragmentCount > 0 {
		count := (fragmentCount + 31) / 32
		
		if fragmentCount <= PROTOCOL_MAXIMUM_FRAGMENT_COUNT {
			incomingCommand.fragments = cast(^u32) mem.alloc(int(count) * size_of(u32))
		}

		// NOTE ?
		// memset(incomingCommand.fragments, 0, (fragmentCount + 31) / 32 * sizeof(u32));
	}

	packet.referenceCount += 1
	peer.totalWaitingData += packet.dataLength
	list_insert(list_next(currentCommand), incomingCommand)

	switch command.header.command & PROTOCOL_COMMAND_MASK {
		case PROTOCOL_COMMAND_SEND_FRAGMENT, PROTOCOL_COMMAND_SEND_RELIABLE:
			peer_dispatch_incoming_reliable_commands(peer, channel)

		case:
			peer_dispatch_incoming_unreliable_commands(peer, channel)
	}

	return incomingCommand

// discardCommand:
// 	if (fragmentCount > 0) {
// 		goto notifyError;
// 	}

// 	if (packet != NULL  && packet.referenceCount == 0) {
// 		callbacks.packet_destroy(packet);
// 	}

// 	return &dummyCommand;

// notifyError:
// 	if (packet != NULL && packet.referenceCount == 0) {
// 		callbacks.packet_destroy(packet);
// 	}

// 	return NULL;
}