package enet

import "core:fmt"
import "core:net"
import "core:mem"
import "core:time"

protocol_command_size :: proc(command: u8) -> int {
	return commandSizes[command & PROTOCOL_COMMAND_MASK]
}

protocol_change_state :: proc(peer: ^Peer, state: PeerState) {
	if state == .CONNECTED || state == .DISCONNECT_LATER {
		peer_on_connect(peer)
	} else {
		peer_on_disconnect(peer)
	}

	peer.state = state
}

protocol_dispatch_state :: proc(host: ^Host, peer: ^Peer, state: PeerState) {
	protocol_change_state(peer, state)

	if !peer.needsDispatch {
		list_insert(list_end(&host.dispatchQueue), &peer.dispatchList)
		peer.needsDispatch = true
	}
}

protocol_dispatch_incoming_commands :: proc(host: ^Host, event: ^Event) -> bool {
	for !list_empty(&host.dispatchQueue) {
		peer := cast(^Peer) list_remove(list_begin(&host.dispatchQueue))
		peer.needsDispatch = false

		#partial switch peer.state {
			case .CONNECTION_PENDING, .CONNECTION_SUCCEEDED:
				protocol_change_state(peer, .CONNECTED)
				event.type = .CONNECT
				event.peer = peer
				event.data = peer.eventData
				return true

			case .ZOMBIE:
				host.recalculateBandwidthLimits = true
				event.type = .DISCONNECT
				event.peer = peer
				event.data = peer.eventData
				peer_reset(peer)

			case .CONNECTED:
				if list_empty(&peer.dispatchedCommands) {
					continue
				}

				event.packet = peer_receive(peer, &event.channelID) 
				if event.packet == nil {
					continue
				}

				event.type = .RECEIVE
				event.peer = peer

				if !list_empty(&peer.dispatchedCommands) {
					peer.needsDispatch = true
					list_insert(list_end(&host.dispatchQueue), &peer.dispatchList)
				}

				return true
		}
	}
	
	return false
}

protocol_notify_connect :: proc(host: ^Host, peer: ^Peer, event: ^Event) {
	host.recalculateBandwidthLimits = true

	if event != nil {
		protocol_change_state(peer, .CONNECTED)

		peer.totalDataSent     = 0
		peer.totalDataReceived = 0
		peer.totalPacketsSent  = 0
		peer.totalPacketsLost  = 0

		event.type = .CONNECT
		event.peer = peer
		event.data = peer.eventData
	} else {
		protocol_dispatch_state(host, peer, peer.state == .CONNECTING ? .CONNECTION_SUCCEEDED : .CONNECTION_PENDING)
	}
}

protocol_notify_disconnect :: proc(host: ^Host, peer: ^Peer, event: ^Event) {
	if peer.state >= .CONNECTION_PENDING {
		host.recalculateBandwidthLimits = true
	}

	if peer.state != .CONNECTING && peer.state < .CONNECTION_SUCCEEDED {
		peer_reset(peer)
	} else if event != nil {
		event.type = .DISCONNECT
		event.peer = peer
		event.data = 0
		peer_reset(peer)
	} else {
		peer.eventData = 0
		protocol_dispatch_state(host, peer, .ZOMBIE)
	}
}

protocol_notify_disconnect_timeout :: proc(host: ^Host, peer: ^Peer, event: ^Event) {
	if peer.state >= .CONNECTION_PENDING {
		host.recalculateBandwidthLimits = true
	}

	if peer.state != .CONNECTING && peer.state < .CONNECTION_SUCCEEDED {
		peer_reset(peer)
	}	else if event != nil {
		event.type = .DISCONNECT_TIMEOUT
		event.peer = peer
		event.data = 0
		peer_reset(peer)
	}	else {
		peer.eventData = 0
		protocol_dispatch_state(host, peer, .ZOMBIE)
	}
}

protocol_remove_sent_unreliable_commands :: proc(peer: ^Peer) {
	for !list_empty(&peer.sentUnreliableCommands) {
		outgoingCommand := cast(^OutgoingCommand) list_front(&peer.sentUnreliableCommands)
		list_remove(&outgoingCommand.outgoingCommandList)

		if outgoingCommand.packet != nil {
			outgoingCommand.packet.referenceCount -= 1

			if outgoingCommand.packet.referenceCount == 0 {
				outgoingCommand.packet.flags |= PACKET_FLAG_SENT
				// TODO callbacks?
				packet_destroy(outgoingCommand.packet)
			}
		}

		free(outgoingCommand)
	}
}

protocol_remove_sent_reliable_command :: proc(peer: ^Peer, reliableSequenceNumber: u16, channelID: u8) -> u8 {
	outgoingCommand: ^OutgoingCommand
	currentCommand: ListIterator
	commandNumber: u8
	wasSent := true

	for currentCommand = list_begin(&peer.sentReliableCommands);
		currentCommand != list_end(&peer.sentReliableCommands);
		currentCommand = list_next(currentCommand)
	{
		outgoingCommand = cast(^OutgoingCommand) currentCommand

		if outgoingCommand.reliableSequenceNumber == reliableSequenceNumber && outgoingCommand.command.header.channelID == channelID {
			break
		}
	}

	if currentCommand == list_end(&peer.sentReliableCommands) {
		for currentCommand = list_begin(&peer.outgoingReliableCommands);
			currentCommand != list_end(&peer.outgoingReliableCommands);
			currentCommand = list_next(currentCommand)
		{
			outgoingCommand = cast(^OutgoingCommand) currentCommand

			if outgoingCommand.sendAttempts < 1 { 
				return PROTOCOL_COMMAND_NONE
			}
			
			if outgoingCommand.reliableSequenceNumber == reliableSequenceNumber && outgoingCommand.command.header.channelID == channelID {
				break
			}
		}

		if currentCommand == list_end(&peer.outgoingReliableCommands) {
			return PROTOCOL_COMMAND_NONE
		}

		wasSent = false
	}

	if outgoingCommand == nil {
		return PROTOCOL_COMMAND_NONE
	}

	if channelID < u8(len(peer.channels)) {
		channel := &peer.channels[channelID]
		reliableWindow := reliableSequenceNumber / PEER_RELIABLE_WINDOW_SIZE
		
		if (channel.reliableWindows[reliableWindow] > 0) {
			channel.reliableWindows[reliableWindow] -= 1
			
			if channel.reliableWindows[reliableWindow] == 0 {
				channel.usedReliableWindows &= ~(1 << reliableWindow)
			}
		}
	}

	commandNumber = outgoingCommand.command.header.command & PROTOCOL_COMMAND_MASK
	list_remove(&outgoingCommand.outgoingCommandList)

	if outgoingCommand.packet != nil {
		if wasSent {
			peer.reliableDataInTransit -= u32(outgoingCommand.fragmentLength)
		}

		outgoingCommand.packet.referenceCount -= 1

		if outgoingCommand.packet.referenceCount == 0 {
			outgoingCommand.packet.flags |= PACKET_FLAG_SENT
			// TODO callbacks
			packet_destroy(outgoingCommand.packet)
		}
	}

	free(outgoingCommand)

	if list_empty(&peer.sentReliableCommands) {
		return commandNumber
	}

	outgoingCommand = cast(^OutgoingCommand) list_front(&peer.sentReliableCommands)
	peer.nextTimeout = time.time_add(outgoingCommand.sentTime, outgoingCommand.roundTripTimeout)

	return commandNumber
}

protocol_handle_connect :: proc(host: ^Host, header: ^ProtocolHeader, command: Protocol) -> ^Peer {
	duplicatePeers: int
	peer: ^Peer
	channelCount := int(command.connect.channelCount)

	if channelCount < PROTOCOL_MINIMUM_CHANNEL_COUNT || channelCount > PROTOCOL_MAXIMUM_CHANNEL_COUNT {
		return nil
	}

	for currentPeer in &host.peers {
		if currentPeer.state == .DISCONNECTED {
			if peer == nil {
				peer = &currentPeer
			}
		} else if currentPeer.state != .CONNECTING && currentPeer.endpoint.address == host.receivedEndpoint.address {
			if currentPeer.endpoint.port == host.receivedEndpoint.port && currentPeer.connectID == u32(command.connect.connectID) {
				return nil
			}

			duplicatePeers += 1
		}
	}

	if peer == nil || duplicatePeers >= host.duplicatePeers {
		return nil
	}

	if channelCount > host.channelLimit {
		channelCount = host.channelLimit
	}

	peer.channels = make([]Channel, channelCount)
	if peer.channels == nil {
		return nil
	}
	peer.state                      = .ACKNOWLEDGING_CONNECT
	peer.connectID                  = u32(command.connect.connectID)
	peer.endpoint                   = host.receivedEndpoint
	peer.outgoingPeerID             = u16(command.connect.outgoingPeerID)
	peer.incomingBandwidth          = u32(command.connect.incomingBandwidth)
	peer.outgoingBandwidth          = u32(command.connect.outgoingBandwidth)
	peer.packetThrottleInterval     = time.Duration(command.connect.packetThrottleInterval)
	peer.packetThrottleAcceleration = time.Duration(command.connect.packetThrottleAcceleration)
	peer.packetThrottleDeceleration = time.Duration(command.connect.packetThrottleDeceleration)
	peer.eventData                  = u32(command.connect.data)

	incomingSessionID := command.connect.incomingSessionID == 0xFF ? peer.outgoingSessionID : command.connect.incomingSessionID
	incomingSessionID = (incomingSessionID + 1) & (PROTOCOL_HEADER_SESSION_MASK >> PROTOCOL_HEADER_SESSION_SHIFT)
	if incomingSessionID == peer.outgoingSessionID {
		incomingSessionID = (incomingSessionID + 1) & (PROTOCOL_HEADER_SESSION_MASK >> PROTOCOL_HEADER_SESSION_SHIFT)
	}
	peer.outgoingSessionID = incomingSessionID

	outgoingSessionID := command.connect.outgoingSessionID == 0xFF ? peer.incomingSessionID : command.connect.outgoingSessionID
	outgoingSessionID = (outgoingSessionID + 1) & (PROTOCOL_HEADER_SESSION_MASK >> PROTOCOL_HEADER_SESSION_SHIFT)
	if outgoingSessionID == peer.incomingSessionID {
		outgoingSessionID = (outgoingSessionID + 1) & (PROTOCOL_HEADER_SESSION_MASK >> PROTOCOL_HEADER_SESSION_SHIFT)
	}
	peer.incomingSessionID = outgoingSessionID

	for channel in &peer.channels {
		list_clear(&channel.incomingReliableCommands)
		list_clear(&channel.incomingUnreliableCommands)
	}
	
	mtu := u32(command.connect.mtu)

	if mtu < PROTOCOL_MINIMUM_MTU {
		mtu = PROTOCOL_MINIMUM_MTU
	} else if mtu > PROTOCOL_MAXIMUM_MTU {
		mtu = PROTOCOL_MAXIMUM_MTU
	}

	peer.mtu = mtu

	if host.outgoingBandwidth == 0 && peer.incomingBandwidth == 0 {
		peer.windowSize = PROTOCOL_MAXIMUM_WINDOW_SIZE
	} else if (host.outgoingBandwidth == 0 || peer.incomingBandwidth == 0) {
		peer.windowSize = (max(host.outgoingBandwidth, peer.incomingBandwidth) / PEER_WINDOW_SIZE_SCALE) * PROTOCOL_MINIMUM_WINDOW_SIZE
	} else {
		peer.windowSize = (min(host.outgoingBandwidth, peer.incomingBandwidth) / PEER_WINDOW_SIZE_SCALE) * PROTOCOL_MINIMUM_WINDOW_SIZE
	}

	if (peer.windowSize < PROTOCOL_MINIMUM_WINDOW_SIZE) {
		peer.windowSize = PROTOCOL_MINIMUM_WINDOW_SIZE
	} else if (peer.windowSize > PROTOCOL_MAXIMUM_WINDOW_SIZE) {
		peer.windowSize = PROTOCOL_MAXIMUM_WINDOW_SIZE
	}

	windowSize: u32
	if (host.incomingBandwidth == 0) {
		windowSize = PROTOCOL_MAXIMUM_WINDOW_SIZE
	} else {
		windowSize = (host.incomingBandwidth / PEER_WINDOW_SIZE_SCALE) * PROTOCOL_MINIMUM_WINDOW_SIZE
	}

	if windowSize > u32(command.connect.windowSize) {
		windowSize = u32(command.connect.windowSize)
	}

	if (windowSize < PROTOCOL_MINIMUM_WINDOW_SIZE) {
		windowSize = PROTOCOL_MINIMUM_WINDOW_SIZE
	} else if (windowSize > PROTOCOL_MAXIMUM_WINDOW_SIZE) {
		windowSize = PROTOCOL_MAXIMUM_WINDOW_SIZE
	}

	verifyCommand: Protocol
	// TODO verify this
	verifyCommand.header.command                            = PROTOCOL_COMMAND_VERIFY_CONNECT | PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE
	verifyCommand.header.channelID                          = 0xFF
	verifyCommand.verifyConnect.outgoingPeerID              = u16be(peer.incomingPeerID)
	verifyCommand.verifyConnect.incomingSessionID           = incomingSessionID
	verifyCommand.verifyConnect.outgoingSessionID           = outgoingSessionID
	verifyCommand.verifyConnect.mtu                         = u32be(peer.mtu)
	verifyCommand.verifyConnect.windowSize                  = u32be(windowSize)
	verifyCommand.verifyConnect.channelCount                = u32be(channelCount)
	verifyCommand.verifyConnect.incomingBandwidth           = u32be(host.incomingBandwidth)
	verifyCommand.verifyConnect.outgoingBandwidth           = u32be(host.outgoingBandwidth)
	verifyCommand.verifyConnect.packetThrottleInterval      = u32be(peer.packetThrottleInterval)
	verifyCommand.verifyConnect.packetThrottleAcceleration  = u32be(peer.packetThrottleAcceleration)
	verifyCommand.verifyConnect.packetThrottleDeceleration  = u32be(peer.packetThrottleDeceleration)
	verifyCommand.verifyConnect.connectID                   = u32be(peer.connectID)

	peer_queue_outgoing_command(peer, verifyCommand, nil, 0, 0)
	return peer
}

protocol_handle_send_reliable :: proc(host: ^Host, peer: ^Peer, command: ^Protocol, currentData: ^[]byte) -> bool {
	if command.header.channelID >= u8(len(peer.channels)) || (peer.state != .CONNECTED && peer.state != .DISCONNECT_LATER) {
		return true
	}

	dataLength := int(command.sendReliable.dataLength)
	currentData^ = currentData[dataLength:]

	if dataLength > host.maximumPacketSize || len(currentData) <= 0 {
		return true
	}

	bytes := mem.ptr_to_bytes(command)
	if peer_queue_incoming_command(
		peer, 
		command^, 
		// TODO check over this again
		bytes[size_of(ProtocolSendReliable):dataLength], 
		PACKET_FLAG_RELIABLE, 
		0) == nil {
		return true
	}

	return false
}

protocol_handle_send_unsequenced :: proc(host: ^Host, peer: ^Peer, command: ^Protocol, currentData: ^[]byte) -> bool {
	if command.header.channelID >= u8(len(peer.channels)) || (peer.state != .CONNECTED && peer.state != .DISCONNECT_LATER) {
		return true
	}

	dataLength := u16(command.sendUnsequenced.dataLength)
	currentData^ = currentData[dataLength:]
	if int(dataLength) > host.maximumPacketSize || len(currentData) <= 0 {
		return true
	}

	unsequencedGroup := u32(command.sendUnsequenced.unsequencedGroup)
	index := unsequencedGroup % PEER_UNSEQUENCED_WINDOW_SIZE

	if unsequencedGroup < u32(peer.incomingUnsequencedGroup) {
		unsequencedGroup += 0x10000
	}

	if unsequencedGroup >= u32(peer.incomingUnsequencedGroup + PEER_FREE_UNSEQUENCED_WINDOWS * PEER_UNSEQUENCED_WINDOW_SIZE) {
		return false
	}

	unsequencedGroup &= 0xFFFF

	if unsequencedGroup - index != u32(peer.incomingUnsequencedGroup) {
		peer.incomingUnsequencedGroup = u16(unsequencedGroup - index)
		peer.unsequencedWindow = {}
	} else {
		wanted := u32(1 << (index % 32))
		
		if peer.unsequencedWindow[index / 32] & wanted == wanted {
			return false
		}
	}

	bytes := mem.ptr_to_bytes(command)
	if peer_queue_incoming_command(
		peer, 
		command^, 
		bytes[size_of(ProtocolSendUnsequenced):dataLength],
		PACKET_FLAG_UNSEQUENCED,
		0,
	) == nil {
		return true
	}

	peer.unsequencedWindow[index / 32] |= 1 << (index % 32)
	return false
}

protocol_handle_send_unreliable :: proc(host: ^Host, peer: ^Peer, command: ^Protocol, currentData: ^[]byte) -> bool {
	if command.header.channelID >= u8(len(peer.channels)) || (peer.state != .CONNECTED && peer.state != .DISCONNECT_LATER) {
		return true
	}

	dataLength := int(command.sendReliable.dataLength)
	currentData^ = currentData[dataLength:]

	if dataLength > host.maximumPacketSize || len(currentData) <= 0 {
		return true
	}

	bytes := mem.ptr_to_bytes(command)
	if peer_queue_incoming_command(
		peer, 
		command^, 
		// TODO check over this again
		bytes[size_of(ProtocolSendUnreliable):dataLength], 
		PACKET_FLAG_RELIABLE, 
		0) == nil {
		return true
	}

	return false
}

protocol_handle_ping :: proc(host: ^Host, peer: ^Peer, command: Protocol) -> bool {
	if peer.state != .CONNECTED && peer.state != .DISCONNECT_LATER {
		return true
	}

	return false
}

protocol_handle_bandwidth_limit :: proc(host: ^Host, peer: ^Peer, command: Protocol) -> bool {
	if peer.state != .CONNECTED && peer.state != .DISCONNECT_LATER {
		return true
	}

	if peer.incomingBandwidth != 0 {
		host.bandwidthLimitedPeers -= 1
	}

	peer.incomingBandwidth = u32(command.bandwidthLimit.incomingBandwidth)
	if peer.incomingBandwidth != 0 {
		host.bandwidthLimitedPeers += 1
	}

	peer.outgoingBandwidth = u32(command.bandwidthLimit.outgoingBandwidth)

	if peer.incomingBandwidth == 0 && host.outgoingBandwidth == 0 {
		peer.windowSize = PROTOCOL_MAXIMUM_WINDOW_SIZE
	} else if peer.incomingBandwidth == 0 || host.outgoingBandwidth == 0 {
		peer.windowSize = (max(peer.incomingBandwidth, host.outgoingBandwidth) / PEER_WINDOW_SIZE_SCALE) * PROTOCOL_MINIMUM_WINDOW_SIZE
	} else {
		peer.windowSize = (min(peer.incomingBandwidth, host.outgoingBandwidth) / PEER_WINDOW_SIZE_SCALE) * PROTOCOL_MINIMUM_WINDOW_SIZE
	}

	if peer.windowSize < PROTOCOL_MINIMUM_WINDOW_SIZE {
		peer.windowSize = PROTOCOL_MINIMUM_WINDOW_SIZE
	} else if (peer.windowSize > PROTOCOL_MAXIMUM_WINDOW_SIZE) {
		peer.windowSize = PROTOCOL_MAXIMUM_WINDOW_SIZE
	}

	return false
}

protocol_handle_throttle_configure :: proc(host: ^Host, peer: ^Peer, command: Protocol) -> bool {
	if peer.state != .CONNECTED && peer.state != .DISCONNECT_LATER {
		return true
	}

	peer.packetThrottleInterval     = time.Duration(command.throttleConfigure.packetThrottleInterval)
	peer.packetThrottleAcceleration = time.Duration(command.throttleConfigure.packetThrottleAcceleration)
	peer.packetThrottleDeceleration = time.Duration(command.throttleConfigure.packetThrottleDeceleration)

	return false
}

protocol_handle_disconnect :: proc(host: ^Host, peer: ^Peer, command: Protocol) {
	if peer.state == .DISCONNECTED || peer.state == .ZOMBIE || peer.state == .ACKNOWLEDGING_DISCONNECT {
		return
	}

	peer_reset_queues(peer)

	if peer.state == .CONNECTION_SUCCEEDED || peer.state == .DISCONNECTING || peer.state == .CONNECTING {
		protocol_dispatch_state(host, peer, .ZOMBIE)
	} else if (peer.state != .CONNECTED && peer.state != .DISCONNECT_LATER) {
		if peer.state == .CONNECTION_PENDING { 
			host.recalculateBandwidthLimits = true
		}
		peer_reset(peer)
	} else if command.header.command & PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE == PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE {
		protocol_change_state(peer, .ACKNOWLEDGING_DISCONNECT)
	}	else {
		protocol_dispatch_state(host, peer, .ZOMBIE)
	}

	if peer.state != .DISCONNECTED {
		peer.eventData = u32(command.disconnect.data)
	}
}

protocol_handle_acknowledge :: proc(host: ^Host, event: ^Event, peer: ^Peer, command: Protocol) -> bool {
	if peer.state == .DISCONNECTED || peer.state == .ZOMBIE {
		return false
	}

	// TODO lookover timing code again
	// receivedSentTime := u32(command.acknowledge.receivedSentTime)
	// receivedSentTime |= host.serviceTime & 0xFFFF0000
	// if (receivedSentTime & 0x8000) > (host.serviceTime & 0x8000) {
	// 	receivedSentTime -= 0x10000;
	// }

	receivedSentTime := time.Time { i64(command.acknowledge.receivedSentTime) }
	if host.serviceTime._nsec < receivedSentTime._nsec {
		return false
	}

	peer.lastReceiveTime = host.serviceTime
	peer.earliestTimeout = {}
	roundTripTime := time.diff(host.serviceTime, receivedSentTime)

	peer_throttle(peer, roundTripTime) 
	peer.roundTripTimeVariance -= peer.roundTripTimeVariance / 4

	if roundTripTime >= peer.roundTripTime {
		peer.roundTripTime         += (roundTripTime - peer.roundTripTime) / 8
		peer.roundTripTimeVariance += (roundTripTime - peer.roundTripTime) / 4
	} else {
		peer.roundTripTime         -= (peer.roundTripTime - roundTripTime) / 8
		peer.roundTripTimeVariance += (peer.roundTripTime - roundTripTime) / 4
	}

	if peer.roundTripTime < peer.lowestRoundTripTime {
		peer.lowestRoundTripTime = peer.roundTripTime
	}

	if peer.roundTripTimeVariance > peer.highestRoundTripTimeVariance {
		peer.highestRoundTripTimeVariance = peer.roundTripTimeVariance
	}

	if peer.packetThrottleEpoch == {} || time.diff(host.serviceTime, peer.packetThrottleEpoch) >= peer.packetThrottleInterval {
		peer.lastRoundTripTime            = peer.lowestRoundTripTime
		peer.lastRoundTripTimeVariance    = peer.highestRoundTripTimeVariance
		peer.lowestRoundTripTime          = peer.roundTripTime
		peer.highestRoundTripTimeVariance = peer.roundTripTimeVariance
		peer.packetThrottleEpoch          = host.serviceTime
	}

	receivedReliableSequenceNumber := u16(command.acknowledge.receivedReliableSequenceNumber)
	commandNumber := protocol_remove_sent_reliable_command(peer, receivedReliableSequenceNumber, command.header.channelID)

	#partial switch peer.state {
	case .ACKNOWLEDGING_CONNECT:
		if commandNumber != PROTOCOL_COMMAND_VERIFY_CONNECT {
			return true
		}
		protocol_notify_connect(host, peer, event)

	case .DISCONNECTING:
		if commandNumber != PROTOCOL_COMMAND_DISCONNECT {
			return true
		}
		protocol_notify_disconnect(host, peer, event)

	case .DISCONNECT_LATER:
		if list_empty(&peer.outgoingReliableCommands) &&
		  list_empty(&peer.outgoingUnreliableCommands) &&
		  list_empty(&peer.sentReliableCommands) {
			peer_disconnect(peer, peer.eventData)
		}
	}

	return false
}

protocol_handle_verify_connect :: proc(host: ^Host, event: ^Event, peer: ^Peer, command: Protocol) -> bool {
	if peer.state != .CONNECTING {
		return false
	}

	channelCount := u32(command.verifyConnect.channelCount)

	if channelCount < PROTOCOL_MINIMUM_CHANNEL_COUNT || channelCount > PROTOCOL_MAXIMUM_CHANNEL_COUNT ||
		time.Duration(command.verifyConnect.packetThrottleInterval) != peer.packetThrottleInterval ||
		time.Duration(command.verifyConnect.packetThrottleAcceleration) != peer.packetThrottleAcceleration ||
		time.Duration(command.verifyConnect.packetThrottleDeceleration) != peer.packetThrottleDeceleration ||
		u32(command.verifyConnect.connectID) != peer.connectID
	{
		peer.eventData = 0
		protocol_dispatch_state(host, peer, .ZOMBIE)
		return true
	}

	protocol_remove_sent_reliable_command(peer, 1, 0xFF)

	// NOTE wtf?
	// if channelCount < peer.channelCount {
	// 	peer.channelCount = channelCount
	// }

	peer.outgoingPeerID    = u16(command.verifyConnect.outgoingPeerID)
	peer.incomingSessionID = command.verifyConnect.incomingSessionID
	peer.outgoingSessionID = command.verifyConnect.outgoingSessionID

	mtu := u32(command.verifyConnect.mtu)

	if mtu < PROTOCOL_MINIMUM_MTU {
		mtu = PROTOCOL_MINIMUM_MTU
	} else if mtu > PROTOCOL_MAXIMUM_MTU {
		mtu = PROTOCOL_MAXIMUM_MTU
	}

	if (mtu < peer.mtu) {
		peer.mtu = mtu
	}

	windowSize := u32(command.verifyConnect.windowSize)
	if windowSize < PROTOCOL_MINIMUM_WINDOW_SIZE {
		windowSize = PROTOCOL_MINIMUM_WINDOW_SIZE
	}

	if windowSize > PROTOCOL_MAXIMUM_WINDOW_SIZE {
		windowSize = PROTOCOL_MAXIMUM_WINDOW_SIZE
	}

	if windowSize < peer.windowSize {
		peer.windowSize = windowSize
	}

	peer.incomingBandwidth = u32(command.verifyConnect.incomingBandwidth)
	peer.outgoingBandwidth = u32(command.verifyConnect.outgoingBandwidth)

	protocol_notify_connect(host, peer, event)
	return false
}

protocol_handle_incoming_commands :: proc(host: ^Host, event: ^Event) {
	// ProtocolHeader *header;
	// Protocol *command;
	// uint8 *currentData;
	// size_t headerSize;
	// uint16 peerID, flags;
	// uint8 sessionID;

	// NOTE FIRST LINE WTF?
	// if len(host.receivedData) < (size_t) &((ProtocolHeader *) 0).sentTime {
	// 	return 0
	// }

	header := cast(^ProtocolHeader) &host.receivedData[0]
	peerID    := u16(header.peerID)
	sessionID := (peerID & PROTOCOL_HEADER_SESSION_MASK) >> PROTOCOL_HEADER_SESSION_SHIFT
	flags     := peerID & PROTOCOL_HEADER_FLAG_MASK
	peerID   &= ~u16(PROTOCOL_HEADER_FLAG_MASK | PROTOCOL_HEADER_SESSION_MASK)

	// TODO stupid offset by time only?
	headerSize := size_of(ProtocolHeader)
	// headerSize = (flags & PROTOCOL_HEADER_FLAG_SENT_TIME ? size_of(ProtocolHeader) : (size_t) &((^ProtocolHeader) 0).sentTime)
	// if (host.checksum != nil) {
	// 	headerSize += size_of(uint32)
	// }

	peer: ^Peer
	if peerID == PROTOCOL_MAXIMUM_PEER_ID {
		peer = nil
	} else if peerID >= u16(len(host.peers)) {
		return
	} else {
		peer = &host.peers[peerID]

		if peer.state == .DISCONNECTED ||
			peer.state == .ZOMBIE ||
			(host.receivedEndpoint.address != peer.endpoint.address ||
			host.receivedEndpoint.port != peer.endpoint.port) ||
			(peer.outgoingPeerID < PROTOCOL_MAXIMUM_PEER_ID &&
			sessionID != u16(peer.incomingSessionID)) {
			return
		}
	}

	if flags & PROTOCOL_HEADER_FLAG_COMPRESSED == PROTOCOL_HEADER_FLAG_COMPRESSED {
		// TODO compressor
		// if host.compressor.context == nil || host.compressor.decompress == nil) {
		// 	return 0
		// }

		// originalSize := host.compressor.decompress(
		// 	host.compressor.context,
		// 	host.receivedData + headerSize,
		// 	host.receivedDataLength - headerSize,
		// 	host.packetData[1] + headerSize,
		// 	size_of(host.packetData[1]) - headerSize
		// )

		// if (originalSize <= 0 || originalSize > size_of(host.packetData[1]) - headerSize) {
		// 	return 0
		// }

		// memcpy(host.packetData[1], header, headerSize)
		// host.receivedData       = host.packetData[1]
		// host.receivedDataLength = headerSize + originalSize
	}

	// // TODO checksum check?
	// if host.checksum != nil {
	// 	// uint32 *checksum = (uint32 *) &host.receivedData[headerSize - size_of(uint32)]
	// 	// uint32 desiredChecksum = *checksum
	// 	// Buffer buffer

	// 	// *checksum = peer != nil ? peer.connectID : 0

	// 	// buffer.data       = host.receivedData
	// 	// buffer.dataLength = host.receivedDataLength

	// 	// if (host.checksum(&buffer, 1) != desiredChecksum) {
	// 	// 	return 0
	// 	// }
	// 	unimplemented("checksum")
	// }

	if peer != nil {
		peer.endpoint.address = host.receivedEndpoint.address
		peer.endpoint.port = host.receivedEndpoint.port
		peer.incomingDataTotal += u32(len(host.receivedData))
		peer.totalDataReceived += u64(len(host.receivedData))
	}

	// iterate received commands
	iter := host.receivedData[headerSize:]
	for len(iter) > 0 {
		command := cast(^Protocol) &iter[0]

		if len(iter) < size_of(ProtocolCommandHeader) {
			break
		}

		commandNumber := command.header.command & PROTOCOL_COMMAND_MASK
		if commandNumber >= PROTOCOL_COMMAND_COUNT {
			break
		}

		commandSize := commandSizes[commandNumber]
		if commandSize == 0 || len(iter) < commandSize {
			break
		}

		iter = iter[commandSize:]

		if peer == nil && commandNumber != PROTOCOL_COMMAND_CONNECT {
			break
		}

		command.header.reliableSequenceNumber = u16be(command.header.reliableSequenceNumber)

		switch commandNumber {
		case PROTOCOL_COMMAND_ACKNOWLEDGE:
			if protocol_handle_acknowledge(host, event, peer, command^) {
				// goto commandError
			}

		case PROTOCOL_COMMAND_CONNECT:
			if peer != nil {
				// goto commandError
			}
			peer = protocol_handle_connect(host, header, command^)
			if peer == nil {
				// goto commandError
			}

		case PROTOCOL_COMMAND_VERIFY_CONNECT:
			if protocol_handle_verify_connect(host, event, peer, command^) {
				// goto commandError
			}

		case PROTOCOL_COMMAND_DISCONNECT:
			protocol_handle_disconnect(host, peer, command^)

		case PROTOCOL_COMMAND_PING:
			if protocol_handle_ping(host, peer, command^) {
				// goto commandError
			}

		case PROTOCOL_COMMAND_SEND_RELIABLE:
			if protocol_handle_send_reliable(host, peer, command, &iter) {
				// goto commandError
			}

		case PROTOCOL_COMMAND_SEND_UNRELIABLE:
			if protocol_handle_send_unreliable(host, peer, command, &iter) {
				// goto commandError
			}

		case PROTOCOL_COMMAND_SEND_UNSEQUENCED:
			if protocol_handle_send_unsequenced(host, peer, command, &iter) {
				// goto commandError
			}

		case PROTOCOL_COMMAND_SEND_FRAGMENT:
			unimplemented("FRAGMENT")
			// if protocol_handle_send_fragment(host, peer, command, &currentData) {
			// 	// goto commandError
			// }

		case PROTOCOL_COMMAND_BANDWIDTH_LIMIT:
			if protocol_handle_bandwidth_limit(host, peer, command^) {
				// goto commandError
			}

		case PROTOCOL_COMMAND_THROTTLE_CONFIGURE:
			if protocol_handle_throttle_configure(host, peer, command^) {
				// goto commandError
			}

		case PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT:
			unimplemented("FRAGMENT UNRELIABLE")
			// if protocol_handle_send_unreliable_fragment(host, peer, command, &currentData) {
			// 	// goto commandError
			// }
		}

		assert(peer != nil)
		if ((command.header.command & PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE) != 0) {
			// uint16 sentTime

			// TODO time only flag?
			// if (!(flags & PROTOCOL_HEADER_FLAG_SENT_TIME)) {
			// 	break
			// }

			sentTime := time.Time { i64(header.sentTime) }

			#partial switch peer.state {
				case .DISCONNECTING, .ACKNOWLEDGING_CONNECT, .DISCONNECTED, .ZOMBIE:
				
				case .ACKNOWLEDGING_DISCONNECT:
					if (command.header.command & PROTOCOL_COMMAND_MASK) == PROTOCOL_COMMAND_DISCONNECT {
						peer_queue_acknowledgement(peer, command^, sentTime)
					}

				case: peer_queue_acknowledgement(peer, command^, sentTime)
			}
		}
	}
}

protocol_receive_incoming_commands :: proc(host: ^Host, event: ^Event) -> bool {
	for packet in 0..<256 {
		data := host.packetData[:host.mtu]
		bytesRead, remoteEndpoint, err := net.recv_udp(host.socket, data)
		
		if err != nil && err != net.UDP_Recv_Error.Would_Block {
			fmt.eprintln("ERR", err)
			return true
		}

		if bytesRead == 0 {
			continue
		}

		host.receivedData = host.packetData[:bytesRead]
		host.totalReceivedData += u32(bytesRead)

		if host.intercept != nil {
			// TODO intercept
		}

		protocol_handle_incoming_commands(host, event)
	}

	return false
}

protocol_handle_throttle_disconnect :: proc(host: ^Host, peer: ^Peer, command: Protocol) {
	if peer.state == .DISCONNECTED || peer.state == .ZOMBIE || peer.state == .ACKNOWLEDGING_DISCONNECT {
		return
	}

	peer_reset_queues(peer)

	if (peer.state == .CONNECTION_SUCCEEDED || peer.state == .DISCONNECTING || peer.state == .CONNECTING) {
		protocol_dispatch_state(host, peer, .ZOMBIE)
	} else if peer.state != .CONNECTED && peer.state != .DISCONNECT_LATER {
		if peer.state == .CONNECTION_PENDING { 
			host.recalculateBandwidthLimits = true
		}
		
		peer_reset(peer)
	} else if u8(command.header.command) & PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE == PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE {
		protocol_change_state(peer, .ACKNOWLEDGING_DISCONNECT)
	}	else {
		protocol_dispatch_state(host, peer, .ZOMBIE)
	}

	if peer.state != .DISCONNECTED {
		peer.eventData = u32(command.disconnect.data)
	}
}

protocol_send_acknowledgements :: proc(host: ^Host, peer: ^Peer) {
	currentAcknowledgement := list_begin(&peer.acknowledgements)
	offset: int

	for currentAcknowledgement != list_end(&peer.acknowledgements) {
		if offset >= BUFFER_MAXIMUM || peer.mtu - u32(host.packetSize) < size_of(ProtocolAcknowledge) {
			host.continueSending = true
			break
		}
	
		buffer_index := host.bufferCount + offset
		command := &host.commands[host.commandCount + offset]

		acknowledgement := cast(^Acknowledgement) currentAcknowledgement
		currentAcknowledgement = list_next(currentAcknowledgement)

		command_bytes := mem.ptr_to_bytes(command)
		host.buffers[buffer_index] = command_bytes[:size_of(ProtocolAcknowledge)]
		host.packetSize += len(host.buffers[buffer_index])

		reliableSequenceNumber := u16be(acknowledgement.command.header.reliableSequenceNumber)

		command.header.command   = PROTOCOL_COMMAND_ACKNOWLEDGE
		command.header.channelID = acknowledgement.command.header.channelID
		command.header.reliableSequenceNumber = reliableSequenceNumber
		command.acknowledge.receivedReliableSequenceNumber = reliableSequenceNumber
		command.acknowledge.receivedSentTime = u32be(acknowledgement.sentTime._nsec)

		if ((acknowledgement.command.header.command & PROTOCOL_COMMAND_MASK) == PROTOCOL_COMMAND_DISCONNECT) {
			protocol_dispatch_state(host, peer, .ZOMBIE)
		}

		list_remove(&acknowledgement.acknowledgementList)
		free(acknowledgement)

		offset += 1
	} 

	host.commandCount = offset
	host.bufferCount = offset
}

protocol_send_unreliable_outgoing_commands :: proc(host: ^Host, peer: ^Peer) {
	buffer_offset: int
	command_offset: int

	currentCommand := list_begin(&peer.outgoingUnreliableCommands)
	for currentCommand != list_end(&peer.outgoingUnreliableCommands) {
		outgoingCommand := cast(^OutgoingCommand) currentCommand
		commandSize := commandSizes[outgoingCommand.command.header.command & PROTOCOL_COMMAND_MASK]

		if buffer_offset >= BUFFER_MAXIMUM || 
			command_offset >= BUFFER_MAXIMUM || 
			peer.mtu - u32(host.packetSize) < u32(commandSize) ||
			(outgoingCommand.packet != nil &&
			peer.mtu - u32(host.packetSize) < u32(commandSize) + u32(outgoingCommand.fragmentLength))
		{
			host.continueSending = true
			break
		}

		currentCommand = list_next(currentCommand)

		if outgoingCommand.packet != nil && outgoingCommand.fragmentOffset == 0 {
			peer.packetThrottleCounter += PEER_PACKET_THROTTLE_COUNTER
			peer.packetThrottleCounter %= PEER_PACKET_THROTTLE_SCALE

			if peer.packetThrottleCounter > peer.packetThrottle {
				reliableSequenceNumber := outgoingCommand.reliableSequenceNumber
				unreliableSequenceNumber := outgoingCommand.unreliableSequenceNumber
				for {
					outgoingCommand.packet.referenceCount -= 1

					if outgoingCommand.packet.referenceCount == 0 {
						// TODO callbacks
						packet_destroy(outgoingCommand.packet)
					}

					list_remove(&outgoingCommand.outgoingCommandList)
					free(outgoingCommand)

					if currentCommand == list_end(&peer.outgoingUnreliableCommands) {
						break
					}

					outgoingCommand = cast(^OutgoingCommand) currentCommand
					if outgoingCommand.reliableSequenceNumber != reliableSequenceNumber || outgoingCommand.unreliableSequenceNumber != unreliableSequenceNumber {
						break
					}

					currentCommand = list_next(currentCommand)
				}

				continue
			}
		}

		command := &host.commands[host.commandCount + command_offset]
		command_bytes := mem.ptr_to_bytes(command)
		host.buffers[host.bufferCount + buffer_offset] = command_bytes[:commandSize]
		host.packetSize += len(host.buffers[host.bufferCount + buffer_offset])
		command^ = outgoingCommand.command
		list_remove(&outgoingCommand.outgoingCommandList)

		if outgoingCommand.packet != nil {
			buffer_offset += 1

			result_offset := uintptr(outgoingCommand.packet.data) + uintptr(outgoingCommand.fragmentOffset)
			result_bytes := mem.byte_slice(rawptr(result_offset), outgoingCommand.fragmentLength)
			host.buffers[host.bufferCount + buffer_offset] = result_bytes
			host.packetSize += len(result_bytes)

			list_insert(list_end(&peer.sentUnreliableCommands), outgoingCommand)
		} else {
			free(outgoingCommand)
		}
	}

	host.commandCount = command_offset
	host.bufferCount  = buffer_offset

	if peer.state == .DISCONNECT_LATER &&
	  list_empty(&peer.outgoingReliableCommands) &&
	  list_empty(&peer.outgoingUnreliableCommands) &&
	  list_empty(&peer.sentReliableCommands) {
		peer_disconnect(peer, peer.eventData)
	}
}

protocol_check_timeouts :: proc(host: ^Host, peer: ^Peer, event: ^Event) -> bool {
	currentCommand := list_begin(&peer.sentReliableCommands)
	insertPosition := list_begin(&peer.outgoingReliableCommands)

	for currentCommand != list_end(&peer.sentReliableCommands) {
		outgoingCommand := cast(^OutgoingCommand) currentCommand
		currentCommand = list_next(currentCommand)

		// TODO double check these
		if time.diff(host.serviceTime, outgoingCommand.sentTime) < outgoingCommand.roundTripTimeout {
			continue
		}

		if peer.earliestTimeout == {} || outgoingCommand.sentTime._nsec < peer.earliestTimeout._nsec {
			peer.earliestTimeout = outgoingCommand.sentTime
		}

		if peer.earliestTimeout != {} &&
			(time.diff(host.serviceTime, peer.earliestTimeout) >= peer.timeoutMaximum ||
			(outgoingCommand.roundTripTimeout >= outgoingCommand.roundTripTimeoutLimit &&
			time.diff(host.serviceTime, peer.earliestTimeout) >= peer.timeoutMinimum))
		{
			protocol_notify_disconnect_timeout(host, peer, event)
			return true
		}

		if outgoingCommand.packet != nil {
			peer.reliableDataInTransit -= u32(outgoingCommand.fragmentLength)
		}

		peer.packetsLost += 1
		peer.totalPacketsLost += 1

		/* Replaced exponential backoff time with something more linear */
		/* Source: http://lists.cubik.org/pipermail/-discuss/2014-May/002308.html */
		outgoingCommand.roundTripTimeout = peer.roundTripTime + 4 * peer.roundTripTimeVariance
		outgoingCommand.roundTripTimeoutLimit = peer.timeoutLimit * outgoingCommand.roundTripTimeout

		list_insert(insertPosition, list_remove(&outgoingCommand.outgoingCommandList))

		if currentCommand == list_begin(&peer.sentReliableCommands) && !list_empty(&peer.sentReliableCommands) {
			outgoingCommand = cast(^OutgoingCommand) currentCommand
			peer.nextTimeout = time.time_add(outgoingCommand.sentTime, outgoingCommand.roundTripTimeout)
		}
	}

	return false
}

protocol_send_reliable_outgoing_commands :: proc(host: ^Host, peer: ^Peer) -> bool {
	buffer_offset: int
	command_offset: int

	windowExceeded: bool
	windowWrap: bool
	canPing := true
	currentCommand := list_begin(&peer.outgoingReliableCommands)

	for currentCommand != list_end(&peer.outgoingReliableCommands) {
		outgoingCommand := cast(^OutgoingCommand) currentCommand
		channel := outgoingCommand.command.header.channelID < u8(len(peer.channels)) ? &peer.channels[outgoingCommand.command.header.channelID] : nil
		reliableWindow := outgoingCommand.reliableSequenceNumber / PEER_RELIABLE_WINDOW_SIZE
		
		if channel != nil {
			// TODO double check these
			window := channel.reliableWindows[(reliableWindow + PEER_RELIABLE_WINDOWS - 1) % PEER_RELIABLE_WINDOWS]
			check := window >= PEER_RELIABLE_WINDOW_SIZE
			rest := channel.usedReliableWindows & ((((1 << PEER_FREE_RELIABLE_WINDOWS) - 1) << reliableWindow) | (((1 << PEER_FREE_RELIABLE_WINDOWS) - 1) >> (PEER_RELIABLE_WINDOWS - reliableWindow)))

			if !windowWrap &&
				outgoingCommand.sendAttempts < 1 &&
				(outgoingCommand.reliableSequenceNumber % PEER_RELIABLE_WINDOW_SIZE == 0) &&
				(check || rest > 0)
			{
				windowWrap = true
			}

			if windowWrap {
				currentCommand = list_next(currentCommand)
				continue
			}
		}

		if outgoingCommand.packet != nil {
			if !windowExceeded {
				windowSize := (u32(peer.packetThrottle) * peer.windowSize) / u32(PEER_PACKET_THROTTLE_SCALE)

				if peer.reliableDataInTransit + u32(outgoingCommand.fragmentLength) > max(windowSize, peer.mtu) {
					windowExceeded = true
				}
			}
			if windowExceeded {
				currentCommand = list_next(currentCommand)
				continue
			}
		}

		canPing = false

		commandSize := commandSizes[outgoingCommand.command.header.command & PROTOCOL_COMMAND_MASK]
		if command_offset >= BUFFER_MAXIMUM ||
			buffer_offset + 1 >= BUFFER_MAXIMUM ||
			peer.mtu - u32(host.packetSize) < u32(commandSize) ||
			(outgoingCommand.packet != nil &&
			(peer.mtu - u32(host.packetSize)) < u32(commandSize + int(outgoingCommand.fragmentLength)))
		{
			host.continueSending = true
			break
		}

		currentCommand = list_next(currentCommand)

		if channel != nil && outgoingCommand.sendAttempts < 1 {
			channel.usedReliableWindows |= 1 << reliableWindow
			channel.reliableWindows[reliableWindow] += 1
		}

		outgoingCommand.sendAttempts += 1

		if outgoingCommand.roundTripTimeout == 0 {
			outgoingCommand.roundTripTimeout      = peer.roundTripTime + 4 * peer.roundTripTimeVariance
			outgoingCommand.roundTripTimeoutLimit = peer.timeoutLimit * outgoingCommand.roundTripTimeout
		}

		if list_empty(&peer.sentReliableCommands) {
			peer.nextTimeout = time.time_add(host.serviceTime, outgoingCommand.roundTripTimeout)
		}

		list_insert(list_end(&peer.sentReliableCommands), list_remove(&outgoingCommand.outgoingCommandList))
		outgoingCommand.sentTime = host.serviceTime

		command := &host.commands[host.commandCount + command_offset]
		command_bytes := mem.ptr_to_bytes(command)
		host.buffers[host.bufferCount + buffer_offset] = command_bytes[:commandSize]
		host.packetSize  += commandSize
		host.headerFlags |= PROTOCOL_HEADER_FLAG_SENT_TIME
		command^ = outgoingCommand.command

		if outgoingCommand.packet != nil {
			buffer_offset += 1
			result_offset := uintptr(outgoingCommand.packet.data) + uintptr(outgoingCommand.fragmentOffset)
			result_bytes := mem.byte_slice(rawptr(result_offset), outgoingCommand.fragmentLength)
			host.buffers[host.bufferCount + buffer_offset] = result_bytes
			host.packetSize += len(result_bytes)
			peer.reliableDataInTransit += u32(outgoingCommand.fragmentLength)
		}

		peer.packetsSent += 1
		peer.totalPacketsSent += 1
	}

	host.commandCount = command_offset
	host.bufferCount  = buffer_offset

	return canPing
}

protocol_send_outgoing_commands :: proc(host: ^Host, event: ^Event, checkForTimeouts: bool) -> bool {
	headerData: [size_of(ProtocolHeader) + size_of(u32)]byte
	header := cast(^ProtocolHeader) &headerData[0]
	shouldCompress: int
	host.continueSending = true

	for host.continueSending {
		host.continueSending = false
		for currentPeer in &host.peers {
			if currentPeer.state == .DISCONNECTED || currentPeer.state == .ZOMBIE {
				continue
			}

			host.headerFlags  = 0
			host.commandCount = 0
			host.bufferCount  = 1
			host.packetSize   = size_of(ProtocolHeader)

			if !list_empty(&currentPeer.acknowledgements) {
				protocol_send_acknowledgements(host, &currentPeer)
			}

			if checkForTimeouts &&
				!list_empty(&currentPeer.sentReliableCommands) &&
				host.serviceTime._nsec >= currentPeer.nextTimeout._nsec &&
				protocol_check_timeouts(host, &currentPeer, event)
			{
				if event != nil && event.type != .NONE {
					return true
				} else {
					continue
				}
			}

			if (list_empty(&currentPeer.outgoingReliableCommands) ||
				protocol_send_reliable_outgoing_commands(host, &currentPeer)) &&
				list_empty(&currentPeer.sentReliableCommands) &&
				time.diff(host.serviceTime, currentPeer.lastReceiveTime) >= currentPeer.pingInterval &&
				currentPeer.mtu - u32(host.packetSize) >= size_of(ProtocolPing)
			{
				peer_ping(&currentPeer)
				protocol_send_reliable_outgoing_commands(host, &currentPeer)
			}

			if !list_empty(&currentPeer.outgoingUnreliableCommands) {
				protocol_send_unreliable_outgoing_commands(host, &currentPeer)
			}

			if host.commandCount == 0 {
				continue
			}

			if currentPeer.packetLossEpoch == {} {
				currentPeer.packetLossEpoch = host.serviceTime
			} else if time.diff(host.serviceTime, currentPeer.packetLossEpoch) >= PEER_PACKET_LOSS_INTERVAL && currentPeer.packetsSent > 0 {
				packetLoss := currentPeer.packetsLost * PEER_PACKET_LOSS_SCALE / currentPeer.packetsSent

				// #ifdef DEBUG
				// printf(
				// 	"peer %u: %f%%+-%f%% packet loss, %u+-%u ms round trip time, %f%% throttle, %u/%u outgoing, %u/%u incoming\n", currentPeer.incomingPeerID,
				// 	currentPeer.packetLoss / (float) PEER_PACKET_LOSS_SCALE,
				// 	currentPeer.packetLossVariance / (float) PEER_PACKET_LOSS_SCALE, currentPeer.roundTripTime, currentPeer.roundTripTimeVariance,
				// 	currentPeer.packetThrottle / (float) PEER_PACKET_THROTTLE_SCALE,
				// 	list_size(&currentPeer.outgoingReliableCommands),
				// 	list_size(&currentPeer.outgoingUnreliableCommands),
				// 	currentPeer.channels != nil ? list_size( &currentPeer.channels.incomingReliableCommands) : 0,
				// 	currentPeer.channels != nil ? list_size(&currentPeer.channels.incomingUnreliableCommands) : 0
				// )
				// #endif

				currentPeer.packetLossVariance -= currentPeer.packetLossVariance / 4

				if (packetLoss >= currentPeer.packetLoss) {
					currentPeer.packetLoss         += (packetLoss - currentPeer.packetLoss) / 8
					currentPeer.packetLossVariance += (packetLoss - currentPeer.packetLoss) / 4
				} else {
					currentPeer.packetLoss         -= (currentPeer.packetLoss - packetLoss) / 8
					currentPeer.packetLossVariance += (currentPeer.packetLoss - packetLoss) / 4
				}

				currentPeer.packetLossEpoch = host.serviceTime
				currentPeer.packetsSent     = 0
				currentPeer.packetsLost     = 0
			}

			dataLength: int
			if host.headerFlags & PROTOCOL_HEADER_FLAG_SENT_TIME == PROTOCOL_HEADER_FLAG_SENT_TIME {
				header.sentTime = u32be(host.serviceTime._nsec)
				dataLength = size_of(ProtocolHeader)
			} else {
				dataLength = size_of(ProtocolHeader) - size_of(u16be)
			}
			host.buffers[0] = headerData[:dataLength]

			shouldCompress = 0
			// TODO compressor
			// if (host.compressor.context != nil && host.compressor.compress != nil) {
			// 	size_t originalSize = host.packetSize - size_of(ProtocolHeader),
			// 	  compressedSize    = host.compressor.compress(host.compressor.context, &host.buffers[1], host.bufferCount - 1, originalSize, host.packetData[1], originalSize)
			// 	if (compressedSize > 0 && compressedSize < originalSize) {
			// 		host.headerFlags |= PROTOCOL_HEADER_FLAG_COMPRESSED
			// 		shouldCompress     = compressedSize
			// 		#ifdef DEBUG_COMPRESS
			// 		printf("peer %u: compressed %u.%u (%u%%)\n", currentPeer.incomingPeerID, originalSize, compressedSize, (compressedSize * 100) / originalSize)
			// 		#endif
			// 	}
			// }

			if currentPeer.outgoingPeerID < PROTOCOL_MAXIMUM_PEER_ID {
				host.headerFlags |= u16(currentPeer.outgoingSessionID) << PROTOCOL_HEADER_SESSION_SHIFT
			}
			header.peerID = u16be(currentPeer.outgoingPeerID | host.headerFlags)
			// TODO checksum
			// if (host.checksum != nil) {
			// 	uint32 *checksum = (uint32 *) &headerData[host.buffers[0].dataLength]
			// 	*checksum = currentPeer.outgoingPeerID < PROTOCOL_MAXIMUM_PEER_ID ? currentPeer.connectID : 0
			// 	host.buffers[0].dataLength += size_of(uint32)
			// 	*checksum = host.checksum(host.buffers, host.bufferCount)
			// }

			if shouldCompress > 0 {
				// NOTE double check the offset 1?
				host.buffers[1] = host.packetData[1:shouldCompress]
				host.bufferCount = 2
			}

			currentPeer.lastSendTime = host.serviceTime
			sentLength: int
			for i in 0..<host.bufferCount {
				data := host.buffers[i]
				sentLength, err := net.send_udp(host.socket, data, currentPeer.endpoint)
				if err != nil {
					fmt.eprintln("ERR SEEEEEEEEND", err)
				}

				if sentLength < 0 {
					// The local 'headerData' array (to which 'data' is assigned) goes out
					// of scope on return from this function, so ensure we no longer point to it.
					host.buffers[0] = nil
					fmt.eprintln("ERROR sending out packages")
				}

				host.totalSentData += u32(sentLength)
				currentPeer.totalDataSent += u64(sentLength)
			}

			protocol_remove_sent_unreliable_commands(&currentPeer)
			host.totalSentPackets += 1
		}
	}

	// The local 'headerData' array (to which 'data' is assigned) goes out
	// of scope on return from this function, so ensure we no longer point to it.
	host.buffers[0] = nil
	return false
}
