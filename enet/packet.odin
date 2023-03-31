package enet

import "core:mem"

// TODO callbacks?

packet_create :: proc(data: []byte, flags: u32) -> (packet: ^Packet) {
	if flags & PACKET_FLAG_NO_ALLOCATE == PACKET_FLAG_NO_ALLOCATE {
		packet = new(Packet)
		packet.data = raw_data(data)
	} else {
		packet = cast(^Packet) mem.alloc(size_of(Packet) + len(data))
		packet.data = rawptr(uintptr(packet) + size_of(Packet))
	}

	packet.flags = flags
	packet.dataLength = len(data)
	return
}

// NOTE create_offset is unecessary since we pass a slice to packet_create

packet_copy :: proc(packet: ^Packet) -> ^Packet {
	return packet_create(mem.byte_slice(packet.data, packet.dataLength), packet.flags)
}

packet_destroy :: proc(packet: ^Packet) {
	if packet == nil {
		return
	}

	free(packet)
}

