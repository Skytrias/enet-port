package enet

Stack :: struct($T: typeid, $N: int) {
	data: [N]T,
	length: int,
}

stack_push :: proc(using stack: ^$T/Stack($K, $N)) -> (out: ^K) {
	if length < N {
		out = &data[length]
		data[length] = {}
		length += 1
	}

	return
}

stack_append :: proc "contextless" (using stack: ^$T/Stack($K, $N), insert: K) -> (out: ^K) {
	if length < N {
		out = &data[length]
		data[length] = insert
		length += 1
	}

	return
}

stack_slice :: proc(using stack: ^$T/Stack($K, $N)) -> []K {
	return data[:length]
}