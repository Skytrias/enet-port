package enet

ListNode :: struct {
	next: ^ListNode,
	previous: ^ListNode,
}

List :: struct {
	using sentinel: ListNode,
}

ListIterator :: ^ListNode

list_clear :: proc(list: ^List) {
	list.next = &list.sentinel
	list.previous = &list.sentinel
}

list_insert :: proc(position, data: ListIterator) -> (result: ListIterator) {
	result = data

	result.previous = position.previous
	result.next = position
	
	result.previous.next = result
	position.previous = result

	return
}

list_remove :: proc(position: ListIterator) -> ListIterator {
	position.previous.next = position.next
	position.next.previous = position.previous
	return position
}

list_move :: proc(position: ListIterator, data_first, data_last: rawptr) -> ListIterator {
	first := cast(ListIterator) data_first
	last := cast(ListIterator) data_last

	first.previous.next = last.next
	last.next.previous = first.previous

	first.previous = position.previous
	last.next = position

	first.previous.next = first
	position.previous = last

	return first
}

list_size :: proc(list: ^List) -> (size: int) {
	iter := list_begin(list)
	for iter != list_end(list) {
		size += 1
		iter = iter.next
	}
	return
}

list_begin :: proc(list: ^List) -> ListIterator {
	return list.next
}

list_end :: proc(list: ^List) -> ListIterator {
	return &list.sentinel
}

list_empty :: proc(list: ^List) -> bool {
	return list.previous == list.next
}

list_next :: #force_inline proc(iterator: ListIterator) -> ListIterator {
	return iterator.next
}

list_previous :: #force_inline proc(iterator: ListIterator) -> ListIterator {
	return iterator.next
}

list_front :: #force_inline proc(list: ^List) -> ListIterator {
	return list.next
}

list_back :: #force_inline proc(list: ^List) -> ListIterator {
	return list.previous
}

