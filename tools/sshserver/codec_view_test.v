module main

fn test_string_view_borrows_but_owned_string_and_payload_survive() {
	mut source := []u8{len: 16}
	source[3] = 12
	source[4] = 4
	source[5] = 94
	owned := payload_from_plain(source, 16)!
	unsafe { source.free() }
	assert owned[0] == 94 && owned.len == 7
	unsafe { owned.free() }
	mut packet := []u8{len: 7}
	packet[3] = 3
	packet[4] = 41
	mut r := Reader{ data: packet }
	view := r.string_view(3)!
	assert view.data == unsafe { &packet[4] }
	assert view == [u8(41), 0, 0]
	r.pos = 0
	copy := r.string_bytes(3)!
	unsafe { packet.free() }
	assert copy == [u8(41), 0, 0]
	unsafe { copy.free() }
}
