module main

fn test_bounded_codec_corpus() {
	for block in [0, -1, 1, 32] {
		if _ := payload_from_plain([]u8{len: 16}, block) {
			assert false
		}
	}
	mut negative := Reader{ data: [u8(0), 0, 0, 0], pos: -1 }
	if _ := negative.uint() {
		assert false
	}
	mut length := Reader{ data: [u8(0), 0, 0, 0] }
	if _ := length.string_bytes(-1) {
		assert false
	}
	for n in 0 .. 64 {
		sample := []u8{len: n, init: 255}
		mut r := Reader{ data: sample }
		if _ := r.string_bytes(65536) {
			assert false
		}
		if _ := payload_from_plain(sample, 8) {
			assert false
		}
	}
	for pad in [u8(0), 1, 2, 3, 11, 12, 255] {
		mut plain := []u8{len: 16}
		plain[3] = 12
		plain[4] = pad
		if _ := payload_from_plain(plain, 16) {
			assert false
		}
	}
	mut plain := []u8{len: 16}
	plain[3] = 12
	plain[4] = 4
	plain[5] = 50
	assert payload_from_plain(plain, 16) or { panic(err) } == plain[5..12]
	for n in 0 .. 32 {
		if _ := secret_mpint([]u8{len: n, init: 1}) {
			assert false
		}
	}
	mut secret := []u8{len: 32}
	secret[0] = 128
	encoded := secret_mpint(secret) or { panic(err) }
	assert encoded.len == 37 && encoded[3] == 33 && encoded[4] == 0 && encoded[5] == 128
	assert mac([]u8{len: 32}, 0, plain) != mac([]u8{len: 32}, 1, plain)
}
