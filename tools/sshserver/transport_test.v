module main

import net
import time

fn C.socketpair(int, int, int, &i32) int

fn test_streaming_mac_matches_reference_in_both_directions() {
	mut t := Transport{rx_mac: []u8{len: 32, init: 7}, tx_mac: []u8{len: 32, init: 19}}
	for i in 0 .. 20 {
		t.rx_seq = u32(i * 65537)
		t.tx_seq = u32(i * 131073)
		payload := []u8{len: i * 97, init: u8(i)}
		for receiving in [false, true]! {
			got := t.packet_mac(receiving, payload)
			expected := mac(if receiving { t.rx_mac } else { t.tx_mac }, if receiving { t.rx_seq } else { t.tx_seq }, payload)
			assert got == expected
			unsafe { got.free(); expected.free() }
		}
		unsafe { payload.free() }
	}
}

fn packet_test_pair() !(&net.TcpConn, &net.TcpConn) {
	mut fds := [2]i32{}
	if C.socketpair(C.AF_UNIX, C.SOCK_STREAM, 0, &fds[0]) != 0 { return error('socketpair') }
	return &net.TcpConn{ sock: net.tcp_socket_from_handle_raw(fds[0]), handle: fds[0],
		read_timeout: 5 * time.second, write_timeout: 5 * time.second },
		&net.TcpConn{ sock: net.tcp_socket_from_handle_raw(fds[1]), handle: fds[1],
		read_timeout: 5 * time.second, write_timeout: 5 * time.second }
}

fn test_encrypted_packets_keep_ctr_continuity_and_payload_ownership() {
	mut client, mut server := packet_test_pair() or { panic(err) }
	defer { client.close() or {} }
	defer { server.close() or {} }
	key := []u8{len: 16, init: 17}
	iv := []u8{len: 16, init: 23}
	mac_key := []u8{len: 32, init: 31}
	mut sender := Transport{ socket: client, encrypted: true,
		tx: ctr(key, iv)!, tx_mac: mac_key, started: time.now().unix() }
	mut receiver := Transport{ socket: server, encrypted: true,
		rx: ctr(key, iv)!, rx_mac: mac_key, started: time.now().unix() }
	for size in [1, 15, 16, 17, 255, 4096, 3] {
		payload := []u8{len: size, init: u8(size)}
		sender.send(payload) or { panic(err) }
		got := receiver.receive() or { panic(err) }
		assert got == payload
		// receive already freed the plaintext backing; this remains caller-owned.
		unsafe { got.free(); payload.free() }
	}
	assert sender.tx_seq == 7 && receiver.rx_seq == 7
}

fn test_invalid_mac_never_returns_a_payload() {
	mut client, mut server := packet_test_pair() or { panic(err) }
	defer { client.close() or {} }
	defer { server.close() or {} }
	key := []u8{len: 16, init: 17}
	iv := []u8{len: 16, init: 23}
	mac_key := []u8{len: 32, init: 31}
	mut stream := ctr(key, iv)!
	mut plain := []u8{len: 16}
	plain[3] = 12
	plain[4] = 10
	plain[5] = 94
	mut wire := []u8{len: 16, cap: 48}
	stream.xor_key_stream(mut wire, plain)
	mut digest := mac(mac_key, 0, plain)
	digest[0] ^= 1
	wire << digest
	mut sender := Transport{ socket: client }
	sender.write_all(wire) or { panic(err) }
	mut receiver := Transport{ socket: server, encrypted: true,
		rx: ctr(key, iv)!, rx_mac: mac_key, started: time.now().unix() }
	if _ := receiver.receive() { assert false } else { assert err.msg() == 'invalid packet MAC' }
	assert receiver.rx_seq == 0
	unsafe { plain.free(); wire.free(); digest.free() }
}
