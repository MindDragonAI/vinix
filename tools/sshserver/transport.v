// SPDX-License-Identifier: GPL-2.0-or-later
module main

import net
import time
import crypto.cipher
import crypto.hmac
import crypto.sha256
import tools.packages.signing

struct Transport {
mut:
	socket    &net.TcpConn = unsafe { nil }
	rx        cipher.Stream
	tx        cipher.Stream
	encrypted bool
	rx_mac    []u8
	tx_mac    []u8
	rx_seq    u32
	tx_seq    u32
	received  u64
	sent      u64
	session   []u8
	started   i64
}

fn (mut t Transport) read_exact(n int) ![]u8 {
	if n < 0 || n > max_packet + 32 { return error('network read bound') }
	mut data := []u8{len: n}
	mut pos := 0
	for pos < n {
		count := t.socket.read(mut data[pos..])!
		if count <= 0 { return error('connection closed') }
		pos += count
	}
	return data
}

fn (mut t Transport) write_all(data []u8) ! {
	mut pos := 0
	for pos < data.len {
		count := t.socket.write(data[pos..])!
		if count <= 0 { return error('connection closed') }
		pos += count
	}
}

// After CHANNEL_CLOSE, let the peer send its close/disconnect and TCP FIN.
// Closing with unread peer bytes can reset TCP and turn a successful exec into
// OpenSSH exit 255. This terminal drain accepts no further application work.
fn (mut t Transport) drain_disconnect() {
	C.shutdown(t.socket.sock.handle, C.SHUT_WR)
	t.socket.set_read_deadline(time.now().add(time.second))
	mut buffer := []u8{len: 4096}
	for _ in 0 .. 16 {
		count := t.socket.read(mut buffer) or { return }
		if count <= 0 { return }
	}
}

fn (t Transport) limits() ! {
	if t.received > u64(1024) * 1024 * 1024 || t.sent > u64(1024) * 1024 * 1024
		|| t.rx_seq > 1000000 || t.tx_seq > 1000000 || time.now().unix() - t.started > 3600 {
		return error('session limit; reconnect required (rekey unsupported)')
	}
}

fn (mut t Transport) send(payload []u8) ! {
	t.limits()!
	if payload.len < 1 || payload.len > max_packet - 64 { return error('payload size') }
	block := if t.encrypted { 16 } else { 8 }
	mut pad := block - ((payload.len + 5) % block)
	if pad < 4 { pad += block }
	mut plain := []u8{cap: payload.len + pad + 5}
	put_u32(mut plain, u32(payload.len + pad + 1))
	plain << u8(pad)
	plain << payload
	plain << entropy(pad)!
	mut wire := plain.clone()
	if t.encrypted {
		t.tx.xor_key_stream(mut wire, plain)
		wire << mac(t.tx_mac, t.tx_seq, plain)
	}
	t.write_all(wire)!
	t.tx_seq++
	t.sent += u64(wire.len)
}

fn (mut t Transport) receive() ![]u8 {
	t.limits()!
	block := if t.encrypted { 16 } else { 8 }
	first := t.read_exact(block)!
	mut plain := first.clone()
	if t.encrypted { t.rx.xor_key_stream(mut plain, first) }
	mut r := Reader{ data: plain }
	n := r.uint()!
	if n < 6 || n > max_packet || (n + 4) % u32(block) != 0 || n + 4 < u32(block) {
		return error('invalid packet length')
	}
	rest := t.read_exact(int(n) + 4 - block)!
	mut tail := rest.clone()
	if t.encrypted { t.rx.xor_key_stream(mut tail, rest) }
	plain << tail
	if t.encrypted {
		supplied := t.read_exact(32)!
		if !hmac.equal(supplied, mac(t.rx_mac, t.rx_seq, plain)) {
			return error('invalid packet MAC')
		}
	}
	t.rx_seq++
	t.received += u64(n) + 4
	return payload_from_plain(plain, block)!
}

fn (mut t Transport) next() ![]u8 {
	for _ in 0 .. 64 {
		p := t.receive()!
		if p[0] == 1 { return error('peer disconnected') }
		if p[0] in [u8(2), 4] { continue }
		if p[0] == 20 && t.encrypted { return error('rekey unsupported; reconnect') }
		return p
	}
	return error('too many ignored packets')
}

fn kex_init() ![]u8 {
	mut p := [u8(20)]
	p << entropy(16)!
	for name in ['curve25519-sha256', 'ssh-ed25519', 'aes128-ctr', 'aes128-ctr', 'hmac-sha2-256',
		'hmac-sha2-256', 'none', 'none', '', ''] {
		put_string(mut p, name.bytes())
	}
	p << u8(0)
	put_u32(mut p, 0)
	return p
}

fn check_kex(p []u8) !bool {
	if p.len < 17 || p[0] != 20 { return error('expected KEXINIT') }
	mut r := Reader{ data: p, pos: 17 }
	mut names := []string{}
	for _ in 0 .. 10 { names << r.string_bytes(4096)!.bytestr() }
	follows := r.byte()!
	if follows > 1 || r.uint()! != 0 { return error('invalid KEXINIT') }
	r.end()!
	required := ['curve25519-sha256', 'ssh-ed25519', 'aes128-ctr', 'aes128-ctr', 'hmac-sha2-256',
		'hmac-sha2-256', 'none', 'none']
	for i, want in required {
		if want !in names[i].split(',') { return error('no matching SSH algorithm') }
	}
	return follows == 1 && (names[0].split(',')[0] != required[0] || names[1].split(',')[0] != required[1])
}

fn (mut t Transport) handshake(key signing.PrivateKey) ! {
	t.write_all('SSH-2.0-Vinix\r\n'.bytes())!
	mut ident := []u8{}
	mut newline := false
	for _ in 0 .. 255 {
		b := t.read_exact(1)![0]
		if b == `\n` {
			newline = true
			break
		}
		ident << b
	}
	client := ident.bytestr().trim_right('\r')
	if !newline || !client.starts_with('SSH-2.0-') || client.bytes().any(it < 32 || it > 126) {
		return error('invalid identification')
	}
	server_kex := kex_init()!
	t.send(server_kex)!
	client_kex := t.next()!
	discard := check_kex(client_kex)!
	if discard { _ := t.next()! }
	init := t.next()!
	mut r := Reader{ data: init }
	if r.byte()! != 30 { return error('expected ECDH_INIT') }
	client_public := r.string_bytes(32)!
	r.end()!
	mut scalar := entropy(32)!
	server_public := x_public(mut scalar)!
	shared := x_shared(mut scalar, client_public)!
	encoded_k := secret_mpint(shared)!
	host_blob := public_blob(key.public_key())
	mut transcript := []u8{}
	for value in [client.bytes(), 'SSH-2.0-Vinix'.bytes(), client_kex, server_kex, host_blob,
		client_public, server_public] {
		put_string(mut transcript, value)
	}
	transcript << encoded_k
	h := sha256.sum(transcript)
	t.session = h.clone()
	mut sig := text_packet(0, 'ssh-ed25519')[1..].clone()
	put_string(mut sig, signing.sign(key, h)!)
	mut reply := [u8(31)]
	put_string(mut reply, host_blob)
	put_string(mut reply, server_public)
	put_string(mut reply, sig)
	t.send(reply)!
	t.send([u8(21)])!
	incoming := t.next()!
	if incoming != [u8(21)] { return error('expected NEWKEYS') }
	t.rx = ctr(kdf(encoded_k, h, `C`, t.session, 16), kdf(encoded_k, h, `A`, t.session, 16))!
	t.tx = ctr(kdf(encoded_k, h, `D`, t.session, 16), kdf(encoded_k, h, `B`, t.session, 16))!
	t.rx_mac = kdf(encoded_k, h, `E`, t.session, 32)
	t.tx_mac = kdf(encoded_k, h, `F`, t.session, 32)
	t.encrypted = true
}
