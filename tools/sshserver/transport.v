// SPDX-License-Identifier: GPL-2.0-or-later
module main

import net
import time
import io
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
	rx_auth   &hmac.Hmac[&sha256.Digest] = unsafe { nil }
	tx_auth   &hmac.Hmac[&sha256.Digest] = unsafe { nil }
	rx_seq    u32
	tx_seq    u32
	received  u64
	sent      u64
	session   []u8
	started   i64
	// Diagnostic counters include identification, MACs and partial I/O. Existing
	// sent/received/sequence limit accounting above is deliberately unchanged.
	wire_rx u64
	wire_tx u64
	diag_started u64 = time.sys_mono_now()
	diag_op string = 'session-start'
	diag_phase string = 'serve'
	diag_errno int
	diag_error_code int
	diag_result i64
	diag_partial int
	diag_requested int
	diag_packet_rx int = -1
	diag_packet_tx int = -1
	diag_disconnect u32
	diag_events int
	diag_cause string = 'none'
	diag_remote u32
}

// Only allow source-owned error labels. Never print arbitrary IError text
// (filesystem/launch/library errors may contain a path or peer data).
fn (mut t Transport) diagnostic_error(err IError) {
	t.diag_error_code = err.code()
	if err is io.Eof { t.diag_cause = 'network-eof'; return }
	if (t.diag_op == 'wait-for-read' || t.diag_op == 'wait-for-read-after-recv'
		|| t.diag_op == 'wait-for-write-after-send') && err.code() == net.err_timed_out_code {
		t.diag_cause = 'network-wait-timeout'
		return
	}
	if t.diag_errno != 0 && t.diag_op in ['recv', 'recv-retry', 'send'] {
		t.diag_cause = 'network-syscall-error'
		return
	}
	message := err.msg()
	t.diag_cause = match message {
		'truncated byte' { 'truncated-byte' }
		'truncated uint32' { 'truncated-uint32' }
		'invalid string limit' { 'invalid-string-limit' }
		'invalid string length' { 'invalid-string-length' }
		'trailing data' { 'trailing-data' }
		'packet alignment' { 'packet-alignment' }
		'invalid packet padding/length' { 'invalid-packet-padding-length' }
		'invalid packet length' { 'invalid-packet-length' }
		'invalid packet MAC' { 'invalid-packet-mac' }
		'invalid global request boolean' { 'invalid-global-request-boolean' }
		'invalid channel recipient' { 'invalid-channel-recipient' }
		'channel window overflow' { 'channel-window-overflow' }
		'channel input window violation' { 'channel-input-window-violation' }
		'invalid channel request' { 'invalid-channel-request' }
		'unsupported channel message' { 'unsupported-channel-message' }
		'peer disconnected' { 'peer-disconnected' }
		'rekey unsupported; reconnect' { 'rekey-unsupported' }
		'too many ignored packets' { 'too-many-ignored-packets' }
		'session limit; reconnect required (rekey unsupported)' { 'session-limit' }
		'poll failed' { 'poll-failed' }
		'connection closed' { 'connection-closed' }
		'payload size' { 'payload-size' }
		'network read bound' { 'network-read-bound' }
		else { 'io-or-library-error' }
	}
}

// Only bounded lifecycle/error events are printed. A final receipt bypasses the
// event budget so a noisy peer cannot hide the terminal state.
fn (mut t Transport) diagnostic(event string, c &Channel, terminal bool) {
	if !terminal && t.diag_events >= 32 { return }
	t.diag_events++
	saved := C.errno
	mut line := [2048]char{}
	n := unsafe { C.snprintf(&line[0], 2048, c'vinix-sshd-diag event=%s cause=%s phase=%s op=%s channel_op=%s errno=%lld error_code=%lld result=%lld partial=%lld requested=%lld elapsed_ms=%llu local=0 remote=%llu opened=%d started=%d eof=%d input_closed=%d pending=%lld window=%llu receive_window=%llu child_pid=%lld child_in=%llu child_out=%llu child_err=%llu input_discarded=%llu reaped=%d raw_status=%lld wait_result=%lld wait_errno=%lld wire_rx=%llu wire_tx=%llu packets_rx=%llu packets_tx=%llu last_rx=%lld last_tx=%lld disconnect_reason=%llu\n',
		event.str, t.diag_cause.str, t.diag_phase.str, t.diag_op.str, c.diag_op.str, i64(t.diag_errno), i64(t.diag_error_code), t.diag_result,
		i64(t.diag_partial), i64(t.diag_requested), u64((time.sys_mono_now() - t.diag_started) / 1000000),
		u64(if c.opened { c.remote } else { t.diag_remote }), i32(c.opened), i32(c.started), i32(c.eof), i32(c.input_closed), i64(c.pending.len),
		u64(c.window), u64(c.receive_window), i64(c.child.pid), c.diag_input, c.diag_output, c.diag_errors,
		c.diag_discarded, i32(c.child.reaped), i64(c.child.status), i64(c.child.wait_result), i64(c.child.wait_errno),
		t.wire_rx, t.wire_tx, u64(t.rx_seq), u64(t.tx_seq), i64(t.diag_packet_rx), i64(t.diag_packet_tx), u64(t.diag_disconnect)) }
	diagnostic_write(&line[0], n)
	C.errno = saved
}

fn (mut t Transport) diagnostic_operation(op string, result i64, code int, done int, wanted int) {
	t.diag_op = op
	t.diag_result = result
	t.diag_errno = code
	t.diag_error_code = 0
	t.diag_partial = done
	t.diag_requested = wanted
}

// Observation adapters for net.TcpConn's POSIX read/write sequence. All server
// reads have a deadline, so TcpConn also takes wait_for_read before blocking
// recv. Keep its one retry, EOF/error values and write wait/retry decisions.
// Capture errno BEFORE error construction, logging or any other syscall.
fn (mut t Transport) observed_read(mut data []u8, done int, wanted int) !int {
	if t.socket.is_blocking {
		t.diagnostic_operation('wait-for-read', 0, 0, done, wanted)
		t.socket.wait_for_read() or { t.diag_error_code = err.code(); return err }
	}
	flags := if t.socket.is_blocking { 0 } else { net.msg_dontwait }
	result := C.recv(t.socket.sock.handle, data.data, data.len, flags)
	code := if result < 0 { int(C.errno) } else { 0 }
	t.diagnostic_operation('recv', i64(result), code, done, wanted)
	if result == 0 { return io.Eof{} }
	if result > 0 { t.wire_rx += u64(result); return result }
	if code in [C.EAGAIN, C.EWOULDBLOCK, C.EINTR] {
		t.diag_op = 'wait-for-read-after-recv'
		t.socket.wait_for_read() or { t.diag_error_code = err.code(); return err }
		retry := C.recv(t.socket.sock.handle, data.data, data.len, flags)
		retry_code := if retry < 0 { int(C.errno) } else { 0 }
		t.diagnostic_operation('recv-retry', i64(retry), retry_code, done, wanted)
		if retry == 0 { return io.Eof{} }
		if retry > 0 { t.wire_rx += u64(retry) }
		return net.socket_error(retry)
	}
	net.wrap_error(code)!
	return error('none')
}

fn (mut t Transport) observed_write(data []u8, done int, wanted int) !int {
	t.socket.last_write_sent = 0
	mut pos := 0
	for pos < data.len {
		result := unsafe { C.send(t.socket.sock.handle, &data[pos], data.len - pos, net.msg_nosignal) }
		code := if result < 0 { int(C.errno) } else { 0 }
		t.diagnostic_operation('send', i64(result), code, done + pos, wanted)
		if result < 0 {
			if code in [C.EAGAIN, C.EWOULDBLOCK, C.EINTR] {
				t.diag_op = 'wait-for-write-after-send'
				t.socket.wait_for_write() or { t.diag_error_code = err.code(); return err }
				continue
			} else { net.wrap_error(code)! }
		}
		pos += result
		t.wire_tx += u64(result)
		t.socket.last_write_sent = pos
	}
	return pos
}

fn (mut t Transport) read_exact(n int) ![]u8 {
	if n < 0 || n > max_packet + 32 { return error('network read bound') }
	mut data := []u8{len: n}
	t.read_into(mut data) or {
		unsafe { data.free() }
		return err
	}
	return data
}

fn (mut t Transport) read_into(mut data []u8) ! {
	mut pos := 0
	for pos < data.len {
		count := t.observed_read(mut data[pos..], pos, data.len)!
		if count <= 0 { return error('connection closed') }
		pos += count
	}
}

fn (mut t Transport) write_all(data []u8) ! {
	mut pos := 0
	for pos < data.len {
		count := t.observed_write(data[pos..], pos, data.len)!
		if count <= 0 { return error('connection closed') }
		pos += count
	}
}

// The streaming keyed API consumes input synchronously and reuses digests;
// hmac.new retains payload-sized temporaries in a -gc none worker.
fn (mut t Transport) packet_mac(receiving bool, plain []u8) []u8 {
	if receiving && isnil(t.rx_auth) { t.rx_auth = hmac.new_hmac(sha256.new, t.rx_mac) }
	if !receiving && isnil(t.tx_auth) { t.tx_auth = hmac.new_hmac(sha256.new, t.tx_mac) }
	mut state := if receiving { t.rx_auth } else { t.tx_auth }
	seq := if receiving { t.rx_seq } else { t.tx_seq }
	prefix := [u8(seq >> 24), u8(seq >> 16), u8(seq >> 8), u8(seq)]!
	state.write(unsafe { prefix[..] }) or { panic(err) }
	state.write(plain) or { panic(err) }
	mut digest := []u8{len: 32}
	state.sum_into(mut digest)
	return digest
}

// After CHANNEL_CLOSE, let the peer send its close/disconnect and TCP FIN.
// Closing with unread peer bytes can reset TCP and turn a successful exec into
// OpenSSH exit 255. This terminal drain accepts no further application work.
fn (mut t Transport) drain_disconnect() {
	t.diag_phase = 'disconnect-drain'
	result := C.shutdown(t.socket.sock.handle, C.SHUT_WR)
	code := if result < 0 { int(C.errno) } else { 0 }
	if result < 0 { diagnostic_io('shutdown-write', t.socket.sock.handle, code, i64(result), 0, 0) }
	t.socket.set_read_deadline(time.now().add(time.second))
	mut buffer := []u8{len: 4096}
	for _ in 0 .. 16 {
		count := t.observed_read(mut buffer, 0, buffer.len) or {
			t.diagnostic_error(err)
			t.diagnostic('disconnect-drain-end', &Channel{}, true)
			return
		}
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
	t.diag_phase = 'packet-send'
	t.diag_packet_tx = if payload.len > 0 { int(payload[0]) } else { -1 }
	t.limits()!
	if payload.len < 1 || payload.len > max_packet - 64 { return error('payload size') }
	block := if t.encrypted { 16 } else { 8 }
	mut pad := block - ((payload.len + 5) % block)
	if pad < 4 { pad += block }
	mut plain := []u8{cap: payload.len + pad + 5}
	defer { unsafe { plain.free() } }
	put_u32(mut plain, u32(payload.len + pad + 1))
	plain << u8(pad)
	plain << payload
	padding := entropy(pad)!
	defer { unsafe { padding.free() } }
	plain << padding
	mut wire := []u8{len: plain.len, cap: plain.len + 32}
	defer { unsafe { wire.free() } }
	copy(mut wire, plain)
	if t.encrypted {
		t.tx.xor_key_stream(mut wire, plain)
		digest := t.packet_mac(false, plain)
		defer { unsafe { digest.free() } }
		wire << digest
	}
	t.write_all(wire)!
	t.tx_seq++
	t.sent += u64(wire.len)
}

fn (mut t Transport) receive() ![]u8 {
	t.diag_phase = 'packet-receive'
	t.limits()!
	block := if t.encrypted { 16 } else { 8 }
	mut first := t.read_exact(block)!
	defer { unsafe { first.free() } }
	if t.encrypted { t.rx.xor_key_stream(mut first, first) }
	mut r := Reader{ data: first }
	n := r.uint()!
	if n < 6 || n > max_packet || (n + 4) % u32(block) != 0 || n + 4 < u32(block) {
		return error('invalid packet length')
	}
	// One owner for the authenticated plaintext. Tail is only a borrowed slice.
	mut plain := []u8{len: int(n) + 4}
	defer { unsafe { plain.free() } }
	copy(mut plain, first)
	mut tail := unsafe { plain[block..] }
	t.read_into(mut tail)!
	if t.encrypted { t.rx.xor_key_stream(mut tail, tail) }
	if t.encrypted {
		supplied := t.read_exact(32)!
		defer { unsafe { supplied.free() } }
		digest := t.packet_mac(true, plain)
		defer { unsafe { digest.free() } }
		if !hmac.equal(supplied, digest) {
			return error('invalid packet MAC')
		}
	}
	t.rx_seq++
	t.received += u64(n) + 4
	payload := payload_from_plain(plain, block)!
	t.diag_packet_rx = int(payload[0])
	return payload
}

fn (mut t Transport) next() ![]u8 {
	for _ in 0 .. 64 {
		p := t.receive()!
		if p[0] == 1 {
			// RFC 4253 numeric reason only; never log peer description/language.
			if p.len >= 5 { t.diag_disconnect = (u32(p[1]) << 24) | (u32(p[2]) << 16) | (u32(p[3]) << 8) | u32(p[4]) }
			t.diag_op = 'peer-disconnect'
			unsafe { p.free() }
			return error('peer disconnected')
		}
		if p[0] == 2 || p[0] == 4 { unsafe { p.free() }; continue }
		if p[0] == 20 && t.encrypted {
			unsafe { p.free() }
			return error('rekey unsupported; reconnect')
		}
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
