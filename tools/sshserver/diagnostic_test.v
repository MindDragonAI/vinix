module main

import net
import time

fn C.socketpair(int, int, int, &i32) int

fn diagnostic_test_pair() !(&net.TcpConn, &net.TcpConn) {
	mut fds := [2]i32{}
	if C.socketpair(C.AF_UNIX, C.SOCK_STREAM, 0, &fds[0]) != 0 { return error('socketpair') }
	return &net.TcpConn{ sock: net.tcp_socket_from_handle_raw(fds[0]), handle: fds[0],
		read_timeout: time.second, write_timeout: time.second },
		&net.TcpConn{ sock: net.tcp_socket_from_handle_raw(fds[1]), handle: fds[1],
		read_timeout: time.second, write_timeout: time.second }
}

fn test_diagnostic_network_partial_eof_and_errno_preserve_progress() {
	mut writer, mut reader := diagnostic_test_pair()!
	defer { writer.close() or {}; reader.close() or {} }
	mut sender := Transport{socket: writer}
	sender.write_all([u8(1), 2, 3])!
	assert sender.wire_tx == 3
	C.shutdown(writer.sock.handle, C.SHUT_WR)
	mut receiver := Transport{socket: reader}
	mut data := []u8{len: 8}
	if _ := receiver.read_into(mut data) { assert false }
	assert receiver.wire_rx == 3
	assert receiver.diag_op == 'recv'
	assert receiver.diag_errno == 0 && receiver.diag_result == 0
	assert receiver.diag_partial == 3 && receiver.diag_requested == 8
	assert receiver.rx_seq == 0 && receiver.received == 0
	// A real syscall failure must retain EBADF, irrespective of later errno.
	C.close(reader.sock.handle)
	reader.is_blocking = false
	if _ := receiver.read_into(mut data) { assert false }
	C.errno = C.EINVAL
	assert receiver.diag_errno == C.EBADF
	assert receiver.wire_rx == 3
}

fn test_diagnostic_receipt_is_bounded_private_and_preserves_errno() {
	mut fds := [2]i32{}
	assert C.pipe(&fds[0]) == 0
	old_stderr := C.dup(2)
	assert old_stderr >= 0
	assert C.dup2(fds[1], 2) == 2
	mut t := Transport{}
	c := Channel{remote: 17, opened: true, term: 'DO-NOT-PRINT-TERM',
		environment: ['DO-NOT-PRINT-ENV'], pending: 'DO-NOT-PRINT-PAYLOAD'.bytes(),
		diag_input: 23, diag_output: 29, diag_errors: 31,
		child: Child{reaped: true, status: 7 << 8}}
	t.diag_events = 32
	t.diagnostic('suppressed', &c, false)
	assert t.diag_events == 32
	C.errno = C.EBUSY
	t.diagnostic('session-error', &c, true)
	assert C.errno == C.EBUSY
	assert C.dup2(old_stderr, 2) == 2
	C.close(old_stderr)
	C.close(fds[1])
	mut data := [4096]u8{}
	n := C.read(fds[0], &data[0], 4096)
	C.close(fds[0])
	assert n > 0 && n < 2048
	text := unsafe { (&data[0]).vstring_with_len(n) }
	assert text.count('\n') == 1 && !text.contains('DO-NOT-PRINT')
	assert !text.contains('suppressed')
	assert text.contains('local=0 remote=17')
	assert text.contains('child_in=23 child_out=29 child_err=31')
	assert text.contains('reaped=1 raw_status=1792')
	t.diagnostic_error(error('private/path/command'))
	assert t.diag_cause == 'io-or-library-error'
	t.diagnostic_error(error('invalid packet MAC'))
	assert t.diag_cause == 'invalid-packet-mac'
}

fn test_diagnostic_wait_timeout_is_not_reported_as_recv_errno() {
	mut writer, mut reader := diagnostic_test_pair()!
	defer { writer.close() or {}; reader.close() or {} }
	reader.set_read_deadline(time.now().add(-time.second))
	mut t := Transport{socket: reader}
	mut data := []u8{len: 1}
	if _ := t.read_into(mut data) { assert false }
	assert t.diag_op == 'wait-for-read'
	assert t.diag_errno == 0 && t.diag_error_code == net.err_timed_out_code
	assert t.wire_rx == 0
}

fn test_diagnostic_session_unwind_keeps_state_and_static_cause() {
	mut writer, mut reader := diagnostic_test_pair()!
	defer { writer.close() or {}; reader.close() or {} }
	mut sender := Transport{socket: writer, started: time.now().unix()}
	// Channel data before CHANNEL_OPEN is rejected without changing its error.
	sender.send([u8(94), 0, 0, 0, 0])!
	mut fds := [2]i32{}
	assert C.pipe(&fds[0]) == 0
	old_stderr := C.dup(2)
	assert C.dup2(fds[1], 2) == 2
	mut receiver := Transport{socket: reader, started: time.now().unix()}
	if _ := receiver.session_loop(Config{}) { assert false } else {
		assert err.msg() == 'invalid channel recipient'
	}
	assert C.dup2(old_stderr, 2) == 2
	C.close(old_stderr)
	C.close(fds[1])
	mut data := [4096]u8{}
	n := C.read(fds[0], &data[0], 4096)
	C.close(fds[0])
	assert n > 0 && n < 2048
	text := unsafe { (&data[0]).vstring_with_len(n) }
	assert text.contains('event=session-error cause=invalid-channel-recipient')
	assert text.contains('channel_op=channel-decode')
	assert text.contains('packets_rx=1') && text.contains('last_rx=94')
	assert text.count('\n') == 1
}

fn test_diagnostic_partial_send_before_timeout_counts_actual_wire_bytes() {
	mut writer, mut reader := diagnostic_test_pair()!
	defer { writer.close() or {}; reader.close() or {} }
	writer.sock.set_option_int(.send_buf_size, 1024)!
	nonblock(writer.sock.handle)!
	writer.set_write_deadline(time.now().add(20 * time.millisecond))
	mut t := Transport{socket: writer}
	data := []u8{len: 1024 * 1024}
	if _ := t.write_all(data) { assert false }
	assert t.wire_tx > 0 && t.wire_tx < u64(data.len)
	assert t.diag_op == 'wait-for-write-after-send'
	assert t.diag_errno in [C.EAGAIN, C.EWOULDBLOCK]
	assert t.diag_error_code == net.err_timed_out_code
	assert t.diag_partial == int(t.wire_tx) && t.diag_requested == data.len
	assert t.socket.last_write_sent == int(t.wire_tx)
	assert t.tx_seq == 0 && t.sent == 0
}
