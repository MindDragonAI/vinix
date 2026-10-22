// SPDX-License-Identifier: GPL-2.0-or-later
module sessionipc

import os

fn C.waitpid(int, &i32, int) int

fn reply_test_pair() [2]i32 {
	mut pair := [i32(-1), i32(-1)]!
	assert C.socketpair(C.AF_UNIX, C.SOCK_STREAM, 0, &pair[0]) == 0
	assert desktop_set_nonblocking(pair[0], true)
	assert desktop_set_nonblocking(pair[1], true)
	return pair
}

fn reply_test_control(fd int) {
	session_close_control()
	session_control_fd = fd
	session_control_owner = C.getpid()
	session_control_pending = false
	session_control_reply_pending = false
}

fn reply_test_busy(request string) {
	started := monotonic_millis()
	session_request(request, 20) or {
		assert err is SessionReplyNotStarted
		session_discard_error(err)
		assert session_has_control()
		assert session_control_reply_pending
		assert monotonic_millis() - started < 300
		return
	}
	assert false
}

// The synchronization socket holds the broker's first reply until all busy
// calls finish. No sleeps or scheduling assumptions decide when it is late.
fn test_late_reply_drained_before_next_request_and_busy_never_sends() {
	pair := reply_test_pair()
	gate := reply_test_pair()
	child := C.fork()
	assert child >= 0
	if child == 0 {
		desktop_close(pair[0])
		desktop_close(gate[0])
		first := session_receive_timeout(pair[1], 2000) or { C._exit(11); return }
		if first != 'first' { C._exit(12) }
		// Parent releases only after the original and repeated busy timeouts.
		session_receive_timeout(gate[1], 2000) or { C._exit(13); return }
		mut poll := C.pollfd{fd: pair[1], events: C.POLLIN}
		if C.poll(&poll, 1, 0) != 0 { C._exit(14) }
		if !session_send_message(pair[1], 'error\told request rejected') { C._exit(15) }
		second := session_receive_timeout(pair[1], 2000) or { C._exit(16); return }
		if second != 'second' { C._exit(17) }
		if !session_send_message(pair[1], 'ok\tsecond') { C._exit(18) }
		C._exit(0)
	}
	desktop_close(pair[1])
	desktop_close(gate[1])
	reply_test_control(pair[0])
	defer {
		session_close_control()
		desktop_close(gate[0])
	}
	reply_test_busy('first')
	reply_test_busy('must not send one')
	reply_test_busy('must not send two')
	assert session_send_message(gate[0], 'release')
	reply := session_request('second', 300) or { panic(err) }
	defer { unsafe { reply.free() } }
	assert reply == 'ok\tsecond'
	assert session_has_control()
	assert !session_control_reply_pending
	mut status := i32(-1)
	assert C.waitpid(child, &status, 0) == child
	assert status == 0
}

fn reply_test_fails_closed(frame string, eof bool, pending bool) {
	pair := reply_test_pair()
	reply_test_control(pair[0])
	session_control_reply_pending = pending
	if frame.len > 0 { assert session_send(pair[1], frame) }
	if eof { desktop_close(pair[1]) }
	defer {
		session_close_control()
		if !eof { desktop_close(pair[1]) }
	}
	session_request('request', 20) or {
		assert err !is SessionReplyNotStarted
		session_discard_error(err)
		assert !session_has_control()
		assert !session_control_reply_pending
		return
	}
	assert false
}

fn test_partial_header_body_malformed_and_eof_close_control() {
	for pending in [false, true] {
		reply_test_fails_closed('\x04\x00', false, pending)
		reply_test_fails_closed('\x04\x00\x00\x00ab', false, pending)
		reply_test_fails_closed('\x04\x00', true, pending)
		reply_test_fails_closed('\x04\x00\x00\x00ab', true, pending)
		reply_test_fails_closed('\x00\x00\x00\x00', false, pending)
		reply_test_fails_closed('\xff\xff\xff\x7f', false, pending)
		reply_test_fails_closed('', true, pending)
	}
}

fn test_public_receive_timeout_does_not_gain_control_idle_semantics() {
	pair := reply_test_pair()
	defer {
		desktop_close(pair[0])
		desktop_close(pair[1])
	}
	session_receive_timeout(pair[0], 20) or {
		assert err !is SessionReplyNotStarted
		assert err.msg() == 'session request timed out'
		session_discard_error(err)
		return
	}
	assert false
}

fn test_actual_read_error_closes_pending_control() {
	pair := reply_test_pair()
	reply_test_control(pair[0])
	session_control_reply_pending = true
	// An invalid descriptor must never be mistaken for an idle timeout.
	desktop_close(pair[0])
	defer { desktop_close(pair[1]); session_close_control() }
	session_request('must not send', 20) or {
		assert err !is SessionReplyNotStarted
		session_discard_error(err)
		assert !session_has_control()
		assert !session_control_reply_pending
		return
	}
	assert false
}

fn test_public_request_timeout_closes_its_connection() {
	session_close_control()
	previous := os.getenv_opt('VINIX_SESSION_RUNTIME')
	// Keep the Unix socket path below SessionAddress's fixed path limit.
	base := os.join_path(os.temp_dir(), 'p-${C.getpid()}')
	os.mkdir_all(base) or { panic(err) }
	os.setenv('VINIX_SESSION_RUNTIME', base, true)
	defer {
		if value := previous {
			os.setenv('VINIX_SESSION_RUNTIME', value, true)
		} else {
			os.unsetenv('VINIX_SESSION_RUNTIME')
		}
		os.rmdir_all(base) or {}
	}
	directory := session_runtime_directory()
	assert session_private_directory(directory)
	path := '${directory}/broker'
	addr := session_address(path) or { panic('test socket path too long') }
	listener := C.socket(C.AF_UNIX, C.SOCK_STREAM, 0)
	assert listener >= 3
	defer { desktop_close(listener) }
	assert C.bind(listener, voidptr(&addr), u32(sizeof(SessionAddress))) == 0
	assert C.listen(listener, 1) == 0
	gate := reply_test_pair()
	child := C.fork()
	assert child >= 0
	if child == 0 {
		desktop_close(gate[0])
		fd := C.accept(listener, unsafe { nil }, unsafe { nil })
		if fd < 0 { C._exit(31) }
		request := session_receive_timeout(fd, 2000) or { C._exit(32); return }
		if request != 'public' { C._exit(33) }
		session_receive_timeout(gate[1], 2000) or { C._exit(34); return }
		mut byte := u8(0)
		if C.recv(fd, &byte, 1, 0) != 0 { C._exit(35) }
		C._exit(0)
	}
	desktop_close(gate[1])
	defer { desktop_close(gate[0]) }
	mut failed := false
	session_request('public', 20) or {
		assert err !is SessionReplyNotStarted
		session_discard_error(err)
		failed = true
	}
	assert failed
	assert !session_has_control()
	assert !session_control_reply_pending
	assert session_send_message(gate[0], 'check eof')
	mut status := i32(-1)
	assert C.waitpid(child, &status, 0) == child
	assert status == 0
}

fn test_fork_does_not_inherit_control_authority() {
	pair := reply_test_pair()
	reply_test_control(pair[0])
	session_control_reply_pending = true
	defer { desktop_close(pair[1]); session_close_control() }
	child := C.fork()
	assert child >= 0
	if child == 0 {
		C._exit(if session_has_control() { 21 } else { 0 })
	}
	mut status := i32(-1)
	assert C.waitpid(child, &status, 0) == child
	assert status == 0
	assert session_has_control()
	assert session_control_reply_pending
}

fn test_close_resets_outstanding_and_startup_is_distinct() {
	pair := reply_test_pair()
	reply_test_control(pair[0])
	defer { desktop_close(pair[1]); session_close_control() }
	session_control_pending = true
	session_request('not ready', 20) or {
		assert err.msg() == 'session services starting'
		session_discard_error(err)
	}
	assert session_control_pending
	assert !session_control_reply_pending
	assert session_send_message(pair[1], 'invalid ready')
	session_request('not ready', 20) or { session_discard_error(err) }
	assert !session_has_control()
	assert !session_control_pending
	assert !session_control_reply_pending
	session_control_reply_pending = true
	session_close_control()
	assert !session_control_reply_pending
}
