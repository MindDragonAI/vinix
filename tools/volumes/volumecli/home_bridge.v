// SPDX-License-Identifier: GPL-2.0-or-later
module volumecli

// Only fixed C-string formats and nonsecret syscall results belong here.
fn home_session_note(format &char, value i32) {
	$if home_test_bridge ? {
		saved := unsafe { C.errno }
		fd := C.open(c'/dev/com1', C.O_WRONLY | C.O_CLOEXEC | C.O_NOFOLLOW)
		if fd >= 0 {
			mut message := [160]char{}
			n := C.snprintf(&message[0], 160, format, value)
			if n > 0 && n < 160 { C.write(fd, &message[0], usize(n)) }
			C.close(fd)
		}
		unsafe { C.errno = saved }
	}
}

fn home_activation_failed(stage string) bool {
	$if home_test_bridge ? {
		saved := unsafe { C.errno }
		fd := C.open(c'/dev/com1', C.O_WRONLY | C.O_CLOEXEC | C.O_NOFOLLOW)
		if fd >= 0 {
			mut message := [160]char{}
			n := C.snprintf(&message[0], 160, c'HOME-ACTIVATION: %s errno=%d\n', unsafe { &stage[0] }, saved)
			if n > 0 && n < 160 { C.write(fd, &message[0], usize(n)) }
			C.close(fd)
		}
		unsafe { C.errno = saved }
	}
	return false
}

// Explicit qualification builds only. COM2 is a private, unrecorded Unix UART
// socket owned by the disposable test controller. Production staging never
// enables this define. No credential is written to a file, log or argument.
fn home_test_event(op u32, bytes &u8, size int) bool {
	$if home_test_bridge ? {
		status := C.open(c'/dev/com1', C.O_WRONLY | C.O_CLOEXEC | C.O_NOFOLLOW)
		if status >= 0 {
			message := c'HOME-TEST: UI telemetry event\n'
			C.write(status, message, C.strlen(message))
			C.close(status)
		}
		fd := C.open(c'/dev/com2', C.O_WRONLY | C.O_CLOEXEC | C.O_NOFOLLOW)
		if fd < 0 { return false }
		defer { C.close(fd) }
		// UART firmware/initialization can precede userspace. Synchronize on
		// a fixed nonsecret magic instead of interpreting that traffic as a frame.
		return home_transfer(fd, unsafe { &u8(c'M14A-HM1') }, 8, true)
			&& home_send(fd, op, bytes, size)
	} $else {
		return true
	}
}
