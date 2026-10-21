// SPDX-License-Identifier: GPL-2.0-or-later
module volumecli

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
