// SPDX-License-Identifier: GPL-2.0-or-later
module volumecli

// Explicit qualification builds only. COM2 is a private, unrecorded Unix UART
// socket owned by the disposable test controller. Production staging never
// enables this define. No credential is written to a file, log or argument.
fn home_test_event(op u32, bytes &u8, size int) bool {
	$if home_test_bridge ? {
		fd := C.open(c'/dev/com2', C.O_WRONLY | C.O_CLOEXEC | C.O_NOFOLLOW)
		if fd < 0 { return false }
		defer { C.close(fd) }
		return home_send(fd, op, bytes, size)
	} $else {
		return true
	}
}
