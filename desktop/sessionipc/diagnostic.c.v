// SPDX-License-Identifier: GPL-2.0-or-later
module sessionipc

#include <stdio.h>

// Qualification-only transport evidence. Never include request/reply contents.
fn session_transport_diagnostic(op string, fd int, result int, code int, done int, wanted int, elapsed i64) {
	$if ssh_transfer_diagnostics ? {
		saved := C.errno
		mut line := [512]char{}
		n := unsafe { C.snprintf(&line[0], 512, c'M16B3-IPC op=%s fd=%lld result=%lld errno=%lld done=%lld wanted=%lld elapsed_ms=%lld\n',
			op.str, i64(fd), i64(result), i64(code), i64(done), i64(wanted), elapsed) }
		serial := C.open(c'/dev/com1', C.O_WRONLY | C.O_NOCTTY)
		if serial >= 0 {
			if n > 0 { C.write(serial, &line[0], usize(if n < 512 { n } else { 511 })) }
			C.close(serial)
		}
		C.errno = saved
	}
}
