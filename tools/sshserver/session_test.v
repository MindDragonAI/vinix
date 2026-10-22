module main

import os

fn test_pipe_exec_eof_drains_both_streams_and_reaps() {
	mut child := pipe_child(['/bin/sh', '-c', 'cat; printf tail; printf diagnostic >&2; exit 7'],
		['PATH=/usr/bin:/bin'], os.getwd()) or { panic(err) }
	defer { child.cleanup() }
	write_fd(child.input, 'input'.bytes()) or { panic(err) }
	child.close_input()
	mut output := []u8{}
	mut errors := []u8{}
	for _ in 0 .. 100 {
		child.reap()
		if child.reaped && child.output < 0 && child.errors < 0 { break }
		mut fds := [C.pollfd{ fd: child.output, events: C.POLLIN },
			C.pollfd{ fd: child.errors, events: C.POLLIN }]
		result := unsafe { C.poll(&fds[0], usize(fds.len), 20) }
		assert result >= 0 || C.errno == C.EINTR
		for index in 0 .. 2 {
			fd := if index == 0 { child.output } else { child.errors }
			if fd < 0 || fds[index].revents & (C.POLLIN | C.POLLHUP | C.POLLERR) == 0 { continue }
			mut data := []u8{len: 128}
			got := C.read(fd, data.data, usize(data.len))
			if got > 0 {
				if index == 0 { output << data[..int(got)] } else { errors << data[..int(got)] }
			} else if got == 0 {
				C.close(fd)
				if index == 0 { child.output = -1 } else { child.errors = -1 }
			} else {
				assert C.errno in [C.EAGAIN, C.EINTR]
			}
		}
	}
	child.reap()
	assert child.reaped
	assert child.status == 7 << 8
	assert output.bytestr() == 'inputtail'
	assert errors.bytestr() == 'diagnostic'
	assert child.output == -1 && child.errors == -1
}
