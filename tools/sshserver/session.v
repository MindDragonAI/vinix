// SPDX-License-Identifier: GPL-2.0-or-later
module main

import os
import math
import desktop.ptycore

const channel_window = 262144
const channel_packet = 32768

struct Channel {
mut:
	opened         bool
	remote         u32
	window         u32
	packet         u32
	receive_window u32 = channel_window
	pending        []u8
	eof            bool
	input_closed   bool
	pty            bool
	term           string = 'xterm'
	rows           int    = 24
	columns        int    = 80
	width          int
	height         int
	environment    []string
	child          Child
	started        bool
}

fn channel_message(id u8, remote u32) []u8 {
	mut p := [id]
	put_u32(mut p, remote)
	return p
}

fn (mut t Transport) channel_reply(c Channel, ok bool) ! {
	t.send(channel_message(if ok { u8(99) } else { u8(100) }, c.remote))!
}

fn (mut c Channel) launch(config Config, command string, shell bool) ! {
	mut argv := ['/bin/sh']
	if !shell {
		if command.starts_with('scp ') {
			parsed := parse_scp_command(command)!
			argv = [os.executable(), '--scp']
			argv << parsed
		} else {
			argv << '-c'
			argv << command
		}
	}
	mut env := ['PATH=/usr/bin:/bin:/usr/sbin:/sbin', 'HOME=${config.home}', 'USER=${config.user}',
		'LOGNAME=${config.user}', 'SHELL=/bin/sh', 'TERM=${c.term}']
	env << c.environment
	if c.pty {
		p := ptycore.spawn(argv, env, config.home, c.rows, c.columns, c.width, c.height)!
		c.child = Child{ pid: p.pid, input: p.terminal, output: p.terminal }
	} else {
		c.child = pipe_child(argv, env, config.home)!
	}
	c.started = true
}

fn (mut t Transport) handle_channel(mut c Channel, config Config, packet []u8) !bool {
	mut r := Reader{ data: packet }
	id := r.byte()!
	if id == 80 {
		_ := r.string_bytes(128)!
		want := r.byte()!
		if want > 1 { return error('invalid global request boolean') }
		if want == 1 { t.send([u8(82)])! }
		return true
	}
	if id == 90 {
		kind := r.string_bytes(64)!.bytestr()
		remote := r.uint()!
		window := r.uint()!
		maximum := r.uint()!

		if c.opened || kind != 'session' || maximum == 0 {
			mut p := channel_message(92, remote)
			put_u32(mut p, 1)
			put_string(mut p, 'only one session channel supported'.bytes())
			put_string(mut p, []u8{})
			t.send(p)!
			return true
		}
		r.end()!
		c.opened = true
		c.remote = remote
		c.window = window
		c.packet = maximum
		mut p := channel_message(91, remote)
		put_u32(mut p, 0)
		put_u32(mut p, channel_window)
		put_u32(mut p, channel_packet)
		t.send(p)!
		return true
	}
	if !c.opened || r.uint()! != 0 { return error('invalid channel recipient') }
	match id {
		93 {
			increment := r.uint()!
			r.end()!
			if increment == 0 || increment > u32(0xffffffff) - c.window {
				return error('channel window overflow')
			}
			c.window += increment
		}
		94 {
			data := r.string_bytes(channel_packet)!
			r.end()!
			if !c.started || c.eof || data.len > int(c.receive_window) || c.pending.len + data.len > channel_window {
				return error('channel input window violation')
			}
			c.receive_window -= u32(data.len)
			c.pending << data
		}
		96 {
			r.end()!
			c.eof = true
		}
		97 {
			r.end()!
			t.send(channel_message(97, c.remote))!
			return false
		}
		98 {
			request := r.string_bytes(64)!.bytestr()

			want := r.byte()!
			if want > 1 { return error('invalid channel request') }
			mut ok := false
			match request {
				'pty-req' {
					term := r.string_bytes(128)!.bytestr()
					columns := r.uint()!
					rows := r.uint()!
					width := r.uint()!
					height := r.uint()!
					modes := r.string_bytes(4096)!
					r.end()!
					// Validate opcode framing even though the initial implementation uses
					// the platform PTY defaults rather than applying client termios modes.
					mut mr := Reader{ data: modes }
					// A forced PTY with piped stdin has no local termios or geometry.
					// RFC 4254 permits an empty modes string and zero dimensions.
					mut ended := modes.len == 0
					for mr.pos < modes.len {
						op := mr.byte()!
						if op == 0 {
							mr.end()!
							ended = true
							break
						}
						if op >= 160 {
							ended = true
							break
						}
						_ := mr.uint()!
					}
					if !c.started && !c.pty && ended && term.len > 0 && !term.contains('\x00')
						&& rows <= 65535 && columns <= 65535 && width <= 65535 && height <= 65535 {
						c.pty = true
						c.term = term
						c.rows = if rows == 0 { 24 } else { int(rows) }
						c.columns = if columns == 0 { 80 } else { int(columns) }
						c.width = int(width)
						c.height = int(height)
						ok = true
					}
				}
				'window-change' {
					columns := r.uint()!
					rows := r.uint()!
					width := r.uint()!
					height := r.uint()!
					r.end()!
					if c.pty && columns > 0 && rows > 0 && columns <= 65535 && rows <= 65535 && width <= 65535 && height <= 65535 {
						c.columns = int(columns)
						c.rows = int(rows)
						c.width = int(width)
						c.height = int(height)
						ok = !c.started || ptycore.resize(c.child.output, int(rows), int(columns), int(width), int(height))
					}
				}
				'env' {
					name := r.string_bytes(64)!.bytestr()
					value := r.string_bytes(1024)!.bytestr()
					r.end()!
					if !c.started && c.environment.len < 16 && name in ['LANG', 'LC_ALL', 'LC_CTYPE'] && !value.contains('\x00') {
						c.environment << '${name}=${value}'
						ok = true
					}
				}
				'shell', 'exec' {
					command := if request == 'exec' {
						r.string_bytes(max_command)!.bytestr()
					} else {
						''
					}
					r.end()!
					if !c.started && !command.contains('\x00') {
						c.launch(config, command, request == 'shell') or {
							eprintln('vinix-sshd: child launch failed: ${err}')
							if want == 1 { t.channel_reply(c, false)! }
							return true
						}
						ok = true
					}
				}
				else {} // subsystem, forwarding and unknown requests are denied.
			}
			if want == 1 { t.channel_reply(c, ok)! }
		}
		else { return error('unsupported channel message') }
	}
	return true
}

fn (mut t Transport) session_loop(config Config) ! {
	mut c := Channel{}
	defer { c.child.cleanup() }
	for {
		t.limits()!
		c.child.reap()
		if c.started && c.child.reaped && c.child.output < 0 && c.child.errors < 0 {
			mut status := channel_message(98, c.remote)
			put_string(mut status, 'exit-status'.bytes())
			status << u8(0)
			code := if c.child.status & 127 == 0 {
				u32((c.child.status >> 8) & 255)
			} else {
				u32(128 + (c.child.status & 127))
			}
			put_u32(mut status, code)
			t.send(status)!
			t.send(channel_message(96, c.remote))!
			t.send(channel_message(97, c.remote))!
			return
		}
		mut fds := [C.pollfd{ fd: t.socket.sock.handle, events: C.POLLIN },
			C.pollfd{ fd: if c.window > 0 { c.child.output } else { -1 }, events: C.POLLIN },
			C.pollfd{ fd: if c.window > 0 { c.child.errors } else { -1 }, events: C.POLLIN },
			C.pollfd{ fd: if c.pending.len > 0 || (c.eof && !c.input_closed) {
				c.child.input
			} else {
				-1
			}, events: C.POLLOUT }]
		n := unsafe { C.poll(&fds[0], usize(fds.len), 100) }
		if n < 0 {
			if C.errno == C.EINTR { continue }
			return error('poll failed')
		}
		if fds[0].revents & (C.POLLIN | C.POLLHUP | C.POLLERR) != 0 {
			if !t.handle_channel(mut c, config, t.next()!)! { return }
		}
		if c.pending.len > 0 && fds[3].revents & C.POLLOUT != 0 {
			sent := C.write(c.child.input, c.pending.data, usize(c.pending.len))
			if sent > 0 {
				c.pending = c.pending[int(sent)..].clone()
				c.receive_window += u32(sent)
				mut adjust := channel_message(93, c.remote)
				put_u32(mut adjust, u32(sent))
				t.send(adjust)!
			} else if sent < 0 && C.errno !in [C.EAGAIN, C.EINTR] {
				c.child.close_input()
				c.input_closed = true
			}
		}
		if !c.pty && fds[3].revents & (C.POLLHUP | C.POLLERR | C.POLLNVAL) != 0 {
			c.child.close_input()
			c.input_closed = true
		}
		// Return credit for input discarded after the child closes its read end.
		// An EPIPE must not throw away already-buffered child output or exit status.
		if c.input_closed && c.pending.len > 0 {
			credit := u32(c.pending.len)
			c.pending = []u8{}
			c.receive_window += credit
			mut adjust := channel_message(93, c.remote)
			put_u32(mut adjust, credit)
			t.send(adjust)!
		}
		if c.eof && c.pending.len == 0 && !c.input_closed && c.started {
			if c.pty {
				// The PTY is nonblocking. Retry an EAGAIN on the next writable poll.
				if fds[3].revents & C.POLLOUT != 0 {
					eot := u8(4)
					sent := C.write(c.child.input, unsafe { &eot }, 1)
					if sent == 1 {
						c.input_closed = true
					} else if sent < 0 && C.errno !in [C.EAGAIN, C.EINTR] {
						c.input_closed = true
					}
				}
			} else {
				c.child.close_input()
				c.input_closed = true
			}
		}
		for index in [1, 2] {
			fd := if index == 1 { c.child.output } else { c.child.errors }
			if fd < 0 || c.window == 0 || fds[index].revents & (C.POLLIN | C.POLLHUP | C.POLLERR) == 0 {
				continue
			}
			size := int(math.min(u32(channel_packet), math.min(c.window, c.packet)))
			mut buffer := []u8{len: size}
			got := C.read(fd, buffer.data, usize(size))
			if got > 0 {
				mut p := channel_message(if index == 1 { u8(94) } else { u8(95) }, c.remote)
				if index == 2 { put_u32(mut p, 1) }
				put_string(mut p, buffer[..int(got)])
				t.send(p)!
				c.window -= u32(got)
			} else if got == 0 || (got < 0 && C.errno !in [C.EAGAIN, C.EINTR]) {
				C.close(fd)
				if index == 1 {
					c.child.output = -1
					if c.pty { c.child.input = -1 }
				} else {
					c.child.errors = -1
				}
			}
		}
	}
}
