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
	diag_input     u64
	diag_output    u64
	diag_errors    u64
	diag_discarded u64
	diag_op        string = 'channel-start'
	diag_close     string = 'session-complete'
}

fn channel_message(id u8, remote u32) []u8 {
	mut p := []u8{cap: 32}
	p << id
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
	c.diag_op = 'channel-decode'
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
		c.diag_op = 'channel-open'
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
		t.diag_remote = remote
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
			c.diag_op = 'channel-window-adjust'
			increment := r.uint()!
			r.end()!
			if increment == 0 || increment > u32(0xffffffff) - c.window {
				return error('channel window overflow')
			}
			c.window += increment
		}
		94 {
			c.diag_op = 'channel-input'
			data := r.string_view(channel_packet)!
			r.end()!
			if !c.started || c.eof || data.len > int(c.receive_window) || c.pending.len + data.len > channel_window {
				return error('channel input window violation')
			}
			c.receive_window -= u32(data.len)
			c.pending << data
		}
		96 {
			c.diag_op = 'peer-eof'
			r.end()!
			if !c.eof { t.diagnostic('peer-eof', &c, false) }
			c.eof = true
		}
		97 {
			c.diag_op = 'peer-close'
			r.end()!
			t.diagnostic('peer-channel-close', &c, false)
			t.send(channel_message(97, c.remote))!
			return false
		}
		98 {
			c.diag_op = 'channel-request'
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
					if !c.started && !c.pty && ended && !term.contains('\x00')
						&& rows <= 65535 && columns <= 65535 && width <= 65535 && height <= 65535 {
						c.pty = true
						// OpenSSH sends an empty terminal type when TERM is unset,
						// including the acceptance worker's stripped environment.
						// Keep the channel's default in that case.
						if term.len > 0 { c.term = term }
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
						c.diag_op = 'child-launch'
						c.launch(config, command, request == 'shell') or {
							t.diagnostic('child-launch-error', &c, false)
							eprintln('vinix-sshd: child launch failed: ${err}')
							if want == 1 { t.channel_reply(c, false)! }
							return true
						}
						ok = true
						t.diagnostic('child-start', &c, false)
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
	mut c := Channel{ pending: []u8{cap: channel_window} }
	defer { unsafe { c.pending.free() } }
	defer {
		c.child.cleanup()
		if c.started { t.diagnostic('child-cleanup', &c, true) }
	}
	mut outcome := 'session-error'
	// Registered after cleanup: snapshot the failing state before cleanup closes
	// descriptors, discards input or terminates/reaps the child.
	defer { t.diagnostic(outcome, &c, true) }
	t.session_run(mut c, config) or {
		t.diagnostic_error(err)
		return err
	}
	outcome = c.diag_close
}

fn (mut t Transport) session_run(mut c Channel, config Config) ! {
	mut buffer := []u8{len: channel_packet}
	defer { unsafe { buffer.free() } }
	for {
		c.diag_op = 'session-limits'
		t.limits()!
		c.diag_op = 'waitpid'
		was_reaped := c.child.reaped
		c.child.reap()
		if !was_reaped && c.child.reaped { t.diagnostic('child-exit', &c, false) }
		if c.started && c.child.reaped && c.child.output < 0 && c.child.errors < 0 {
			c.diag_op = 'local-exit-status-eof-close'
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
			c.diag_close = 'local-channel-close-child-exit'
			return
		}
		mut fds := [C.pollfd{ fd: t.socket.sock.handle, events: C.POLLIN },
			C.pollfd{ fd: if c.window > 0 { c.child.output } else { -1 }, events: C.POLLIN },
			C.pollfd{ fd: if c.window > 0 { c.child.errors } else { -1 }, events: C.POLLIN },
			C.pollfd{ fd: if c.pending.len > 0 || (c.eof && !c.input_closed) {
				c.child.input
			} else {
				-1
			}, events: C.POLLOUT }]!
		c.diag_op = 'session-poll'
		n := unsafe { C.poll(&fds[0], usize(fds.len), 100) }
		poll_code := if n < 0 { int(C.errno) } else { 0 }
		if n < 0 {
			if poll_code == C.EINTR { continue }
			t.diagnostic_operation('poll', i64(n), poll_code, 0, fds.len)
			return error('poll failed')
		}
		if fds[0].revents & (C.POLLIN | C.POLLHUP | C.POLLERR) != 0 {
			c.diag_op = 'network-next'
			packet := t.next()!
			keep := t.handle_channel(mut c, config, packet) or {
				unsafe { packet.free() }
				return err
			}
			unsafe { packet.free() }
			if !keep { c.diag_close = 'peer-channel-close'; return }
		}
		if c.pending.len > 0 && fds[3].revents & C.POLLOUT != 0 {
			c.diag_op = 'child-input-write'
			sent := C.write(c.child.input, c.pending.data, usize(c.pending.len))
			code := if sent < 0 { int(C.errno) } else { 0 }
			if sent > 0 {
				c.diag_input += u64(sent)
				// delete_many compacts in place and retains the bounded allocation.
				c.pending.delete_many(0, int(sent))
				c.receive_window += u32(sent)
				mut adjust := channel_message(93, c.remote)
				defer { unsafe { adjust.free() } }
				put_u32(mut adjust, u32(sent))
				t.send(adjust)!
			} else if sent < 0 && code !in [C.EAGAIN, C.EINTR] {
				t.diagnostic_operation('child-input-write', i64(sent), code, 0, c.pending.len)
				t.diagnostic('child-input-error', &c, false)
				c.child.close_input()
				c.input_closed = true
			}
		}
		if !c.pty && fds[3].revents & (C.POLLHUP | C.POLLERR | C.POLLNVAL) != 0 {
			if !c.input_closed {
				c.diag_op = 'child-input-poll-close'
				t.diagnostic_operation('child-input-poll', i64(fds[3].revents), 0, 0, c.pending.len)
				t.diagnostic('child-input-poll-close', &c, false)
			}
			c.child.close_input()
			c.input_closed = true
		}
		// Return credit for input discarded after the child closes its read end.
		// An EPIPE must not throw away already-buffered child output or exit status.
		if c.input_closed && c.pending.len > 0 {
			credit := u32(c.pending.len)
			c.diag_discarded += u64(credit)
			c.pending.clear()
			c.receive_window += credit
			mut adjust := channel_message(93, c.remote)
			defer { unsafe { adjust.free() } }
			put_u32(mut adjust, credit)
			t.send(adjust)!
		}
		if c.eof && c.pending.len == 0 && !c.input_closed && c.started {
			if c.pty {
				// The PTY is nonblocking. Retry an EAGAIN on the next writable poll.
				if fds[3].revents & C.POLLOUT != 0 {
					eot := u8(4)
					c.diag_op = 'child-input-eot'
					sent := C.write(c.child.input, unsafe { &eot }, 1)
					code := if sent < 0 { int(C.errno) } else { 0 }
					if sent == 1 {
						c.diag_input++
						c.input_closed = true
					} else if sent < 0 && code !in [C.EAGAIN, C.EINTR] {
						t.diagnostic_operation('child-input-eot', i64(sent), code, 0, 1)
						t.diagnostic('child-eot-error', &c, false)
						c.input_closed = true
					}
				}
			} else {
				c.diag_op = 'child-input-peer-eof'
				t.diagnostic('child-input-peer-eof', &c, false)
				c.child.close_input()
				c.input_closed = true
			}
		}
		for index in [1, 2]! {
			fd := if index == 1 { c.child.output } else { c.child.errors }
			if fd < 0 || c.window == 0 || fds[index].revents & (C.POLLIN | C.POLLHUP | C.POLLERR) == 0 {
				continue
			}
			size := int(math.min(u32(channel_packet), math.min(c.window, c.packet)))
			c.diag_op = if index == 1 { 'child-stdout-read' } else { 'child-stderr-read' }
			got := C.read(fd, buffer.data, usize(size))
			code := if got < 0 { int(C.errno) } else { 0 }
			if got > 0 {
				if index == 1 { c.diag_output += u64(got) } else { c.diag_errors += u64(got) }
				// Reserve header + payload up front: no abandoned growth buffers.
				mut p := []u8{cap: int(got) + 13}
				defer { unsafe { p.free() } }
				p << if index == 1 { u8(94) } else { u8(95) }
				put_u32(mut p, c.remote)
				if index == 2 { put_u32(mut p, 1) }
				put_string(mut p, buffer[..int(got)])
				t.send(p)!
				c.window -= u32(got)
			} else if got == 0 || (got < 0 && code !in [C.EAGAIN, C.EINTR]) {
				t.diagnostic_operation(c.diag_op, i64(got), code, 0, size)
				t.diagnostic(if got == 0 { 'child-output-eof' } else { 'child-output-error' }, &c, false)
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
