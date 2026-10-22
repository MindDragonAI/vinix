// SPDX-License-Identifier: GPL-2.0-or-later
module main

import os
import time

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <stdio.h>

// Fixed stack storage and literal labels only: diagnostics must not retain V
// interpolation temporaries in a -gc none worker, or disclose peer contents.
fn diagnostic_write(data &char, n int) {
	code := C.errno
	if n > 0 { C.write(2, data, usize(if n < 2048 { n } else { 2047 })) }
	C.errno = code
}

fn diagnostic_io(op string, fd int, code int, result i64, done int, wanted int) {
	saved := C.errno
	mut line := [2048]char{}
	n := unsafe { C.snprintf(&line[0], 2048, c'vinix-sshd-diag event=fd-io op=%s fd=%lld errno=%lld result=%lld partial=%lld requested=%lld\n',
		op.str, i64(fd), i64(code), result, i64(done), i64(wanted)) }
	diagnostic_write(&line[0], n)
	C.errno = saved
}

fn diagnostic_worker(pid int, status i32, started u64) {
	saved := C.errno
	mut line := [2048]char{}
	n := unsafe { C.snprintf(&line[0], 2048, c'vinix-sshd-diag event=session-worker-exit pid=%lld raw_status=%lld elapsed_ms=%llu\n',
		i64(pid), i64(status), u64((time.sys_mono_now() - started) / 1000000)) }
	diagnostic_write(&line[0], n)
	C.errno = saved
}

fn C.mmap(voidptr, usize, int, int, int, i64) voidptr
fn C.munmap(voidptr, usize) int

struct C.stat {
	st_mode u32
	st_uid  u32
	st_size i64
}

struct C.pollfd {
mut:
	fd      i32
	events  i16
	revents i16
}

fn C.open(&char, int, ...int) int
fn C.openat(int, &char, int, ...voidptr) int
fn C.mkdirat(int, &char, u32) int
fn C.fstat(int, &C.stat) int
fn C.fchmod(int, u32) int
fn C.fsync(int) int
fn C.linkat(int, &char, int, &char, int) int
fn C.unlinkat(int, &char, int) int
fn C.read(int, voidptr, usize) int
fn C.write(int, voidptr, usize) isize
fn C.close(int) int
fn C.S_ISREG(u32) int
fn C.S_ISDIR(u32) int
fn C.poll(&C.pollfd, usize, int) int
fn C.fork() int
fn C.waitpid(int, &i32, int) int
fn C.kill(int, int) int
fn C.pipe(&i32) int
fn C.dup2(int, int) int
fn C.execve(&char, voidptr, voidptr) int
fn C.chdir(&char) int
fn C._exit(int)
fn C.fcntl(int, int, ...voidptr) int
fn C.getuid() u32
fn C.getpid() int
fn C.signal(int, voidptr) voidptr
fn C.setsid() int

struct Child {
mut:
	pid    int = -1
	input  int = -1
	output int = -1
	errors int = -1
	reaped bool
	status i32
	// Last waitpid observation, including failures; status is valid only if reaped.
	wait_result int
	wait_errno int
}

fn nonblock(fd int) ! {
	flags := C.fcntl(fd, C.F_GETFL)
	if flags < 0 { return error('fcntl GETFL fd=${fd} errno=${C.errno}') }
	if C.fcntl(fd, C.F_SETFL, flags | C.O_NONBLOCK) != 0 {
		return error('fcntl SETFL fd=${fd} errno=${C.errno}')
	}
}

fn pipe_child(argv []string, environment []string, home string) !Child {
	mut args := []&char{}
	mut env := []&char{}
	for a in argv { args << &char(a.str) }
	for e in environment { env << &char(e.str) }
	args << &char(unsafe { nil })
	env << &char(unsafe { nil })
	// POSIX writes two C ints. This compiler's V int is 64-bit: [2]int would
	// put both descriptors in element zero and leave the second descriptor zero.
	mut input := [2]i32{}
	mut output := [2]i32{}
	mut errors := [2]i32{}
	if C.pipe(unsafe { &input[0] }) != 0 { return error('stdin pipe errno=${C.errno}') }
	if C.pipe(unsafe { &output[0] }) != 0 {
		C.close(input[0])
		C.close(input[1])
		return error('stdout pipe errno=${C.errno}')
	}
	if C.pipe(unsafe { &errors[0] }) != 0 {
		for fd in [input[0], input[1], output[0], output[1]] { C.close(fd) }
		return error('stderr pipe errno=${C.errno}')
	}
	// Enumerate before fork. Child performs no V allocation or GC operation.
	mut inherited := []int{}
	$if !linux {
		names := os.ls('/dev/fd') or {
			for fd in [input[0], input[1], output[0], output[1], errors[0], errors[1]] {
				C.close(fd)
			}
			return err
		}
		for name in names { if name.int() > 2 { inherited << name.int() } }
	}
	pid := C.fork()
	if pid == 0 {
		if C.setsid() < 0 || C.dup2(input[0], 0) < 0 || C.dup2(output[1], 1) < 0 || C.dup2(errors[1], 2) < 0 {
			C._exit(126)
		}
		$if linux {
			if unsafe { C.syscall(C.SYS_close_range, u32(3), u32(-1), u32(0)) } != 0 {
				C._exit(126)
			}
		} $else {
			for fd in inherited { C.close(fd) }
		}
		if C.chdir(home.str) != 0 { C._exit(126) }
		C.execve(argv[0].str, args.data, env.data)
		C._exit(127)
	}
	C.close(input[0])
	C.close(output[1])
	C.close(errors[1])
	mut child := Child{ pid: pid, input: input[1], output: output[0], errors: errors[0] }
	if pid < 0 {
		code := C.errno
		child.cleanup()
		return error('fork failed errno=${code}')
	}
	nonblock(child.input) or {
		child.cleanup()
		return err
	}
	nonblock(child.output) or {
		child.cleanup()
		return err
	}
	nonblock(child.errors) or {
		child.cleanup()
		return err
	}
	return child
}

fn (mut c Child) reap() {
	if c.pid > 0 && !c.reaped {
		result := C.waitpid(c.pid, &c.status, C.WNOHANG)
		code := if result < 0 { int(C.errno) } else { 0 }
		c.wait_result = result
		c.wait_errno = code
		if result == c.pid { c.reaped = true }
	}
}

// A child may close stdin and continue producing stdout/stderr. Keep those
// descriptors alive until drained, including when the leader has exited.
fn (mut c Child) close_input() {
	if c.input >= 0 && c.input != c.output && c.input != c.errors { C.close(c.input) }
	c.input = -1
}

fn (mut c Child) cleanup() {
	if c.input >= 0 { C.close(c.input) }
	if c.output >= 0 && c.output != c.input { C.close(c.output) }
	if c.errors >= 0 && c.errors != c.input && c.errors != c.output { C.close(c.errors) }
	c.input = -1
	c.output = -1
	c.errors = -1
	if c.pid <= 0 { return }
	// Also kill descendants still holding output pipes after leader exit.
	C.kill(-c.pid, C.SIGTERM)
	if !c.reaped { C.kill(c.pid, C.SIGTERM) }
	for _ in 0 .. 20 {
		c.reap()
		if c.reaped { break }
		time.sleep(10 * time.millisecond)
	}
	C.kill(-c.pid, C.SIGKILL)
	if !c.reaped {
		C.kill(c.pid, C.SIGKILL)
		for {
			result := C.waitpid(c.pid, &c.status, 0)
			code := if result < 0 { int(C.errno) } else { 0 }
			c.wait_result = result
			c.wait_errno = code
			if result == c.pid || (result < 0 && code == C.ECHILD) {
				c.reaped = true
				break
			}
			if result < 0 && code != C.EINTR { break }
		}
	}
}

fn read_exact_fd(fd int, n int) ![]u8 {
	if n < 0 || n > max_packet { return error('read bound') }
	mut data := []u8{len: n}
	read_into_fd(fd, mut data) or {
		unsafe { data.free() }
		return err
	}
	return data
}

fn read_into_fd(fd int, mut data []u8) ! {
	mut pos := 0
	for pos < data.len {
		count := unsafe { C.read(fd, &data[pos], usize(data.len - pos)) }
		code := if count < 0 { int(C.errno) } else { 0 }
		if count < 0 && code == C.EINTR { continue }
		if count <= 0 {
			diagnostic_io('read', fd, code, i64(count), pos, data.len)
			return error('short read')
		}
		pos += int(count)
	}
}

fn write_fd(fd int, data []u8) ! {
	mut pos := 0
	for pos < data.len {
		n := unsafe { C.write(fd, &data[pos], usize(data.len - pos)) }
		code := if n < 0 { int(C.errno) } else { 0 }
		if n < 0 && code == C.EINTR { continue }
		if n <= 0 {
			diagnostic_io('write', fd, code, i64(n), pos, data.len)
			return error('write failed')
		}
		pos += int(n)
	}
}

// Open every path component relative to an already-open directory, refusing
// symlinks at every level. The returned descriptor owns the final component.
fn open_directory(path string) !int {
	if !path.starts_with('/') || path.contains('\x00') {
		return error('absolute directory required')
	}
	mut fd := C.open(c'/', C.O_RDONLY | C.O_DIRECTORY | C.O_CLOEXEC)
	if fd < 0 { return error('open root') }
	for part in path.split('/') {
		if part == '' { continue }
		if part == '.' || part == '..' {
			C.close(fd)
			return error('unsafe path component')
		}
		next := C.openat(fd, part.str, C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW | C.O_CLOEXEC)
		C.close(fd)
		if next < 0 { return error('cannot open directory without symlinks') }
		fd = next
	}
	return fd
}
