// SPDX-License-Identifier: GPL-2.0-or-later
// DIAGNOSTIC ONLY: replace vinix-desktop ONLY in a disposable test ISO.
module main

import desktop.sessiondaemon
import os
import net
import time

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

fn C.openat(int, &char, int, ...int) int
fn C.mkdirat(int, &char, u32) int
fn C.execv(&char, &&char) int
fn C.umask(u32) u32

fn private_dir(parent int, name string) !int {
	C.mkdirat(parent, &char(name.str), 0o700)
	fd := C.openat(parent, &char(name.str), C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW | C.O_CLOEXEC)
	if fd < 0 { return error('directory unavailable') }
	mut st := C.stat{}
	if C.fstat(fd, &st) != 0 || st.st_uid != 0 || u32(st.st_mode) & 0o7777 != 0o700 {
		C.close(fd)
		return error('unsafe directory ${name}')
	}
	return fd
}

fn create_private(parent int, name string, data string) ! {
	fd := C.openat(parent, &char(name.str), C.O_WRONLY | C.O_CREAT | C.O_EXCL | C.O_NOFOLLOW | C.O_CLOEXEC, 0o600)
	if fd < 0 { return error('seed destination must be new') }
	defer { C.close(fd) }
	mut pos := 0
	for pos < data.len {
		n := unsafe { C.write(fd, data.str + pos, usize(data.len - pos)) }
		if n <= 0 { return error('seed write failed') }
		pos += int(n)
	}
	if C.fsync(fd) != 0 { return error('seed sync failed') }
}

fn seed() ! {
	if !sessiondaemon.ssh_encrypted_home_ready() {
		mounts := os.read_file('/proc/self/mounts') or { '' }
		matched := mounts.contains('/dev/mapper/vinix63 /root ext2')
		serial_note('M16B-SEED: mapper mount substring=${matched}\n')
		fd := C.open(c'/root/.vinix-encrypted-home', C.O_RDONLY | C.O_NOFOLLOW | C.O_CLOEXEC)
		if fd >= 0 {
			mut st := C.stat{}
			status := C.fstat(fd, &st)
			serial_note('M16B-SEED: marker stat=${status} uid=${st.st_uid} mode=${st.st_mode} size=${st.st_size}\n')
			mut bytes := [64]u8{}
			n := C.read(fd, &bytes[0], 64)
			serial_note('M16B-SEED: marker bounded read=${n}\n')
			C.close(fd)
		}
		return error('encrypted home guard failed')
	}
	serial_note('M16B-SEED: HOME guard passed\n')
	C.umask(0o077)
	root := C.open(c'/root', C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW | C.O_CLOEXEC)
	if root < 0 { return error('root unavailable') }
	defer { C.close(root) }
	homes := private_dir(root, 'home')!
	defer { C.close(homes) }
	user := private_dir(homes, 'm16b')!
	defer { C.close(user) }
	ssh := private_dir(user, '.ssh')!
	defer { C.close(ssh) }
	// Public key only, bounded before heap allocation. No private seed is read.
	keyfd := C.open(c'/usr/share/vinix/m16b-client.pub', C.O_RDONLY | C.O_NOFOLLOW | C.O_CLOEXEC)
	if keyfd < 0 { return error('public key unavailable') }
	defer { C.close(keyfd) }
	mut buf := [1025]u8{}
	mut used := 0
	for used < buf.len {
		n := unsafe { C.read(keyfd, &buf[used], usize(buf.len - used)) }
		if n < 0 { return error('public key read failed') }
		if n == 0 { break }
		used += int(n)
	}
	if used < 80 || used > 1024 { return error('public key size invalid') }
	key := unsafe { tos(&buf[0], used) }
	if !key.starts_with('ssh-ed25519 ') || !key.ends_with('\n') || key.count('\n') != 1 {
		return error('public key format invalid')
	}
	create_private(ssh, 'authorized_keys', key)!
	create_private(root, '.vinix-ssh', 'm16b\n/root/home/m16b\n')!
	if !sessiondaemon.ssh_key_directory_ready() { return error('key directory unsafe') }
}

fn serial_note(message string) {
	fd := C.open(c'/dev/com1', C.O_WRONLY | C.O_CLOEXEC)
	if fd >= 0 { C.write(fd, message.str, usize(message.len)); C.close(fd) }
}

fn preunlock_probe() ! {
	serial_note('M16B-PREUNLOCK: entry\n')
	if sessiondaemon.ssh_encrypted_home_ready() { return error('HOME is already unlocked') }
	serial_note('M16B-PREUNLOCK: HOME locked\n')
	addresses := net.resolve_addrs('127.0.0.1:22', .ip, .tcp)!
	address := addresses[0]
	fd := C.socket(C.AF_INET, C.SOCK_STREAM, 0)
	if fd < 0 { return error('probe socket unavailable') }
	defer { C.close(fd) }
	flags := C.fcntl(fd, C.F_GETFL)
	if flags < 0 || C.fcntl(fd, C.F_SETFL, flags | C.O_NONBLOCK) != 0 { return error('probe nonblocking failed') }
	serial_note('M16B-PREUNLOCK: connecting\n')
	result := C.connect(fd, voidptr(&address), address.len())
	mut code := C.errno
	serial_note('M16B-PREUNLOCK: connect result=${result} errno=${code}\n')
	if result < 0 && code == C.EINPROGRESS {
		mut polling := C.pollfd{ fd: fd, events: C.POLLOUT }
		polled := C.poll(&polling, 1, 2000)
		serial_note('M16B-PREUNLOCK: poll result=${polled} revents=${polling.revents}\n')
		if polled <= 0 { return error('probe connect timeout') }
		mut socket_error := i32(0)
		mut length := u32(sizeof(i32))
		if C.getsockopt(fd, C.SOL_SOCKET, C.SO_ERROR, &socket_error, &length) != 0 { return error('probe socket status unavailable') }
		code = int(socket_error)
		serial_note('M16B-PREUNLOCK: socket error=${code}\n')
	}
	if result == 0 || code != C.ECONNREFUSED { return error('guest TCP refusal not proven') }
	mut banner := [256]u8{}
	if C.recv(fd, &banner[0], usize(banner.len), C.MSG_DONTWAIT) > 0 { return error('closed port returned banner data') }
	serial_note('M16B2-PREUNLOCK: errno=111 banner_bytes=0 auth_exchange=false\n')
	serial := C.open(c'/dev/com1', C.O_WRONLY | C.O_CLOEXEC)
	if serial < 0 { return error('serial receipt unavailable') }
	defer { C.close(serial) }
	message := 'M16B-PREUNLOCK: CONNECT_REFUSED locked_HOME=true\n'
	if C.write(serial, message.str, usize(message.len)) != message.len {
		return error('receipt write failed')
	}
}

fn postunlock_probe() ! {
	if !sessiondaemon.ssh_encrypted_home_ready() { return error('HOME is locked') }
	addresses := net.resolve_addrs('127.0.0.1:22', .ip, .tcp)!
	address := addresses[0]
	fd := C.socket(C.AF_INET, C.SOCK_STREAM, 0)
	if fd < 0 { return error('probe socket unavailable') }
	defer { C.close(fd) }
	flags := C.fcntl(fd, C.F_GETFL)
	if flags < 0 || C.fcntl(fd, C.F_SETFL, flags | C.O_NONBLOCK) != 0 { return error('probe nonblocking failed') }
	result := C.connect(fd, voidptr(&address), address.len())
	if result != 0 {
		if C.errno != C.EINPROGRESS { return error('post-unlock connect failed') }
		mut polling := C.pollfd{ fd: fd, events: C.POLLOUT }
		if C.poll(&polling, 1, 2000) <= 0 { return error('probe connect timeout') }
		mut code := i32(0)
		mut length := u32(sizeof(i32))
		if C.getsockopt(fd, C.SOL_SOCKET, C.SO_ERROR, &code, &length) != 0 || code != 0 {
			return error('post-unlock socket failed')
		}
	}
	serial_note('M16B2-POSTUNLOCK: CONNECT_SUCCESS unlocked_HOME=true\n')
	println('M16B2-POSTUNLOCK: CONNECT_SUCCESS unlocked_HOME=true')
}

fn main() {
	serial_note('M16B-SEED: main entry\n')
	if os.args.len == 2 && os.args[1] == '--perf-sampler' {
		for _ in 0 .. 90 {
			serial_note('M16B2_SAMPLE uptime=' + (os.read_file('/proc/uptime') or { 'unavailable\n' }))
			serial_note(os.read_file('/proc/meminfo') or { 'meminfo unavailable\n' })
			for name in os.ls('/proc') or { []string{} } {
				if name.len > 0 && name.bytes().all(it >= `0` && it <= `9`) {
					stat := os.read_file('/proc/' + name + '/stat') or { continue }
					serial_note('M16B2_STAT ' + stat)
				}
			}
			time.sleep(2 * time.second)
		}
		return
	}
	if os.args.len == 2 && os.args[1] == '--postunlock-probe' {
		postunlock_probe() or { eprintln('M16B2-POSTUNLOCK: FAIL'); exit(1) }
		return
	}
	if os.args.len == 2 && os.args[1] == '--preunlock-probe' {
		preunlock_probe() or {
			serial_note('M16B-PREUNLOCK: FAIL ${err.msg()}\n')
			eprintln('M16B-PREUNLOCK: FAIL')
			exit(1)
		}
		return
	}
	seed() or {
		serial_note('M16B-SEED: FAIL ${err.msg()}\n')
		eprintln('M16B-SEED: FAIL (no desktop or SSH started)')
		exit(1)
	}
	println('M16B-SEED: PASS genuine encrypted home seeded')
	// Preserve libc argv as C strings. Only the actual desktop/broker starts SSH.
	mut args := unsafe { []&char{len: os.args.len + 1, init: nil} }
	real := '/usr/bin/vinix-desktop.real'
	args[0] = &char(real.str)
	for i in 1 .. os.args.len { args[i] = &char(os.args[i].str) }
	C.execv(&char(real.str), &args[0])
	eprintln('M16B-SEED: real desktop exec failed')
	exit(127)
}
