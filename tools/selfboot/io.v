// SPDX-License-Identifier: GPL-2.0-or-later
module main

import crypto.sha256
import crypto.rand
import os

#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#define selfboot_stat stat
#define selfboot_lstat lstat
#define selfboot_fstat fstat
#define selfboot_follow stat

struct C.selfboot_stat {
	st_dev            u64
	st_ino            u64
	st_mode           u32
	st_nlink          u64
	st_size           i64
	st_mtime          i64
	st_ctime          i64
	selfboot_mtime_ns i64
	selfboot_ctime_ns i64
}

fn C.selfboot_lstat(&char, &C.selfboot_stat) int
fn C.selfboot_fstat(int, &C.selfboot_stat) int
fn C.selfboot_follow(&char, &C.selfboot_stat) int
fn C.flock(int, int) int
fn C.pread(int, voidptr, usize, i64) i64
fn C.pwrite(int, voidptr, usize, i64) i64
fn C.ftruncate(int, u64) int
fn C.fsync(int) int
fn C.rename(&char, &char) int
fn C.mkdtemp(&char) &char

struct Identity {
	dev      u64
	ino      u64
	bytes    i64
	mtime    i64
	ctime    i64
	mtime_ns i64
	ctime_ns i64
}

struct Locked {
	path string
	fd   int
	id   Identity
}

fn identity(s C.selfboot_stat) Identity {
	return Identity{s.st_dev, s.st_ino, s.st_size, s.st_mtime, s.st_ctime, s.selfboot_mtime_ns, s.selfboot_ctime_ns}
}

fn absolute(path string) ! {
	if !os.is_abs_path(path) || path.bytes().any(it < 32 || it == 127) || path.ends_with('/') || path.contains('//')
		|| path.split('/').any(it == '.' || it == '..') {
		return error('require a named, normalized absolute path: ${path}')
	}
	// Reject symlink components as well as a symlink leaf.
	parent := os.dir(path)
	if os.real_path(parent) != parent { return error('symlink or missing parent: ${path}') }
}

fn regular(path string) !Identity {
	absolute(path)!
	mut s := C.selfboot_stat{}
	if C.selfboot_lstat(path.str, &s) != 0 { return error('cannot lstat ${path}') }
	if s.st_mode & 0o170000 != 0o100000 {
		return error('regular files only; block devices, symlinks and special files REFUSED: ${path}')
	}
	if s.st_nlink != 1 { return error('hardlinks REFUSED: ${path}') }
	return identity(s)
}

fn locked(path string) !Locked {
	before := regular(path)!
	fd := C.open(path.str, C.O_RDONLY | C.O_NOFOLLOW | C.O_CLOEXEC | C.O_NONBLOCK)
	if fd < 0 { return error('cannot open ${path}') }
	mut ok := false
	defer { if !ok { C.close(fd) } }
	if C.flock(fd, C.LOCK_EX | C.LOCK_NB) != 0 {
		return error('exclusive lock unavailable: ${path}')
	}
	mut s := C.selfboot_stat{}
	if C.selfboot_fstat(fd, &s) != 0 || identity(s) != before || s.st_nlink != 1 {
		return error('identity changed while opening: ${path}')
	}
	ok = true
	return Locked{path, fd, before}
}

fn (f Locked) close() { C.close(f.fd) }

fn (f Locked) unchanged() ! {
	mut s := C.selfboot_stat{}
	if C.selfboot_fstat(f.fd, &s) != 0 || identity(s) != f.id || regular(f.path)! != f.id || s.st_nlink != 1 {
		return error('opened file or pathname changed: ${f.path}')
	}
}

fn read_at(fd int, offset i64, count int) ![]u8 {
	if offset < 0 || count < 0 { return error('invalid read range') }
	mut data := []u8{len: count}
	mut done := 0
	for done < count {
		n := C.pread(fd, unsafe { &u8(data.data) + done }, usize(count - done), offset + done)
		if n <= 0 { return error('short/failed read at ${offset + done}') }
		done += int(n)
	}
	return data
}

fn write_at(fd int, offset i64, data []u8) ! {
	mut done := 0
	for done < data.len {
		n := C.pwrite(fd, unsafe { &u8(data.data) + done }, usize(data.len - done), offset + done)
		if n <= 0 { return error('short/failed write') }
		done += int(n)
	}
}

fn fresh_file(path string, bytes i64) !int {
	fd := C.open(path.str, C.O_RDWR | C.O_CREAT | C.O_EXCL | C.O_NOFOLLOW | C.O_CLOEXEC, 0o600)
	if fd < 0 { return error('cannot exclusively create ${path}') }
	if C.flock(fd, C.LOCK_EX | C.LOCK_NB) != 0 {
		C.close(fd)
		return error('cannot lock new file ${path}')
	}
	if C.ftruncate(fd, u64(bytes)) != 0 {
		C.close(fd)
		return error('cannot size ${path}')
	}
	return fd
}

fn durable(fd int) ! { if C.fsync(fd) != 0 { return error('fsync failed') } }

fn hash_range(fd int, start i64, bytes i64) !string {
	mut h := sha256.new()
	mut at := i64(0)
	for at < bytes {
		n := int(if bytes - at > 1048576 { i64(1048576) } else { bytes - at })
		h.write(read_at(fd, start + at, n)!)!
		at += n
	}
	return h.sum([]u8{}).hex()
}

fn digest(path string) !string {
	f := locked(path)!
	defer { f.close() }
	result := hash_range(f.fd, 0, f.id.bytes)!
	f.unchanged()!
	return result
}

// Destination must be a newly truncated file, or a range already known zero.
// Zero chunks become sparse holes; bytes, including the last chunk, stay exact.
fn clone_range(src int, src_at i64, dst int, dst_at i64, bytes i64) !string {
	mut h := sha256.new()
	mut at := i64(0)
	for at < bytes {
		n := int(if bytes - at > 1048576 { i64(1048576) } else { bytes - at })
		data := read_at(src, src_at + at, n)!
		h.write(data)!
		if data.any(it != 0) { write_at(dst, dst_at + at, data)! }
		at += n
	}
	return h.sum([]u8{}).hex()
}

fn blank(f Locked) ! {
	mut at := i64(0)
	for at < f.id.bytes {
		n := int(if f.id.bytes - at > 1048576 { i64(1048576) } else { f.id.bytes - at })
		if read_at(f.fd, at, n)!.any(it != 0) {
			return error('target is not completely zero: ${f.path}')
		}
		at += n
	}
	f.unchanged()!
}

fn temporary(parent string) !string {
	mut pattern := (parent + '/.selfboot-XXXXXX\x00').bytes()
	p := unsafe { C.mkdtemp(&char(pattern.data)) }
	if p == unsafe { nil } { return error('cannot create private staging directory') }
	return unsafe { p.vstring().clone() }
}

fn random_token() !string { return rand.bytes(16)!.hex() }

// Native programs receive argv directly. No shell, command string or interpreter.
fn native(argv []string) ! {
	if argv.len == 0 { return error('empty native command') }
	executable := os.find_abs_path_of_executable(argv[0]) or { return error('required native tool unavailable: ${argv[0]}') }
	mut p := os.new_process(executable)
	p.set_args(argv[1..])
	// Do not inherit mtools configuration that can redirect a drive or execute filters.
	p.set_environment({
		'PATH':     os.getenv('PATH')
		'LC_ALL':   'C'
		'MTOOLSRC': '/dev/null'
		'HOME':     '/nonexistent'
	})
	p.run()
	p.wait()
	code := p.code
	p.close()
	if code != 0 { return error('native helper ${argv[0]} exited ${code}') }
}

fn native_output(argv []string, limit int) !string {
	executable := os.find_abs_path_of_executable(argv[0]) or { return error('required native tool unavailable: ${argv[0]}') }
	mut p := os.new_process(executable)
	p.set_args(argv[1..])
	p.set_environment({
		'PATH':   os.getenv('PATH')
		'LC_ALL': 'C'
		'HOME':   '/nonexistent'
	})
	p.set_redirect_stdio_merged()
	p.run()
	mut output := ''
	for {
		chunk := p.stdout_read()
		if output.len + chunk.len > limit {
			p.signal_kill()
			p.wait()
			p.close()
			return error('native output exceeds limit: ${argv[0]}')
		}
		output += chunk
		if chunk == '' && !p.is_alive() { break }
	}
	p.wait()
	code := p.code
	p.close()
	if code != 0 { return error('native helper ${argv[0]} exited ${code}: ${output}') }
	return output
}
