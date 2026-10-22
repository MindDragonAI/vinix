// SPDX-License-Identifier: GPL-2.0-or-later
module main

import os
import math
import time

const scp_max_file = u64(1073741824)
const scp_max_depth = 32

struct ScpOptions {
mut:
	receive   bool
	send      bool
	recursive bool
	directory bool
	preserve  bool
	target    string
}

struct ScpTime {
	valid bool
	mtime i64
	mnsec i64
	atime i64
	ansec i64
}

fn C.futimens(int, &C.timespec) int

fn scp_set_time(fd int, stamp ScpTime) ! {
	if !stamp.valid { return }
	times := [C.timespec{ tv_sec: stamp.atime, tv_nsec: stamp.ansec },
		C.timespec{ tv_sec: stamp.mtime, tv_nsec: stamp.mnsec }]!
	result := C.futimens(fd, &times[0])
	code := if result != 0 { int(C.errno) } else { 0 }
	if result != 0 {
		diagnostic_io('futimens', fd, code, i64(result), 0, 0)
		return error('SCP timestamp update')
	}
}

// A small literal shell-word decoder for OpenSSH's scp command. No expansion,
// substitutions, control operators, redirects, or unparsed options are executed.
fn parse_scp_command(command string) ![]string {
	if command.len > max_command { return error('SCP command too long') }
	mut words := []string{}
	mut current := []u8{}
	mut quote := u8(0)
	mut escaped := false
	mut active := false
	for ch in command.bytes() {
		if escaped {
			current << ch
			escaped = false
			active = true
			continue
		}
		if ch == `\\` && quote != `'` {
			escaped = true
			active = true
			continue
		}
		if quote != 0 {
			if ch == quote { quote = 0 } else { current << ch }
			active = true
			continue
		}
		if ch in [`'`, `"`] {
			quote = ch
			active = true
			continue
		}
		if ch in [` `, `\t`] {
			if active {
				words << current.bytestr()
				current = []u8{}
				active = false
			}
			continue
		}
		if ch < 32 || ch in [`;`, `|`, `&`, `<`, `>`, `\x60`, `$`, `(`, `)`] {
			return error('nonliteral SCP command')
		}
		current << ch
		active = true
	}
	if escaped || quote != 0 { return error('unterminated SCP command') }
	if active { words << current.bytestr() }
	if words.len < 3 || words[0] != 'scp' { return error('invalid SCP command') }
	_ := scp_options(words[1..])!
	return words[1..].clone()
}

fn scp_options(args []string) !ScpOptions {
	mut o := ScpOptions{}
	mut end := false
	for arg in args {
		if !end && arg == '--' {
			end = true
			continue
		}
		if !end && arg.starts_with('-') {
			if arg.len < 2 { return error('invalid SCP flags') }
			for ch in arg.bytes()[1..] {
				match ch {
					`t` { o.receive = true }
					`f` { o.send = true }
					`r` { o.recursive = true }
					`d` { o.directory = true }
					`p` { o.preserve = true }
					else { return error('unsupported SCP flag') }
				}
			}
		} else {
			if o.target != '' || arg == '' || arg.contains('\x00') || arg.contains('\n') {
				return error('one SCP target required')
			}
			o.target = arg
		}
	}
	if o.receive == o.send || o.target == '' {
		return error('SCP requires exactly one direction and target')
	}
	return o
}

fn safe_name(name string) bool {
	return name.len > 0 && name.len <= 255 && name !in ['.', '..'] && !name.contains('/') && !name.contains('\\')
		&& !name.bytes().any(it < 32 || it == 127)
}

fn decimal(text string, maximum u64) !u64 {
	if text.len == 0 || text.len > 20 { return error('invalid unsigned decimal') }
	mut value := u64(0)
	for ch in text.bytes() {
		if ch < `0` || ch > `9` || value > (maximum - u64(ch - `0`)) / 10 {
			return error('decimal overflow')
		}
		value = value * 10 + u64(ch - `0`)
		if value > maximum { return error('decimal exceeds limit') }
	}
	return value
}

struct ScpRecord {
	kind u8
	mode u32
	size u64
	name string
}

fn scp_record(line string) !ScpRecord {
	if line.len < 9 || line.len > 1024 || line[0] !in [`C`, `D`] || line[5] != ` ` {
		return error('invalid SCP record')
	}
	mut mode := u32(0)
	for ch in line.bytes()[1..5] {
		if ch < `0` || ch > `7` { return error('invalid mode') }
		mode = mode * 8 + u32(ch - `0`)
	}
	split := line.index_after(' ', 6) or { return error('missing SCP name') }
	size := decimal(line[6..split], scp_max_file)!
	name := line[split + 1..]
	if !safe_name(name) || (line[0] == `D` && size != 0) { return error('unsafe SCP name/size') }
	return ScpRecord{ kind: line[0], mode: mode & 0o777, size: size, name: name }
}

fn scp_line() !string {
	mut line := []u8{}
	for _ in 0 .. 2048 {
		ch := read_exact_fd(0, 1)![0]
		if ch == `\n` { return line.bytestr() }
		if ch == 0 { return error('NUL in SCP line') }
		line << ch
	}
	return error('SCP line too long')
}

fn scp_ack() ! {
	code := read_exact_fd(0, 1)![0]
	if code == 0 { return }
	if code in [u8(1), 2] { _ := scp_line()! }
	return error('SCP peer error')
}

fn scp_ok() ! { write_fd(1, [u8(0)])! }

// Resolve user-specified target components once, without following symlinks.
// Incoming protocol names are then opened only relative to these descriptors.
fn scp_parent(target string) !(int, string) {
	absolute := if target.starts_with('/') { target } else { os.getwd() + '/' + target }
	mut parts := []string{}
	for part in absolute.split('/') {
		if part == '' || part == '.' { continue }
		if part == '..' {
			if parts.len == 0 { return error('target escapes root') }
			parts.delete_last()
		} else {
			parts << part
		}
	}
	if parts.len == 0 { return open_directory('/')!, '' }
	name := parts.pop()
	if !safe_name(name) { return error('unsafe target name') }
	return open_directory('/' + parts.join('/'))!, name
}

fn scp_receive(o ScpOptions) ! {
	parent, name := scp_parent(o.target)!
	defer { C.close(parent) }
	mut root := C.openat(parent, if name == '' { c'.' } else { name.str }, C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW | C.O_CLOEXEC)
	mut named := ''
	if root < 0 {
		if o.directory { return error('SCP destination must be a directory') }
		// Only ENOENT or ENOTDIR can indicate a named regular-file destination.
		if C.errno !in [C.ENOENT, C.ENOTDIR] { return error('unsafe destination') }
		root = C.dup(parent)
		named = name
	}
	if root < 0 { return error('SCP destination open') }
	mut dirs := [root]
	mut modes := []u32{}
	mut stamps := []ScpTime{}
	mut pending_stamp := ScpTime{}
	defer { for fd in dirs { C.close(fd) }
	 }
	mut top_count := 0
	scp_ok()!
	for {
		first := read_exact_fd(0, 1) or {
			if dirs.len == 1 && top_count > 0 { return }
			return err
		}
		if first[0] in [u8(1), 2] {
			_ := scp_line()!
			return error('SCP sender error')
		}
		line := first.bytestr() + scp_line()!
		if line.starts_with('T') {
			fields := line[1..].split(' ')
			if fields.len != 4 { return error('invalid SCP time') }
			pending_stamp = ScpTime{
				valid: true
				mtime: i64(decimal(fields[0], 0x7fffffff)!)
				mnsec: i64(decimal(fields[1], 999999)!) * 1000
				atime: i64(decimal(fields[2], 0x7fffffff)!)
				ansec: i64(decimal(fields[3], 999999)!) * 1000
			}
			scp_ok()!
			continue
		}
		if line == 'E' {
			if dirs.len <= 1 { return error('SCP directory underflow') }
			fd := dirs.pop()
			mode := modes.pop()
			scp_set_time(fd, stamps.pop()) or {
				C.close(fd)
				return err
			}
			if C.fchmod(fd, mode) != 0 || C.fsync(fd) != 0 {
				C.close(fd)
				return error('directory metadata')
			}
			C.close(fd)
			scp_ok()!
			continue
		}
		record := scp_record(line)!
		if dirs.len == 1 {
			top_count++
			if named != '' && top_count > 1 { return error('multiple records for named target') }
		}
		entry := if dirs.len == 1 && named != '' { named } else { record.name }
		dir := dirs.last()
		if record.kind == `D` {
			if !o.recursive || dirs.len >= scp_max_depth {
				return error('recursive SCP disabled/depth exceeded')
			}
			if C.mkdirat(dir, entry.str, 0o700) != 0 && C.errno != C.EEXIST {
				return error('mkdir SCP directory')
			}
			fd := C.openat(dir, entry.str, C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW | C.O_CLOEXEC)
			if fd < 0 { return error('unsafe SCP directory') }
			dirs << fd
			modes << record.mode
			stamps << pending_stamp
			pending_stamp = ScpTime{}
			scp_ok()!
			continue
		}
		fd := C.openat(dir, entry.str, C.O_WRONLY | C.O_CREAT | C.O_NOFOLLOW | C.O_CLOEXEC | C.O_NONBLOCK, u32(0o600))
		if fd < 0 { return error('SCP file open') }
		receive_file(fd, record, pending_stamp) or {
			C.close(fd)
			return err
		}
		pending_stamp = ScpTime{}
		C.close(fd)
	}
}

fn receive_file(fd int, record ScpRecord, stamp ScpTime) ! {
	started := time.sys_mono_now()
	mut op := 'fstat'
	mut code := 0
	mut remaining := record.size
	mut complete := false
	// One receipt for a failed file. No filename, mode, timestamp or
	// protocol text is printed; fd I/O receipts carry partial syscall progress.
	defer {
		saved := C.errno
		mut line := [2048]char{}
		n := unsafe { C.snprintf(&line[0], 2048, c'vinix-sshd-diag event=scp-receive-file complete=%d op=%s errno=%lld errno_valid=%d size=%llu completed_bytes=%llu remaining=%llu elapsed_ms=%llu\n',
			i32(complete), op.str, i64(code), i32(code >= 0), record.size, record.size - remaining, remaining,
			u64((time.sys_mono_now() - started) / 1000000)) }
		if !complete { diagnostic_write(&line[0], n) }
		C.errno = saved
	}
	mut s := C.stat{}
	stat_result := C.fstat(fd, &s)
	code = if stat_result != 0 { int(C.errno) } else { 0 }
	if stat_result != 0 {
		return error('SCP target not regular')
	}
	op = 'regular-file-check'
	if C.S_ISREG(s.st_mode) == 0 { return error('SCP target not regular') }
	op = 'ftruncate'
	truncate_result := C.ftruncate(fd, 0)
	code = if truncate_result != 0 { int(C.errno) } else { 0 }
	if truncate_result != 0 { return error('SCP target not regular') }
	op = 'initial-ack-write'
	code = -1 // Helper failures have their own fd-io receipt with exact errno.
	scp_ok()!
	mut buffer := []u8{len: 32768}
	defer { unsafe { buffer.free() } }
	for remaining > 0 {
		size := int(math.min(remaining, u64(32768)))
		mut data := unsafe { buffer[..size] }
		op = 'file-data-read'
		read_into_fd(0, mut data)!
		op = 'file-data-write'
		write_fd(fd, data)!
		remaining -= u64(size)
	}
	op = 'sender-ack-read'
	scp_ack()!
	op = 'timestamp'
	scp_set_time(fd, stamp)!
	op = 'fchmod'
	mode_result := C.fchmod(fd, record.mode)
	code = if mode_result != 0 { int(C.errno) } else { 0 }
	if mode_result != 0 { return error('SCP file fsync/mode') }
	op = 'fsync'
	sync_result := C.fsync(fd)
	code = if sync_result != 0 { int(C.errno) } else { 0 }
	if sync_result != 0 { return error('SCP file fsync/mode') }
	op = 'final-ack-write'
	code = -1
	scp_ok()!
	complete = true
}

struct C.DIR {}

struct C.dirent {
	d_name [256]char
}

fn C.dup(int) int
fn C.fdopendir(int) &C.DIR
fn C.readdir(voidptr) &C.dirent
fn C.closedir(&C.DIR) int
fn C.ftruncate(int, u64) int

fn scp_send_entry(parent int, name string, recursive bool, depth int) ! {
	if depth >= scp_max_depth || !safe_name(name) { return error('SCP send name/depth') }
	fd := C.openat(parent, name.str, C.O_RDONLY | C.O_NOFOLLOW | C.O_NONBLOCK | C.O_CLOEXEC)
	if fd < 0 { return error('SCP source open') }
	defer { C.close(fd) }
	mut s := C.stat{}
	if C.fstat(fd, &s) != 0 || s.st_size < 0 { return error('SCP source stat') }
	mode := s.st_mode & 0o777
	if C.S_ISDIR(s.st_mode) != 0 {
		if !recursive { return error('SCP source is a directory; use -r') }
		write_fd(1, 'D${mode:04o} 0 ${name}\n'.bytes())!
		scp_ack()!
		listing_fd := C.dup(fd)
		if listing_fd < 0 { return error('SCP source directory descriptor') }
		listing := C.fdopendir(listing_fd)
		if listing == unsafe { nil } {
			C.close(listing_fd)
			return error('SCP source directory')
		}
		defer { C.closedir(listing) }
		mut count := 0
		for {
			item := C.readdir(listing)
			if item == unsafe { nil } { break }
			child := unsafe { cstring_to_vstring(&item.d_name[0]) }.clone()
			if child in ['.', '..'] { continue }
			count++
			if count > 100000 { return error('SCP directory entry limit') }
			scp_send_entry(fd, child, recursive, depth + 1)!
		}
		write_fd(1, 'E\n'.bytes())!
		scp_ack()!
		return
	}
	if C.S_ISREG(s.st_mode) == 0 || u64(s.st_size) > scp_max_file {
		return error('SCP source type/size')
	}
	write_fd(1, 'C${mode:04o} ${s.st_size} ${name}\n'.bytes())!
	scp_ack()!
	mut remaining := u64(s.st_size)
	mut buffer := []u8{len: 32768}
	defer { unsafe { buffer.free() } }
	for remaining > 0 {
		size := int(math.min(remaining, u64(32768)))
		mut data := unsafe { buffer[..size] }
		read_into_fd(fd, mut data)!
		write_fd(1, data)!
		remaining -= u64(size)
	}
	scp_ok()!
	scp_ack()!
}

fn scp_main(args []string) ! {
	o := scp_options(args)!
	if o.receive {
		scp_receive(o) or {
			write_fd(1, ('\x01vinix-scp: ' + err.msg().replace('\n', ' ') + '\n').bytes()) or {}
			return err
		}
		return
	}
	scp_ack()!
	parent, name := scp_parent(o.target)!
	defer { C.close(parent) }
	scp_send_entry(parent, name, o.recursive, 0) or {
		write_fd(1, ('\x01vinix-scp: ' + err.msg().replace('\n', ' ') + '\n').bytes()) or {}
		return err
	}
}
