// SPDX-License-Identifier: GPL-2.0-or-later
module disk_probe

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/resource.h>

fn C.open(&char, i32, ...voidptr) i32
fn C.close(i32) i32
fn C.read(i32, voidptr, usize) isize
fn C.write(i32, voidptr, usize) isize
fn C.fsync(i32) i32
fn C.getuid() u32
fn C.geteuid() u32
fn C.strcmp(&char, &char) i32
fn C.strlen(&char) usize
fn C.setrlimit(i32, &C.rlimit) i32
fn C.__errno_location() &i32

struct C.rlimit {
	rlim_cur u64
	rlim_max u64
}

// No heap strings, stdio buffering, credentials, or marker constants.
fn read_retry(fd i32, buf voidptr, size usize) isize {
	for {
		n := C.read(fd, buf, size)
		if n >= 0 || unsafe { *C.__errno_location() } != C.EINTR { return n }
	}
	return -1
}

fn write_all(fd i32, buf &u8, size int) bool {
	mut at := 0
	for at < size {
		n := unsafe { C.write(fd, buf + at, usize(size - at)) }
		if n < 0 && unsafe { *C.__errno_location() } == C.EINTR { continue }
		if n <= 0 || n > size - at { return false }
		at += int(n)
	}
	return true
}

fn mount_line(line &char) int {
	unsafe {
		mut fields := [6]&char{}
		mut at := 0
		for field in 0 .. 6 {
			for line[at] == 32 || line[at] == 9 { at++ }
			if line[at] == 0 { return -1 }
			fields[field] = line + at
			for line[at] != 0 && line[at] != 32 && line[at] != 9 { at++ }
			if line[at] != 0 { line[at] = 0; at++ }
		}
		if C.strcmp(fields[1], c'/root') != 0 { return 0 }
		if C.strcmp(fields[0], c'/dev/mapper/vinix63') != 0
			|| C.strcmp(fields[2], c'ext2') != 0 { return -1 }
		mut rw := false
		mut option := fields[3]
		mut end := option
		for {
			if *end == 44 || *end == 0 {
				last := *end == 0
				*end = 0
				if C.strcmp(option, c'ro') == 0 { return -1 }
				if C.strcmp(option, c'rw') == 0 { rw = true }
				if last { break }
				option = end + 1
			}
			end++
		}
		return if rw { 1 } else { -1 }
	}
}

@[direct_array_access]
fn home_mounted() bool {
	fd := C.open(c'/proc/self/mounts', C.O_RDONLY | C.O_CLOEXEC | C.O_NOFOLLOW)
	if fd < 0 { return false }
	mut line := [4096]u8{}
	mut at := 0
	mut matches := 0
	mut ok := true
	for {
		n := read_retry(fd, &line[at], 1)
		if n < 0 { ok = false; break }
		if n == 0 {
			if at != 0 { ok = false }
			break
		}
		if line[at] == `\n` {
			line[at] = 0
			result := mount_line(unsafe { &char(&line[0]) })
			if result < 0 { ok = false; break }
			matches += result
			at = 0
		} else {
			if line[at] == 0 { ok = false; break }
			at++
			if at == line.len - 1 { ok = false; break }
		}
	}
	closed := C.close(fd) == 0
	return ok && closed && matches == 1
}

@[export: 'main']
pub fn entry(argc i32, argv &&char) i32 {
	limit := C.rlimit{}
	if C.setrlimit(C.RLIMIT_CORE, &limit) != 0 { return 1 }
	if C.getuid() != 0 || C.geteuid() != 0 || argc != 3 { return 1 }
	unsafe {
		writing := C.strcmp(argv[1], c'--write') == 0
		if !writing && C.strcmp(argv[1], c'--read') != 0 { return 1 }
		mut expected := [129]u8{}
		mut size := 0
		for size <= 128 && argv[2][size] != 0 {
			// Printable ASCII excludes line breaks and terminal control sequences.
			if size == 128 || argv[2][size] < 32 || argv[2][size] > 126 { return 1 }
			expected[size] = u8(argv[2][size])
			size++
		}
		if size == 0 { return 1 }
		expected[size] = `\n`
		size++
		if !home_mounted() { return 1 }
		if writing {
			fd := C.open(c'/root/M14A-MARKER.TXT', C.O_WRONLY | C.O_NOFOLLOW
				| C.O_CLOEXEC | C.O_CREAT | C.O_EXCL, u32(0o600))
			if fd < 0 { return 1 }
			written := write_all(fd, &expected[0], size)
			// fsync must actually succeed; close alone is not durability evidence.
			synced := C.fsync(fd) == 0
			closed := C.close(fd) == 0
			if !written || !synced || !closed { return 1 }
		}
		fd := C.open(c'/root/M14A-MARKER.TXT', C.O_RDONLY | C.O_NOFOLLOW | C.O_CLOEXEC)
		if fd < 0 { return 1 }
		mut actual := [130]u8{}
		mut count := 0
		mut verified := true
		for count < size {
			n := read_retry(fd, &actual[count], usize(size - count))
			if n <= 0 || n > size - count { verified = false; break }
			count += int(n)
		}
		if verified {
			for i in 0 .. size {
				if actual[i] != expected[i] { verified = false }
			}
			if read_retry(fd, &actual[size], 1) != 0 { verified = false }
		}
		closed := C.close(fd) == 0
		if !verified || !closed { return 1 }
		serial := C.open(c'/dev/com1', C.O_WRONLY | C.O_NOFOLLOW | C.O_CLOEXEC)
		if serial < 0 { return 1 }
		stage := if writing { &char(c'HOME-QUALIFY WRITE PASS\n') } else { &char(c'HOME-QUALIFY READ PASS\n') }
		mut report := [192]u8{}
		prefix := int(C.strlen(stage))
		for i in 0 .. prefix { report[i] = u8(stage[i]) }
		for i in 0 .. size { report[prefix + i] = actual[i] }
		sent := write_all(serial, &report[0], prefix + size)
		serial_closed := C.close(serial) == 0
		return if sent && serial_closed { 0 } else { 1 }
	}
}
