module main

import os
import strconv

fn mapped_identity(line string, id Identity) bool {
	fields := line.fields()
	if fields.len < 5 { return false }
	dev := fields[3].split(':')
	if dev.len != 2 { return false }
	major := strconv.parse_uint(dev[0], 16, 32) or { return false }
	minor := strconv.parse_uint(dev[1], 16, 32) or { return false }
	ino := strconv.parse_uint(fields[4], 10, 64) or { return false }
	return ino == id.ino && major == ((id.dev >> 8) & 0xfff | (id.dev >> 32) & 0xfffff000)
		&& minor == ((id.dev & 0xff) | (id.dev >> 12) & 0xffffff00)
}

// Mutation is Linux-only. flock is advisory: the operator must keep this image
// offline throughout the transaction. Repeated scans also catch uncooperative users.
fn offline(f Locked) ! {
	$if linux {
		// A loop mapping can exist without any process keeping the backing file open.
		for name in os.ls('/sys/block')! {
			if !name.starts_with('loop') { continue }
			backing := '/sys/block/${name}/loop/backing_file'
			if !os.exists(backing) { continue }
			value := os.read_file(backing)!.trim_right('\n')
			if value == '' { continue }
			path := if value.starts_with('/') { value } else { '/' + value }
			mut s := C.selfboot_stat{}
			if C.selfboot_follow(path.str, &s) != 0 {
				return error('cannot resolve loop backing file: ${path}')
			}
			if s.st_dev == f.id.dev && s.st_ino == f.id.ino {
				return error('loop-backed image REFUSED: ${f.path}')
			}
		}
		mountinfo := os.read_file('/proc/self/mountinfo')!
		for line in mountinfo.split_into_lines() {
			fields := line.split(' ')
			if fields.len < 6 { return error('malformed host mountinfo') }
			mountpoint := fields[4].replace('\\040', ' ').replace('\\011', '\t').replace('\\134', '\\')
			mut mount_stat := C.selfboot_stat{}
			if C.selfboot_follow(mountpoint.str, &mount_stat) == 0
				&& mount_stat.st_dev == f.id.dev && mount_stat.st_ino == f.id.ino {
				return error('mounted/bind-mounted image REFUSED: ${f.path}')
			}
			for field in line.split(' ') {
				// mountinfo uses octal escapes; decode before identity/path comparisons.
				path := field.replace('\\040', ' ').replace('\\011', '\t').replace('\\134', '\\')
				if path == f.path { return error('mounted image REFUSED: ${f.path}') }
			}
		}
		for pid in os.ls('/proc')! {
			if pid == '' || !pid.bytes().all(it.is_digit()) || pid == os.getpid().str() { continue }
			dir := '/proc/${pid}/fd'
			entries := os.ls(dir) or {
				if !os.exists('/proc/${pid}') { continue }
				return error('cannot inspect ${dir}; run with visibility of all host processes (normally root)')
			}
			for entry in entries {
				mut s := C.selfboot_stat{}
				fdpath := dir + '/' + entry
				if C.selfboot_follow(fdpath.str, &s) != 0 {
					if !os.exists(fdpath) { continue }
					return error('cannot inspect process descriptor: ${fdpath}')
				}
				if s.st_dev == f.id.dev && s.st_ino == f.id.ino {
					return error('open/live image REFUSED: ${f.path} (pid ${pid})')
				}
			}
			maps := os.read_file('/proc/${pid}/maps') or {
				if !os.exists('/proc/${pid}') { continue }
				return error('cannot inspect process mappings for ${pid}')
			}
			for line in maps.split_into_lines() {
				if mapped_identity(line, f.id) {
					return error('memory-mapped/live image REFUSED: ${f.path} (pid ${pid})')
				}
			}
		}
		f.unchanged()!
	} $else {
		return error('${os.user_os()}: install/update require Linux /proc and /sys offline checks; live raw-device support is unavailable')
	}
}
