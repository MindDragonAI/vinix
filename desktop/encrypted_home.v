// SPDX-License-Identifier: GPL-2.0-or-later
module main

import os

// Qualification only: fixed text, with no mount/marker contents or credentials.
fn desktop_home_note(message &char) {
	$if home_desktop_diagnostics ? {
		saved := unsafe { C.errno }
		fd := C.open(c'/dev/com1', C.O_WRONLY | C.O_CLOEXEC | C.O_NOFOLLOW)
		if fd >= 0 {
			C.write(fd, message, unsafe { C.strlen(message) })
			C.close(fd)
		}
		unsafe { C.errno = saved }
	}
}

fn desktop_encrypted_home_ready() bool {
	// A marker alone on the public system volume is never authorization.
	desktop_home_note(c'HOME-DESKTOP: guard proc read start\n')
	mounts := os.read_file('/proc/self/mounts') or {
		desktop_home_note(c'HOME-DESKTOP: guard proc read failed; guard failed\n')
		return false
	}
	desktop_home_note(c'HOME-DESKTOP: guard proc read finish\n')
	defer { unsafe { mounts.free() } }
	mut mounted := false
	lines := mounts.split_into_lines()
	// []string.free() recursively frees its strings. Freeing copied elements
	// first leaves dangling array entries and double-frees them at cleanup.
	defer { unsafe { lines.free() } }
	for line in lines {
		fields := line.fields()
		if fields.len >= 4 && fields[0] == '/dev/mapper/vinix63' && fields[1] == '/root'
			&& fields[2] == 'ext2' && (fields[3] == 'rw' || fields[3].starts_with('rw,')) { mounted = true }
		unsafe { fields.free() }
	}
	if !mounted {
		desktop_home_note(c'HOME-DESKTOP: mount check failed; guard failed\n')
		return false
	}
	desktop_home_note(c'HOME-DESKTOP: mount check passed; marker stat start\n')
	info := os.lstat('/root/.vinix-encrypted-home') or {
		desktop_home_note(c'HOME-DESKTOP: marker stat failed; guard failed\n')
		return false
	}
	if info.get_filetype() != .regular || info.mode & 0o077 != 0 || info.size != 24 {
		desktop_home_note(c'HOME-DESKTOP: marker metadata failed; guard failed\n')
		return false
	}
	desktop_home_note(c'HOME-DESKTOP: marker stat passed; marker read start\n')
	marker := os.read_file('/root/.vinix-encrypted-home') or {
		desktop_home_note(c'HOME-DESKTOP: marker read failed; guard failed\n')
		return false
	}
	desktop_home_note(c'HOME-DESKTOP: marker read finish\n')
	defer { unsafe { marker.free() } }
	ready := marker == 'Vinix encrypted home v1\n'
	if ready {
		desktop_home_note(c'HOME-DESKTOP: guard passed\n')
	} else {
		desktop_home_note(c'HOME-DESKTOP: marker check failed; guard failed\n')
	}
	return ready
}
