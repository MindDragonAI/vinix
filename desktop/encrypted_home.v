// SPDX-License-Identifier: GPL-2.0-or-later
module main

import os

fn desktop_encrypted_home_ready() bool {
	// A marker alone on the public system volume is never authorization.
	mounts := os.read_file('/proc/self/mounts') or { return false }
	defer { unsafe { mounts.free() } }
	mut mounted := false
	lines := mounts.split_into_lines()
	defer { unsafe { for line in lines { line.free() }; lines.free() } }
	for line in lines {
		fields := line.fields()
		if fields.len >= 4 && fields[0] == '/dev/mapper/vinix63' && fields[1] == '/root'
			&& fields[2] == 'ext2' && (fields[3] == 'rw' || fields[3].starts_with('rw,')) { mounted = true }
		unsafe { for field in fields { field.free() }; fields.free() }
	}
	if !mounted { return false }
	info := os.lstat('/root/.vinix-encrypted-home') or { return false }
	if info.get_filetype() != .regular || info.mode & 0o077 != 0 || info.size != 24 { return false }
	marker := os.read_file('/root/.vinix-encrypted-home') or { return false }
	defer { unsafe { marker.free() } }
	return marker == 'Vinix encrypted home v1\n'
}
