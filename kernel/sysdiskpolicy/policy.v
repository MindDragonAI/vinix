// SPDX-License-Identifier: GPL-2.0-or-later
module sysdiskpolicy

pub const marker_magic = 'VINIX-SYSDISK-1\n'
pub const marker_bytes = 512

// All strings are borrowed views of the command line. No split/substr or
// dynamic candidate list is needed on the kernel's manual-free boot path.
pub struct Selector {
pub:
	present     bool
	valid       bool
	root        string
	predecessor string
}

pub fn lower_hex(value string, length int) bool {
	if value.len != length { return false }
	for c in value {
		if !hex_digit(c) { return false }
	}
	return true
}

fn hex_digit(c u8) bool {
	return (c >= `0` && c <= `9`) || (c >= `a` && c <= `f`)
}

fn space(c u8) bool {
	return c == ` ` || c == `\t` || c == `\r` || c == `\n`
}

pub fn selector(command string) Selector {
	mut roots := 0
	mut predecessors := 0
	mut root := ''
	mut predecessor := ''
	mut i := 0
	for i < command.len {
		if space(command[i]) {
			i++
			continue
		}
		start := i
		for i < command.len && !space(command[i]) { i++ }
		token := unsafe { tos(command.str + start, i - start) }
		if token == 'vinix.sysroot' || token.starts_with('vinix.sysroot=') {
			roots++
			if token.len >= 14 { root = unsafe { tos(token.str + 14, token.len - 14) } }
		}
		if token == 'vinix.disk_from' || token.starts_with('vinix.disk_from=') {
			predecessors++
			if token.len >= 16 { predecessor = unsafe { tos(token.str + 16, token.len - 16) } }
		}
	}
	return Selector{
		present:     roots != 0
		valid:       roots == 1 && predecessors == 1 && lower_hex(root, 32)
			&& (predecessor == 'none' || lower_hex(predecessor, 16))
		root:        root
		predecessor: predecessor
	}
}

pub struct Marker {
pub:
	root      [32]u8
	bytes     u64
	bootstrap [16]u8
}

// Parse exactly the raw first sector, never a filesystem probe: probing VJFS
// can replay its journal. The source length is also the partition length.
pub fn parse_marker(data &u8, length int, device_bytes u64) ?Marker {
	if marker_magic.len != 16 || length != marker_bytes || device_bytes < 2048
		|| device_bytes % 512 != 0 {
		return none
	}
	mut root := [32]u8{}
	mut bootstrap := [16]u8{}
	mut bytes := u64(0)
	for i in 0 .. marker_bytes {
		c := unsafe { data[i] }
		if i < 16 {
			if c != marker_magic[i] { return none }
		} else if i < 80 {
			if !hex_digit(c) { return none }
			if i < 48 {
				root[i - 16] = c
			} else if i < 64 {
				bytes = (bytes << 4) | u64(if c <= `9` { c - `0` } else { c - `a` + 10 })
			} else {
				bootstrap[i - 64] = c
			}
		} else if c != 0 {
			return none
		}
	}
	if bytes != device_bytes { return none }
	return Marker{ root: root, bytes: bytes, bootstrap: bootstrap }
}

pub fn matches(marker &Marker, root string) bool {
	if !lower_hex(root, 32) { return false }
	for i in 0 .. 32 {
		if marker.root[i] != root[i] { return false }
	}
	return true
}

pub enum Selection {
	no_match
	ambiguous
	readonly
	ready
}

pub fn selection(count int, readonly bool) Selection {
	if count == 0 { return .no_match }
	if count != 1 { return .ambiguous }
	if readonly { return .readonly }
	return .ready
}

pub fn vjfs_signature(data &u8, length int) bool {
	return length >= 58 && unsafe { data[56] == 0x56 && data[57] == 0x4a }
}

pub enum Transition {
	reject
	boot
	update
	resume
}

// A pending root belongs ONLY to its durable target. In particular the source
// id in the ownership marker cannot authorize recovery by an older boot image.
pub fn transition(installed string, image string, predecessor string, target string) Transition {
	if !lower_hex(image, 16)
		|| (predecessor != 'none' && !lower_hex(predecessor, 16)) {
		return .reject
	}
	if installed == image { return .boot }
	if !lower_hex(predecessor, 16) || predecessor == image { return .reject }
	if installed == 'pending' {
		return if target == image { Transition.resume } else { Transition.reject }
	}
	if lower_hex(installed, 16) && installed == predecessor { return .update }
	return .reject
}
