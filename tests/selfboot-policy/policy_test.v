// SPDX-License-Identifier: GPL-2.0-or-later
module main

import sysdiskpolicy as policy

const root_token = '0123456789abcdef0123456789abcdef'
const source_id = '1111111111111111'
const next_id = '2222222222222222'
const newer_id = '3333333333333333'
const volume_bytes = u64(0x100000000)

fn marker_sector() [512]u8 {
	mut data := [512]u8{}
	for i, c in policy.marker_magic { data[i] = c }
	for i, c in root_token { data[16 + i] = c }
	for i, c in '0000000100000000' { data[48 + i] = c }
	for i, c in source_id { data[64 + i] = c }
	return data
}

fn test_selector_requires_exact_lowercase_tokens_and_explicit_predecessor() {
	for from in ['none', source_id] {
		command := 'vinix.disk=auto vinix.sysroot=${root_token} vinix.disk_from=${from}'
		selected := policy.selector(command)
		assert selected.present && selected.valid
		assert selected.root == root_token && selected.predecessor == from
	}
	selected := policy.selector('\tvinix.sysroot=${root_token}\nvinix.disk_from=none\r')
	assert selected.present && selected.valid
	for command in ['vinix.disk=auto', 'prefixvinix.sysroot=${root_token}',
		'vinix.sysroots=${root_token}', 'other=vinix.sysroot=${root_token}'] {
		assert !policy.selector(command).present
	}
	for command in ['vinix.sysroot', 'vinix.sysroot=', 'vinix.sysroot=${root_token}',
		'vinix.sysroot=${root_token} vinix.disk_from', 'vinix.sysroot=${root_token} vinix.disk_from=',
		'vinix.sysroot=${root_token} vinix.disk_from=NONE',
		'vinix.sysroot=${root_token} vinix.disk_from=ABCDEF0123456789',
		'vinix.sysroot=${root_token} vinix.disk_from=111111111111111',
		'vinix.sysroot=${root_token}0 vinix.disk_from=none',
		'vinix.sysroot=ABCDEF0123456789abcdef0123456789 vinix.disk_from=none',
		'vinix.sysroot=${root_token} vinix.sysroot=${root_token} vinix.disk_from=none',
		'vinix.sysroot=${root_token} vinix.disk_from=none vinix.disk_from=none'] {
		assert policy.selector(command).present
		assert !policy.selector(command).valid
	}
	assert policy.lower_hex(root_token, 32)
	assert !policy.lower_hex('0123456789abcdef0123456789abcdeg', 32)
	assert !policy.lower_hex('', 16)
}

fn test_marker_format_has_exact_header_geometry_and_source_identity() {
	assert policy.marker_magic.len == 16
	assert policy.marker_bytes == 512
	data := marker_sector()
	marker := policy.parse_marker(&data[0], 512, volume_bytes) or { panic('valid marker') }
	assert marker.bytes == volume_bytes
	for i, c in root_token {
		assert marker.root[i] == c
	}
	for i, c in source_id {
		assert marker.bootstrap[i] == c
	}
	assert policy.matches(&marker, root_token)
	assert !policy.matches(&marker, 'ffffffffffffffffffffffffffffffff')
	assert !policy.matches(&marker, '')
	assert policy.parse_marker(&data[0], 511, volume_bytes) == none
	assert policy.parse_marker(&data[0], 513, volume_bytes) == none
	assert policy.parse_marker(&data[0], 512, volume_bytes - 512) == none
	assert policy.parse_marker(&data[0], 512, volume_bytes + 512) == none
	assert policy.parse_marker(&data[0], 512, 0) == none
}

fn test_marker_rejects_every_corrupt_header_token_length_id_or_padding_byte() {
	for offset in 0 .. 512 {
		mut data := marker_sector()
		data[offset] ^= 0x80
		assert policy.parse_marker(&data[0], 512, volume_bytes) == none, 'corrupt marker byte ${offset}'
	}
	mut data := marker_sector()
	for i in 48 .. 64 { data[i] = `f` }
	assert policy.parse_marker(&data[0], 512, volume_bytes) == none
	for i in 48 .. 64 { data[i] = `0` }
	assert policy.parse_marker(&data[0], 512, 0) == none
}

fn test_raw_vjfs_signature_is_required_before_replay() {
	mut superblock := [512]u8{}
	assert !policy.vjfs_signature(&superblock[0], 512)
	superblock[56] = 0x53
	superblock[57] = 0xef
	assert !policy.vjfs_signature(&superblock[0], 512) // foreign ext2
	superblock[56] = 0x56
	superblock[57] = 0x4a
	assert policy.vjfs_signature(&superblock[0], 512)
	assert !policy.vjfs_signature(&superblock[0], 57)
	superblock[56] = 0x4a
	superblock[57] = 0x56
	assert !policy.vjfs_signature(&superblock[0], 512)
}

fn test_selection_fails_closed_on_no_match_duplicate_and_readonly() {
	assert policy.selection(0, false) == .no_match
	assert policy.selection(1, false) == .ready
	assert policy.selection(1, true) == .readonly
	for count in [2, 3, 100] {
		assert policy.selection(count, false) == .ambiguous
		assert policy.selection(count, true) == .ambiguous
	}
}

fn test_same_image_boot_clone_update_and_explicit_successor_update() {
	assert policy.transition(source_id, source_id, 'none', '') == .boot
	assert policy.transition(next_id, next_id, source_id, next_id) == .boot
	assert policy.transition(source_id, next_id, source_id, '') == .update
	assert policy.transition(next_id, newer_id, next_id, next_id) == .update
	// A crash after target persistence but before pending still has the old id.
	assert policy.transition(source_id, next_id, source_id, next_id) == .update
	assert policy.transition(source_id, source_id, 'none', next_id) == .boot
}

fn test_stale_generation_and_unauthorized_transitions_are_refused() {
	assert policy.transition(next_id, source_id, 'none', next_id) == .reject
	assert policy.transition(newer_id, next_id, source_id, newer_id) == .reject
	assert policy.transition(source_id, next_id, 'none', '') == .reject
	assert policy.transition(source_id, next_id, next_id, '') == .reject
	assert policy.transition(source_id, next_id, newer_id, '') == .reject
	assert policy.transition('', next_id, source_id, '') == .reject
	assert policy.transition('not-an-image-id!', next_id, source_id, '') == .reject
	assert policy.transition(source_id, '', source_id, '') == .reject
	assert policy.transition(source_id, next_id, '', '') == .reject
	assert policy.transition(source_id, next_id, 'ABCDEF0123456789', '') == .reject
}

fn test_pending_recovery_is_bound_to_durable_target_not_source_marker() {
	assert policy.transition('pending', next_id, source_id, next_id) == .resume
	assert policy.transition('pending', newer_id, next_id, newer_id) == .resume
	for target in ['', 'pending', source_id, newer_id, '222222222222222X'] {
		assert policy.transition('pending', next_id, source_id, target) == .reject
	}
	// Old clone config and previous update config cannot consume new pending.
	assert policy.transition('pending', source_id, 'none', next_id) == .reject
	assert policy.transition('pending', next_id, source_id, newer_id) == .reject
	assert policy.transition('pending', next_id, 'none', next_id) == .reject
	assert policy.transition('pending', next_id, next_id, next_id) == .reject
}
