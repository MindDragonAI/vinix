// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Alexander Medvednikov
module sysdisk

import fs
import fs.ext2
import hibernate
import initramfs
import limine
import memory
import pagecache
import resource
import stat
import sysdiskpolicy

// A machine booted from an installer image (the release ISOs pass
// vinix.disk=auto) keeps its system on a disk, as a QEMU machine started by
// scripts/run-desktop-aarch64.sh does: the whole filesystem survives a restart. Given a
// disk, the first boot installs the image onto it and runs from there; later
// boots find it and skip unpacking the image into memory; a newer image is
// unpacked over the old system, leaving /root as it is. Without a disk it runs
// from memory as before.
//
// Only a disk that is entirely blank at both ends is ever formatted. A disk
// with anything recognisable on it -- a partition table, a filesystem, data --
// is left alone unless it is an ext2 volume this installed.
// With vinix.sysroot, only the uniquely marked partition is eligible, every
// refusal is fatal, and the whole-disk installer is never entered.
pub enum Outcome {
	in_memory // no disk used: the image is still to be unpacked into RAM
	booted    // an installed, up-to-date system is the root
	installed // the image was just unpacked onto a blank disk
	updated   // the image was just unpacked over an older installed one
}

// Smaller than this and the system, with room for the apps pkg installs, does
// not fit.
const min_disk_bytes = u64(4) << 30

// The image's id, on the disk. It reads `pending` while an install or an
// update is being written, so a boot interrupted halfway is finished by the
// next one rather than trusted.
const id_file = '/.vinix-image-id'
const id_name = '.vinix-image-id'
const pending_id = 'pending'
const target_name = '.vinix-update-target'

fn command_line() string {
	kernel_file := limine.kernel_file()
	if kernel_file == unsafe { nil } || kernel_file.cmdline == unsafe { nil } {
		return ''
	}
	return unsafe { cstring_to_vstring(kernel_file.cmdline) }
}

pub fn requested() bool {
	command := command_line()
	return command.contains('vinix.disk=auto') || sysdiskpolicy.selector(command).present
}

pub fn mount_or_install() Outcome {
	selector := sysdiskpolicy.selector(command_line())
	if selector.present && !selector.valid {
		refuse('malformed or duplicate sysroot/disk_from selector')
	}
	image := initramfs.image_id() @[freed]
	defer { unsafe { image.free() } }
	if selector.present {
		return mount_partition(selector, image)
	}
	if image.len == 0 {
		println('sysdisk: this image has no id; running from memory')
		return .in_memory
	}
	disks := whole_disks()
	defer {
		unsafe { disks.free() }
	}
	if disks.len == 0 {
		println('sysdisk: no disk; running from memory, and nothing will be kept')
		return .in_memory
	}
	// A disk this installed on before.
	for disk in disks {
		mut filesystem, ok := ext2.ext2_init(disk)
		if !ok {
			continue
		}
		mut root := ext2.ext2_root(mut filesystem) or { continue }
		installed := read_id(root) @[freed]
		owned := installed.len != 0
		same_image := installed == image
		unsafe { installed.free() }
		if !owned {
			// Some other ext2 volume: not ours to take.
			continue
		}
		if same_image {
			if fs.install_disk_root(mut root) {
				report('sysdisk: running from the system on', disk, '')
				return .booted
			}
			continue
		}
		if !fs.install_empty_disk_root(mut root) {
			continue
		}
		report('sysdisk: updating the system on', disk, ' (keeping /root)')
		mark(pending_id)
		initramfs.install('root')
		commit(image)
		return .updated
	}
	// A blank disk to install on.
	for disk in disks {
		if u64(disk.resource.stat.size) < min_disk_bytes || !blank(disk) {
			continue
		}
		report('sysdisk: installing onto', disk, '')
		if !ext2.format(disk, 'vinix') {
			report('sysdisk: could not format', disk, '')
			continue
		}
		mut filesystem, ok := ext2.ext2_init(disk)
		if !ok {
			continue
		}
		mut root := ext2.ext2_root(mut filesystem) or { continue }
		if !fs.install_empty_disk_root(mut root) {
			continue
		}
		mark(pending_id)
		initramfs.install('')
		commit(image)
		println('sysdisk: installed; later boots start from the disk')
		return .installed
	}
	println('sysdisk: no blank disk of 4 GiB or more; running from memory')
	return .in_memory
}

// No filesystem code runs until the complete partition scan has found exactly
// one owned root. Neither foreign partitions nor any whole disk are probed,
// replayed or formatted on this path. Candidate pointers and I/O stay on stack.
fn selected_partition(selector sysdiskpolicy.Selector) &fs.VFSNode {
	dev := fs.get_node(vfs_root, '/dev', true) or {
		refuse('sysroot has no matching owned partition')
		return unsafe { nil }
	}
	mut selected := unsafe { &fs.VFSNode(nil) }
	mut count := 0
	mut sector := [512]u8{}
	for name, node in dev.children {
		if !name.contains('-') || name.starts_with('.') || node.resource == unsafe { nil }
			|| !stat.isblk(node.resource.stat.mode) || node.resource.stat.size < 2048 {
			continue
		}
		mut parent_end := name.len
		for i := name.len - 1; i >= 0; i-- {
			if name[i] == `-` {
				parent_end = i
				break
			}
		}
		parent := unsafe { tos(name.str, parent_end) }
		if hibernate.is_image_device(parent) { continue }
		mut res := unsafe { node.resource }
		got := res.read(unsafe { nil }, &sector[0], 0, 512) or { continue }
		marker := sysdiskpolicy.parse_marker(&sector[0], int(got), u64(res.stat.size)) or {
			continue
		}
		if sysdiskpolicy.matches(unsafe { &marker }, selector.root) {
			selected = node
			count++
		}
	}
	// Count before checking the backend: a readonly duplicate is still a
	// duplicate, and must not make another matching root safe to use.
	mut readonly := false
	if count == 1 {
		mut backend := unsafe { selected.resource }
		readonly = selected.read_only || resource.backend_is_read_only(mut backend)
	}
	match sysdiskpolicy.selection(count, readonly) {
		.no_match { refuse('sysroot has no matching owned partition') }
		.ambiguous { refuse('sysroot has ambiguous duplicate partitions') }
		.readonly { refuse('sysroot matching partition has a readonly backend') }
		.ready {}
	}
	mut backend := unsafe { selected.resource }
	got := backend.read(unsafe { nil }, &sector[0], 1024, 512) or {
		refuse('cannot read sysroot VJFS signature')
		return unsafe { nil }
	}
	if got != 512 || !sysdiskpolicy.vjfs_signature(&sector[0], int(got)) {
		refuse('sysroot is not a private VJFS volume')
	}
	return selected
}

fn mount_partition(selector sysdiskpolicy.Selector, image string) Outcome {
	if !sysdiskpolicy.lower_hex(image, 16) { refuse('boot module has no valid image id') }
	disk := selected_partition(selector)
	mut filesystem, ok := ext2.ext2_init(disk)
	if !ok { refuse('could not mount selected VJFS sysroot') }
	mut root := ext2.ext2_root(mut filesystem) or {
		refuse('could not read selected VJFS root')
		return .in_memory
	}
	installed := read_named_id(root, id_name) @[freed]
	target := read_named_id(root, target_name) @[freed]
	defer {
		unsafe {
			installed.free()
			target.free()
		}
	}
	decision := sysdiskpolicy.transition(installed, image, selector.predecessor, target)
	if decision == .reject {
		C.kprintf(c'sysdisk: image mismatch installed=%.*s module=%.*s from=%.*s target=%.*s\n',
			i32(installed.len), installed.str, i32(image.len), image.str, i32(selector.predecessor.len),
			selector.predecessor.str, i32(target.len), target.str)
		refuse('sysroot image transition refused')
	}
	if decision == .boot {
		if !fs.install_disk_root(mut root) { refuse('selected sysroot is not bootable') }
		report('sysdisk: running from the system on', disk, '')
		return .booted
	}
	if !fs.install_empty_disk_root(mut root) { refuse('cannot switch to selected sysroot') }
	report('sysdisk: updating the system on', disk, ' (keeping /root)')
	// Persist the target BEFORE pending. An interrupted write of the target
	// leaves the old installed id intact. A pending root with a missing, torn
	// or different target is rejected, including by the previous generation.
	mark_named(target_name, image)
	mark_named(id_name, pending_id)
	initramfs.install('root')
	if !pagecache.sync_all() { refuse('could not sync updated sysroot') }
	mark_named(id_name, image)
	return .updated
}

@[noreturn]
fn refuse(reason string) {
	C.kprintf(c'sysdisk: refusing partition root: %.*s\n', i32(reason.len), reason.str)
	panic('sysdisk: partition root refused')
}

fn mark_named(name string, id string) {
	if !write_named_id(vfs_root, name, id) || !pagecache.sync_all() {
		refuse('could not durably record sysroot update state')
	}
}

// Block devices in /dev that are whole disks: sd0, ata0, nvme0n1, vda. A
// partition's name has a dash (sd0-1), and a partition is never the target.
fn whole_disks() []&fs.VFSNode {
	mut disks := []&fs.VFSNode{}
	dev := fs.get_node(vfs_root, '/dev', true) or { return disks }
	for name, node in dev.children {
		// Not `name == '.'`: V3 compiles a string comparison in this loop to
		// a C == on the structs. No device name starts with a dot anyway.
		if name.contains('-') || name.starts_with('.') || node.resource == unsafe { nil } {
			continue
		}
		// The device named to keep an image of memory on is that and nothing
		// else, however blank it looks: a system installed on it would be
		// written over by the first image.
		if hibernate.is_image_device(name) {
			continue
		}
		if stat.isblk(node.resource.stat.mode) {
			disks << node
		}
	}
	return disks
}

// Whether a disk reads as all zeroes over its first and last MiB: a disk
// image freshly made by QEMU or VirtualBox. Anything written by a partitioner,
// a filesystem or an OS shows up at one end or the other.
fn blank(disk &fs.VFSNode) bool {
	size := u64(disk.resource.stat.size)
	span := u64(1024 * 1024)
	if size < 2 * span {
		return false
	}
	buffer := memory.calloc(span, 1)
	if buffer == unsafe { nil } {
		return false
	}
	defer { memory.free(buffer) }
	for offset in [u64(0), size - span]! {
		mut res := unsafe { disk.resource }
		got := res.read(unsafe { nil }, buffer, offset, span) or { return false }
		if u64(got) != span {
			return false
		}
		words := unsafe { &u64(buffer) }
		for i in 0 .. span / 8 {
			if unsafe { words[i] } != 0 {
				return false
			}
		}
	}
	return true
}

// The id of the image installed on a volume, or '' when it has none.
fn read_id(root &fs.VFSNode) string {
	return read_named_id(root, id_name)
}

fn read_named_id(root &fs.VFSNode, name string) string {
	node := fs.get_node(root, name, false) or { return '' }
	if node.resource == unsafe { nil } || !stat.isreg(node.resource.stat.mode)
		|| node.symlink_target.len != 0 {
		return ''
	}
	size := u64(node.resource.stat.size)
	if size == 0 || size > 256 {
		return ''
	}
	mut text := [256]u8{}
	mut res := unsafe { node.resource }
	got := res.read(unsafe { nil }, &text[0], 0, size) or { return '' }
	if got != i64(size) { return '' }
	mut length := int(got)
	for length > 0 && text[length - 1] <= ` ` {
		length--
	}
	return unsafe { tos(&text[0], length) }.clone()
}

// Record `id` as the image the root holds. It is padded with spaces over a
// longer earlier id rather than truncated; readers trim them.
fn write_id(id string) {
	if !write_named_id(vfs_root, id_file, id) {
		println('sysdisk: could not record the image id')
	}
}

fn write_named_id(root &fs.VFSNode, name string, id string) bool {
	mut node := fs.get_node(root, name, false) or {
		fs.create(root, name, stat.ifreg | 0o644) or { return false }
	}
	if node.resource == unsafe { nil } || !stat.isreg(node.resource.stat.mode)
		|| node.symlink_target.len != 0 {
		return false
	}
	mut res := node.resource
	old_size := u64(res.stat.size)
	mut text := [256]u8{}
	length := if u64(id.len) > old_size { u64(id.len) } else { old_size }
	if length > 256 {
		return false
	}
	for i in 0 .. length {
		text[i] = if i < u64(id.len) { id[i] } else { ` ` }
	}
	got := res.write(unsafe { nil }, &text[0], 0, length) or { return false }
	return got == i64(length)
}

// Mark the system on the disk as `image`, once all of it is there: the image
// is written out before the id that vouches for it, so a machine switched off
// at any point either has the whole image or a `pending` one to redo.
fn commit(image string) {
	pagecache.sync_all()
	mark(image)
}

// Record `id` and see that it reaches the disk.
fn mark(id string) {
	write_id(id)
	pagecache.sync_all()
}

fn report(what string, disk &fs.VFSNode, tail string) {
	size_gib := u64(disk.resource.stat.size) >> 30
	print(what)
	print(' /dev/')
	print(disk.name)
	print(' (')
	C.kprintf(c'%llu', size_gib)
	print(' GiB)')
	println(tail)
}
