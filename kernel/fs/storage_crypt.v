// SPDX-License-Identifier: GPL-2.0-or-later
module fs

import aesxts
import errno
import kbudget
import memory
import proc

// A page-sized workspace amortizes backend command setup across native sectors.
// Key-use critical sections still cover one sector; backend I/O covers at most
// one page. Both serialize with removal. Copy/allocator admission stays outside
// the volume lock, and caller plaintext is never encrypted in place.
fn (mut volume LogicalVolume) encrypted_transfer(buffer voidptr, offset u64, bytes u64, writing bool) ?i64 {
	volume.l.acquire()
	size := u64(volume.stat.size); sector := u64(volume.stat.blksize)
	removed := volume.removed; readonly := volume.readonly
	volume.l.release()
	if removed { errno.set(errno.enodev); return none }
	if writing && readonly { errno.set(errno.erofs); return none }
	if sector == 0 || offset > size || bytes > size - offset || offset % sector != 0 || bytes % sector != 0 { errno.set(errno.einval); return none }
	if bytes == 0 { return 0 }
	if buffer == unsafe { nil } { errno.set(errno.efault); return none }
	capacity := if bytes < 4096 { bytes } else if sector > 4096 { sector } else { u64(4096) / sector * sector }
	charge := proc.reserve_kernel(.file, capacity)?; defer { kbudget.release(charge) }
	workspace := memory.malloc_packed_fallible(capacity) @[freed]
	if workspace == unsafe { nil } { errno.set(errno.enomem); return none }
	defer { aesxts.erase(workspace, usize(capacity)); memory.free(workspace) }
	for done := u64(0); done < bytes; {
		chunk := if bytes - done < capacity { bytes - done } else { capacity }
		if writing { unsafe { C.memcpy(workspace, &u8(buffer) + done, usize(chunk)) } }
		else { volume.encrypted_io(workspace, offset + done, chunk, false)? }
		for part := u64(0); part < chunk; part += sector {
			volume.crypt_sector(voidptr(u64(workspace) + part), offset + done + part, sector, writing)?
		}
		if writing { volume.encrypted_io(workspace, offset + done, chunk, true)? }
		else { unsafe { C.memcpy(&u8(buffer) + done, workspace, usize(chunk)) } }
		done += chunk
	}
	volume.metrics.completed(bytes, writing)
	return i64(bytes)
}

fn (mut volume LogicalVolume) crypt_sector(workspace voidptr, offset u64, sector u64, writing bool) ? {
	volume.l.acquire(); defer { volume.l.release() }
	if volume.removed { errno.set(errno.enodev); return none }
	if !aesxts.crypt(&volume.cipher, workspace, sector, sector, offset / sector, !writing) { errno.set(errno.eio); volume.metrics.failed(); return none }
}

fn (mut volume LogicalVolume) encrypted_io(workspace voidptr, offset u64, bytes u64, writing bool) ? {
	volume.l.acquire(); defer { volume.l.release() }
	if volume.removed { errno.set(errno.enodev); return none }
	mut result := i64(0)
	if writing { result = volume.parent.write(unsafe { nil }, workspace, volume.parent_offset + offset, bytes) or { volume.metrics.failed(); return none } }
	else { result = volume.parent.read(unsafe { nil }, workspace, volume.parent_offset + offset, bytes) or { volume.metrics.failed(); return none } }
	if result != i64(bytes) { errno.set(errno.eio); volume.metrics.failed(); return none }
}
