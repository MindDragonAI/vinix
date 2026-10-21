// SPDX-License-Identifier: GPL-2.0-or-later
@[has_globals]
module fs

import errno
import file
import proc
import resource
import security

__global block_formatter fn (&VFSNode, string) bool = unsafe { nil }

pub fn register_block_formatter(formatter fn (&VFSNode, string) bool) {
	block_formatter = formatter
}

fn format_encrypted_home(mut descriptor file.FD) ?int {
	if !storage_admin() || security.securelevel() >= 2 {
		errno.set(errno.eperm); return none
	}
	if descriptor.handle.flags & resource.o_accmode != resource.o_rdwr
		|| descriptor.handle.flags & resource.o_path != 0 {
		errno.set(errno.ebadf); return none
	}
	descriptor.handle.mac_check(proc.mac_write)?
	mut backend := descriptor.handle.resource
	if mut backend is LogicalVolume {
		logical_volumes_lock.acquire()
		if !backend.encrypted || backend.readonly || backend.removed
			|| block_formatter == unsafe { nil } {
			logical_volumes_lock.release(); errno.set(errno.einval); return none
		}
		// Excludes mounts, retained caches, swap and concurrent raw writes.
		token := security.begin_block_reconfigure(backend.identity) or {
			logical_volumes_lock.release(); return none
		}
		// The reservation prevents removal/resize after dropping this IRQ
		// masking lock. Never hold it across allocator or formatter I/O.
		logical_volumes_lock.release()
		defer { security.end_block_reconfigure(token) }
		mut node := unsafe { &VFSNode(C.vinix_stack_alloc(sizeof(VFSNode))) }
		unsafe { *node = VFSNode{resource: descriptor.handle.resource} }
		if !block_formatter(node, 'Encrypted home') { errno.set(errno.eio); return none }
		return 0
	}
	errno.set(errno.enotty); return none
}
