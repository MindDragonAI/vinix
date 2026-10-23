// SPDX-License-Identifier: GPL-2.0-or-later
module fs

import errno
import memory
import memory.mmap
import stat

// Network mappings are private snapshots. Shared mappings need coherent page
// caching and writeback, which these synchronous clients do not provide yet.
fn network_mmap_allowed(mode u32, flags int) bool {
	if !stat.isreg(mode) {
		errno.set(errno.enodev)
		return false
	}
	if flags & mmap.map_shared != 0 {
		errno.set(errno.enotsup)
		return false
	}
	return true
}

struct NetworkMmapPage {
	physical voidptr
	offset u64
	count u64
}

// Resource.mmap receives a FILE PAGE NUMBER, not a byte offset. Return one
// zeroed user-accounted physical page; only its direct-map alias is writable.
// The caller holds its backend lock across the size snapshot and bounded read,
// just as ext2 holds its filesystem lock. Never acquire Resource.l here: VFS
// callers can already hold it, and it does not serialize the wire client.
fn network_mmap_page(mode u32, size i64, page u64, flags int) ?NetworkMmapPage {
	if !network_mmap_allowed(mode, flags) { return none }
	if size < 0 || page > u64(0x7fffffffffffffff) / page_size {
		errno.set(errno.eoverflow)
		return none
	}
	offset := page * page_size
	count := if offset >= u64(size) { u64(0) } else if u64(size) - offset < page_size {
		u64(size) - offset
	} else { page_size }
	physical := memory.pmm_alloc_user(1)
	if physical == unsafe { nil } {
		errno.set(errno.enomem)
		return none
	}
	return NetworkMmapPage{physical, offset, count}
}

fn (page NetworkMmapPage) complete(got i64) voidptr {
	if got != i64(page.count) {
		memory.pmm_free(page.physical, 1)
		errno.set(errno.eio)
		return unsafe { nil }
	}
	return page.physical
}
