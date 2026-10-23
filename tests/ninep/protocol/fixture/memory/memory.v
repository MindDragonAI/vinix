@[has_globals]
module memory

fn C.memset(voidptr, int, usize) voidptr
fn C.free(voidptr)
fn C.malloc(usize) voidptr

__global (
	pages int
	fail_page bool
)

pub fn live_pages() int { return pages }
pub fn fail_next_page() { fail_page = true }

pub fn pmm_alloc_user(n u64) voidptr {
	assert n == 1
	if fail_page { fail_page = false; return unsafe { nil } }
	p := C.malloc(4096)
	C.memset(p, 0, 4096)
	pages++
	return p
}

pub fn pmm_free(p voidptr, n u64) {
	assert n == 1 && p != unsafe { nil } && pages > 0
	pages--
	C.free(p)
}

pub fn malloc_packed_fallible(n u64) voidptr { return C.malloc(usize(n)) }

pub fn free(p voidptr) {
	C.free(p)
}
