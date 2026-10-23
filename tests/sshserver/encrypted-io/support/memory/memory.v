@[has_globals]
module memory
#include <stdlib.h>
fn C.malloc(usize) voidptr
fn C.free(voidptr)
__global live int
__global fail bool
__global last_bytes u64
pub fn live_count() int { return live }
pub fn set_fail(value bool) { fail = value }
pub fn malloc_packed_fallible(bytes u64) voidptr {
	assert live == 0
	last_bytes = bytes
	if fail { return unsafe { nil } }
	p := C.malloc(usize(bytes))
	if p != unsafe { nil } { live++ }
	return p
}
pub fn free(pointer voidptr) {
	assert live == 1
	// Validate the production defer erased the entire allocation before free.
	unsafe { for i := u64(0); i < last_bytes; i++ { assert (&u8(pointer))[i] == 0 } }
	live--
	C.free(pointer)
}
