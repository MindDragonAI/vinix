@[has_globals]
module kbudget
__global outstanding u64
__global reject bool
pub fn reserve(bytes u64) bool {
	if reject { return false }
	outstanding += bytes
	return true
}
pub fn release(bytes u64) { assert outstanding >= bytes; outstanding -= bytes }
pub fn outstanding_bytes() u64 { return outstanding }
pub fn set_reject(value bool) { reject = value }
