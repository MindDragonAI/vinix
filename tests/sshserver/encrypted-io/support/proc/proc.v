module proc
import kbudget
import errno
pub enum Kind { file }
pub fn reserve_kernel(_ Kind, bytes u64) ?u64 {
	if !kbudget.reserve(bytes) { errno.set(errno.enomem); return none }
	return bytes
}
