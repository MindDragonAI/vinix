@[has_globals]
module errno
pub const enodev = 19
pub const erofs = 30
pub const einval = 22
pub const efault = 14
pub const enomem = 12
pub const eio = 5
__global last int
pub fn set(value int) { last = value }
pub fn last_error() int { return last }
