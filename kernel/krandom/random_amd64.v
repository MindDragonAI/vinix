module krandom

import x86.cpu

// Availability alone is insufficient: check carry on every bounded draw.
fn architecture_seed(mut output [64]u8) bool {
	for i in 0 .. 8 {
		mut word := u64(0)
		if C.vinix_hw_random64(unsafe { &word }) == 0 {
			explicit_bzero(&output[0], 64)
			return false
		}
		unsafe { C.memcpy(&output[i * 8], &word, 8) }
		explicit_bzero(unsafe { &word }, sizeof(word))
	}
	return true
}

fn cycle_counter() u64 { return cpu.rdtsc() }
