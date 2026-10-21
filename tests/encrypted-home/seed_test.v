// SPDX-License-Identifier: GPL-2.0-or-later
module krandom

#include <string.h>
fn C.vinix_hw_random64(&u64) int
__global (seed_draws int seed_fail_at int = -1)

@[export: 'vinix_hw_random64']
fn seed_hardware(out &u64) int {
	if seed_draws == seed_fail_at { return 0 }
	seed_draws++
	unsafe { *out = u64(seed_draws) * u64(0x123456789abcdef) }
	return 1
}

fn test_checked_initial_seed_failure_erases_partial_seed() {
	for fail in 0 .. 8 {
		seed_draws = 0; seed_fail_at = fail
		mut bytes := [64]u8{init: 0xa5}
		assert !architecture_seed(mut bytes)
		assert seed_draws == fail
		assert bytes == [64]u8{}
	}
	seed_draws = 0; seed_fail_at = -1
	mut bytes := [64]u8{}
	assert architecture_seed(mut bytes)
	assert seed_draws == 8 && bytes != [64]u8{}
}
