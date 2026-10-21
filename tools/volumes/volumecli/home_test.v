// SPDX-License-Identifier: GPL-2.0-or-later
module volumecli

import os

fn home_test_rng(output &u8, size int) bool {
	unsafe { for i in 0 .. size { output[i] = u8(i * 17 + 3) } }
	return true
}
fn home_test_no_entropy(_ &u8, _ int) bool { return false }

fn test_home_child_erases_the_entire_supervisor_not_its_pointer_size() {
	mut state := HomeSupervisor{}
	mut zero := HomeSupervisor{}
	unsafe { C.memset(&state, 0xa5, sizeof(HomeSupervisor)); C.memset(&zero, 0, sizeof(HomeSupervisor)) }
	home_erase_state(mut state)
	assert unsafe { C.memcmp(&state, &zero, sizeof(HomeSupervisor)) == 0 }
}

fn test_home_compile_time_entropy_failure() {
	$if home_entropy_failure ? {
		mut state := HomeSupervisor{fresh: true, bytes: 128 * 1024 * 1024, sector: 512}
		assert !home_prepare(mut state, home_entropy)
		assert state.phase == .failed && state.key == [64]u8{}
	}
}

fn test_home_blank_scan_rejects_middle_occupancy_and_short_reads() {
	path := os.join_path(os.temp_dir(), 'vinix-home-blank-' + os.getpid().str())
	fd := C.open(path.str, C.O_RDWR | C.O_CREAT | C.O_EXCL | C.O_CLOEXEC, u32(0o600))
	assert fd >= 0
	defer { C.close(fd); os.rm(path) or {} }
	mut zeros := [131072]u8{}
	assert home_transfer(fd, &zeros[0], zeros.len, true)
	assert home_blank(fd, u64(zeros.len))
	mut occupied := u8(1)
	assert C.pwrite(fd, &occupied, 1, 65432) == 1
	assert !home_blank(fd, u64(zeros.len))
	occupied = 0
	assert C.pwrite(fd, &occupied, 1, 65432) == 1
	assert !home_blank(fd, u64(zeros.len + 4096))
	mut locked := HomeSupervisor{}
	assert !home_activate(-1, mut locked)
}

fn test_home_words_and_normalization() {
	assert home_words.split_into_lines().len == 2048
	mut out := [128]u8{}
	input := '  ABANDON\tability\nable about above absent absorb abstract absurd abuse access accident \r\n'
	n := home_normalize(input.str, input.len, &out[0])
	assert n > 0
	assert unsafe { tos(&out[0], n) } == 'abandon ability able about above absent absorb abstract absurd abuse access accident'
	for bad in ['abandon', 'abandon ability able about above absent absorb abstract absurd abuse access nonword',
		'abandon ability able about above absent absorb abstract absurd abuse access accidént'] {
		assert home_normalize(bad.str, bad.len, &out[0]) == 0
	}
	mut random := [24]u8{init: 255}
	n2 := home_phrase(&random, &out[0])
	assert unsafe { tos(&out[0], n2) } == 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo'
}

fn test_home_enrollment_entropy_failure_and_state_denials() {
	mut state := HomeSupervisor{fresh: true, bytes: 128 * 1024 * 1024, sector: 512}
	assert !home_prepare(mut state, home_test_no_entropy)
	assert state.phase == .failed && state.key == [64]u8{}
	assert !home_unlock(mut state, c'anything', 8, false, 100)
	assert !home_enroll(mut state, c'anything', 8, c'', 0, true)
	assert !home_prepare(mut state, home_test_rng)
}

fn test_home_shared_budget_survives_ui_replacement_and_clock_rollback() {
	mut budget := HomeBudget{}
	for i in 0 .. 3 { assert budget.allowed(10); budget.reject(10); assert budget.failures == u32(i + 1) }
	assert budget.until == 12 && !budget.allowed(11)
	// A new UI has no budget. Its next request reaches this same object.
	assert !budget.allowed(9)
	assert budget.allowed(12); budget.reject(12); assert budget.until == 16
	for i in 0 .. 20 { now := i64(1000 + i * 400); assert budget.allowed(now); budget.reject(now); assert budget.until <= now + 300 }
}

fn test_home_dual_slot_exact_password_geometry_and_persistence() {
	mut enrolled := HomeSupervisor{fresh: true, bytes: 128 * 1024 * 1024, sector: 512}
	assert home_prepare(mut enrolled, home_test_rng)
	phrase := enrolled.phrase
	n := enrolled.phrase_size
	assert !home_enroll(mut enrolled, &phrase[0], n, c'Exact Password ', 15, false)
	assert home_enroll(mut enrolled, &phrase[0], n, c'Exact Password ', 15, true)
	assert enrolled.phase == .mounting
	assert home_header_valid(&enrolled.header, enrolled.bytes, enrolled.sector)
	mut candidate := HomeSupervisor{header: enrolled.header, bytes: enrolled.bytes, sector: enrolled.sector}
	assert !home_unlock(mut candidate, c'exact password ', 15, true, 1)
	assert !home_unlock(mut candidate, c'Exact Password', 14, true, 2)
	assert home_unlock(mut candidate, c'Exact Password ', 15, true, 3)
	assert candidate.key == enrolled.key
	assert !home_unlock(mut candidate, &phrase[0], n, false, 4)
	mut words := HomeSupervisor{header: enrolled.header, bytes: enrolled.bytes, sector: enrolled.sector}
	assert home_unlock(mut words, &phrase[0], n, false, 1)
	assert words.key == enrolled.key
	// Only authenticated ciphertext and public geometry/identity are persisted.
	for i in 0 .. 4096 - 64 { assert !recovery_equal(&enrolled.header[i], &enrolled.key[0], 64) }
	for i in 0 .. 4096 - n { assert !recovery_equal(&enrolled.header[i], &phrase[0], n) }
	for i in 0 .. 4096 - 15 { assert !recovery_equal(&enrolled.header[i], c'Exact Password ', 15) }
	for index in [0, 8, 12, 13, 16, 24, 32, 40, 48, 64, 128, 448, 4095] {
		mut bad := enrolled.header; bad[index] ^= 128
		if home_header_valid(&bad, enrolled.bytes, enrolled.sector) {
			mut rejected := HomeSupervisor{header: bad, bytes: enrolled.bytes, sector: enrolled.sector}
			assert !home_unlock(mut rejected, &phrase[0], n, false, 1)
		}
	}
	assert !home_header_valid(&enrolled.header, enrolled.bytes + 4096, enrolled.sector)
	assert !home_header_valid(&enrolled.header, enrolled.bytes, 4096)
}

fn test_home_phrase_order_changed_unknown_and_phrase_only() {
	mut state := HomeSupervisor{fresh: true, bytes: 128 * 1024 * 1024, sector: 4096}
	assert home_prepare(mut state, home_test_rng)
	phrase := state.phrase; n := state.phrase_size
	assert home_enroll(mut state, &phrase[0], n, c'', 0, true)
	assert state.header[12] == 1
	canonical := unsafe { tos(&phrase[0], n) }
	mut pieces := canonical.split(' ')
	first := pieces[0]; pieces[0] = pieces[1]; pieces[1] = first
	reordered := pieces.join(' ')
	pieces[0] = 'abandon'; changed := pieces.join(' ')
	pieces[0] = 'nonword'; unknown := pieces.join(' ')
	for secret in [reordered, changed, unknown] {
		mut locked := HomeSupervisor{header: state.header, bytes: state.bytes, sector: state.sector}
		assert !home_unlock(mut locked, secret.str, secret.len, false, 100)
		assert locked.phase == .locked && locked.key == [64]u8{}
	}
	mut locked := HomeSupervisor{header: state.header, bytes: state.bytes, sector: state.sector}
	assert !home_unlock(mut locked, c'password', 8, true, 1)
	assert home_unlock(mut locked, &phrase[0], n, false, 2)
	assert locked.key == state.key
}
