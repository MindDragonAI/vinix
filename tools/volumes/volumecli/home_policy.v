// SPDX-License-Identifier: GPL-2.0-or-later
module volumecli

const home_data_offset = u64(1048576)
const home_header_bytes = 4096

enum HomePhase { locked enrollment mounting session failed }

struct HomeBudget {
mut:
	failures u32
	until i64
	last i64
}

fn (mut budget HomeBudget) allowed(now i64) bool {
	if now < budget.last { return false }
	budget.last = now
	return now >= budget.until
}

fn (mut budget HomeBudget) reject(now i64) {
	if budget.failures < 32 { budget.failures++ }
	if budget.failures < 3 { return }
	shift := if budget.failures - 3 > 8 { u32(8) } else { budget.failures - 3 }
	delay := i64(2) << shift
	budget.until = now + if delay > 300 { i64(300) } else { delay }
}

fn home_space(ch u8) bool { return ch == 32 || (ch >= 9 && ch <= 13) }

@[direct_array_access]
fn home_word(index int, output &u8) int {
	mut word := 0
	mut start := 0
	for i in 0 .. home_words.len {
		if home_words[i] != `\n` { continue }
		if word == index {
			unsafe { C.memcpy(output, &home_words[start], i - start) }
			return i - start
		}
		start = i + 1; word++
	}
	return 0
}

@[direct_array_access]
fn home_known(word &u8, size int) bool {
	mut start := 0
	for i in 0 .. home_words.len {
		if home_words[i] != `\n` { continue }
		if i - start == size && recovery_equal(word, unsafe { &u8(&home_words[start]) }, size) { return true }
		start = i + 1
	}
	return false
}

// Only phrases are normalized. Passwords remain exact bytes.
fn home_normalize(input &u8, size int, output &u8) int {
	if size <= 0 || size > 1024 { return 0 }
	mut count := 0; mut used := 0; mut word_start := 0; mut in_word := false
	unsafe {
		for i in 0 .. size + 1 {
			ch := if i == size { u8(32) } else { input[i] }
			if home_space(ch) {
				if !in_word { continue }
				if !home_known(output + word_start, used - word_start) { return 0 }
				count++; in_word = false
			} else {
				if !in_word {
					if count >= 12 { return 0 }
					if used != 0 { output[used] = 32; used++ }
					word_start = used; in_word = true
				}
				if used >= 127 || !((ch >= `a` && ch <= `z`) || (ch >= `A` && ch <= `Z`)) { return 0 }
				output[used] = if ch >= `A` && ch <= `Z` { ch + 32 } else { ch }; used++
			}
		}
	}
	return if count == 12 { used } else { 0 }
}

@[direct_array_access]
fn home_phrase(random &[24]u8, output &u8) int {
	mut used := 0
	for i in 0 .. 12 {
		if i != 0 { unsafe { output[used] = 32 }; used++ }
		// 16-bit uniform draws truncated to 11 bits: no modulo bias.
		index := (int(random[i * 2]) | int(random[i * 2 + 1]) << 8) & 2047
		used += home_word(index, unsafe { output + used })
	}
	return used
}

@[direct_array_access]
fn home_header_valid(header &[4096]u8, bytes u64, sector u64) bool {
	if bytes < 64 * 1024 * 1024 || bytes >= u64(4) * 1024 * 1024 * 1024
		|| (sector != 512 && sector != 4096) || bytes % 4096 != 0
		|| !recovery_equal(&header[0], unsafe { &u8(c'VINIXHM1') }, 8)
		|| get_le(&header[0], 8, 4) != 1 || header[12] < 1 || header[12] > 2 { return false }
	for i in 13 .. 16 { if header[i] != 0 { return false } }
	if get_le(&header[0], 16, 8) != bytes || get_le(&header[0], 24, 8) != sector
		|| get_le(&header[0], 32, 8) != home_data_offset
		|| get_le(&header[0], 40, 8) != bytes - home_data_offset { return false }
	for i in 64 .. 128 { if header[i] != 0 { return false } }
	for slot in 0 .. int(header[12]) {
		at := 128 + slot * 320
		if !volume_seal_header(unsafe { &header[at] }, 320) { return false }
		disk := volume_seal_disk(unsafe { &header[at] })
		row := volume_seal_row(unsafe { &header[at] })
		if disk.bytes != bytes || disk.sector != sector || disk.kind != 2
			|| !recovery_equal(&disk.id[0], &header[48], 16)
			|| row.slot != 63 || row.flags != 0 || row.offset != home_data_offset
			|| row.length != bytes - home_data_offset { return false }
	}
	for i in 128 + int(header[12]) * 320 .. 4096 { if header[i] != 0 { return false } }
	return true
}
