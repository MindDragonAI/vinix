// SPDX-License-Identifier: GPL-2.0-or-later
// Measure the production encrypted-volume primitive, without disk or SSH.
module main

import aesxts
import time

fn main() {
	mut key := [64]u8{}
	for i in 0 .. 64 { key[i] = u8(i * 37 + 19) }
	mut cipher := aesxts.Cipher{}
	if !aesxts.initialize(mut cipher, &key) { panic('initialize') }
	defer { aesxts.clear(mut cipher); aesxts.erase(&key[0], sizeof(key)) }
	mut data := []u8{len: 65536}
	for i in 0 .. data.len { data[i] = u8(i * 13 + 7) }
	for decrypt in [false, true] {
		start := time.sys_mono_now()
		for _ in 0 .. 16 {
			if !aesxts.crypt(&cipher, data.data, 65536, 512, 0, decrypt) { panic('crypt') }
		}
		ns := time.sys_mono_now() - start
		println('XTS-THROUGHPUT decrypt=${decrypt} bytes=1048576 elapsed_ms=${ns/1000000} MiB_s=${1.0e9/f64(ns):.3f}')
	}
	for i in 0 .. data.len { if data[i] != u8(i * 13 + 7) { panic('roundtrip mismatch') } }
	println('XTS-THROUGHPUT PASS')
}
