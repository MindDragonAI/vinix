module fs

import aesxts
import errno
import kbudget
import memory

fn rejected(mut v LogicalVolume, buffer voidptr, offset u64, bytes u64, writing bool) bool {
	v.encrypted_transfer(buffer, offset, bytes, writing) or { return true }
	return false
}

fn clean() { assert memory.live_count() == 0 && kbudget.outstanding_bytes() == 0 }

fn test_production_transfer_batches_io_and_preserves_ciphertext_units() {
	for sector in [512, 4096] {
		mut v := volume(65536, sector)
		mut source := []u8{len: 32768 + sector}
		for i in 0 .. source.len { source[i] = u8(i * 13 + 7) }
		original := source.clone()
		offset := u64(sector)
		written := v.encrypted_transfer(source.data, offset, u64(source.len), true) or { panic('write failed') }
		assert written == source.len
		assert source == original, 'write must not encrypt caller memory in place'
		clean()
		mut expected := source.clone()
		assert aesxts.crypt(&v.cipher, expected.data, u64(expected.len), u64(sector), 1, false)
		assert v.parent.data[4096 + sector .. 4096 + sector + source.len] == expected
		assert v.parent.data[4096 + sector - 1] == 0xa5
		assert v.parent.data[4096 + sector + source.len] == 0xa5
		mut returned := []u8{len: source.len}
		read := v.encrypted_transfer(returned.data, offset, u64(returned.len), false) or { panic('read failed') }
		assert read == returned.len
		assert returned == original
		clean()
		calls := (source.len + 4095) / 4096
		println('CRYPT-IO sector=${sector} bytes=${source.len} writes=${v.parent.writes} reads=${v.parent.reads} maximum=${v.parent.maximum}')
		assert v.parent.writes == calls && v.parent.reads == calls
		assert v.parent.maximum <= 4096
		assert v.metrics.bytes == u64(source.len * 2) && v.metrics.failures == 0
	}
}

fn test_errors_removal_and_allocation_failure_release_and_wipe_workspace() {
	for writing in [false, true] {
		for short in [false, true] {
			mut v := volume(16384, 512)
			mut data := []u8{len: 8192, init: 0x73}
			if short { v.parent.short_at = 1 } else { v.parent.fail_at = 1 }
			assert rejected(mut v, data.data, 0, u64(data.len), writing)
			assert v.parent.reads + v.parent.writes == 1 && v.metrics.failures == 1
			assert v.l.depth == 0 && errno.last_error() == errno.eio
			if writing { for byte in data { assert byte == 0x73 } }
			clean()
		}
		mut v := volume(16384, 512)
		v.l.remove_after = 2 // After first read I/O, or first write encryption.
		mut data := []u8{len: 8192, init: 0x73}
		assert rejected(mut v, data.data, 0, u64(data.len), writing)
		assert v.removed && errno.last_error() == errno.enodev && v.l.depth == 0
		assert v.parent.writes == 0 && v.parent.reads == if writing { 0 } else { 1 }
		for byte in data { assert byte == 0x73 }
		clean()
	}
	for allocation in [false, true] {
		mut v := volume(8192, 512)
		mut data := []u8{len: 4096}
		if allocation { memory.set_fail(true) } else { kbudget.set_reject(true) }
		assert rejected(mut v, data.data, 0, 4096, true)
		memory.set_fail(false); kbudget.set_reject(false)
		assert errno.last_error() == errno.enomem && v.parent.writes == 0
		clean()
	}
}

fn test_preconditions_zero_and_readonly_do_not_reach_backend() {
	mut v := volume(8192, 512)
	mut data := []u8{len: 512}
	zero := v.encrypted_transfer(unsafe { nil }, 0, 0, false) or { panic('zero failed') }
	assert zero == 0
	assert rejected(mut v, data.data, 1, 512, false) && errno.last_error() == errno.einval
	assert rejected(mut v, data.data, 0, 513, false) && errno.last_error() == errno.einval
	assert rejected(mut v, data.data, 8192, 512, false) && errno.last_error() == errno.einval
	assert rejected(mut v, unsafe { nil }, 0, 512, false) && errno.last_error() == errno.efault
	v.readonly = true
	assert rejected(mut v, data.data, 0, 512, true) && errno.last_error() == errno.erofs
	v.removed = true
	assert rejected(mut v, data.data, 0, 512, false) && errno.last_error() == errno.enodev
	assert v.parent.reads == 0 && v.parent.writes == 0
	clean()
	println('CRYPT-IO preconditions/removal/failure/erasure PASS')
}
