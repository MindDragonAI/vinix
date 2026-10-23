module fs

import aesxts
import errno

#include <string.h>
fn C.memcpy(voidptr, voidptr, usize) voidptr

struct TestStat { size i64 blksize i64 }
struct TestLock {
mut:
	depth int
	releases int
	remove_after int
	owner &LogicalVolume = unsafe { nil }
}
fn (mut l TestLock) acquire() { assert l.depth == 0; l.depth = 1 }
fn (mut l TestLock) release() {
	assert l.depth == 1
	l.depth = 0; l.releases++
	if l.remove_after > 0 && l.releases == l.remove_after { l.owner.removed = true }
}
struct TestMetrics {
mut:
	bytes u64
	failures int
}
fn (mut m TestMetrics) completed(bytes u64, _ bool) { m.bytes += bytes }
fn (mut m TestMetrics) failed() { m.failures++ }

struct TestParent {
mut:
	data []u8
	lock &TestLock = unsafe { nil }
	reads int
	writes int
	maximum u64
	fail_at int
	short_at int
}
fn (mut p TestParent) io(buffer voidptr, loc u64, count u64, writing bool) ?i64 {
	assert p.lock.depth == 1, 'backend I/O must serialize with removal'
	assert loc <= u64(p.data.len) && count <= u64(p.data.len) - loc
	if writing { p.writes++ } else { p.reads++ }
	if count > p.maximum { p.maximum = count }
	op := p.reads + p.writes
	if op == p.fail_at { errno.set(errno.eio); return none }
	if op == p.short_at { return i64(count) - 1 }
	unsafe {
		if writing { C.memcpy(&p.data[int(loc)], buffer, usize(count)) }
		else { C.memcpy(buffer, &p.data[int(loc)], usize(count)) }
	}
	return i64(count)
}
fn (mut p TestParent) read(_ voidptr, buffer voidptr, loc u64, count u64) ?i64 { return p.io(buffer, loc, count, false) }
fn (mut p TestParent) write(_ voidptr, buffer voidptr, loc u64, count u64) ?i64 { return p.io(buffer, loc, count, true) }

struct LogicalVolume {
mut:
	l TestLock
	stat TestStat
	removed bool
	readonly bool
	cipher aesxts.Cipher
	parent TestParent
	parent_offset u64
	metrics TestMetrics
}

fn volume(bytes int, sector int) &LogicalVolume {
	mut v := &LogicalVolume{
		stat: TestStat{size: bytes, blksize: sector}
		parent: TestParent{data: []u8{len: bytes + 8192, init: 0xa5}}
		parent_offset: 4096
	}
	v.l.owner = v
	v.parent.lock = unsafe { &v.l }
	mut key := [64]u8{}
	for i in 0 .. 64 { key[i] = u8(i * 37 + 19) }
	assert aesxts.initialize(mut v.cipher, &key)
	return v
}
