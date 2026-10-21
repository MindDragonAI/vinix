module main

import crypto.sha256
import encoding.hex

const mib = i64(1024 * 1024)
const esp_bytes = i64(1024 * 1024 * 1024)
const root_start = mib + esp_bytes
const meta_at = i64(32768)
const meta_bytes = 65536

struct Geometry {
	root_bytes i64
	disk_bytes i64
}

fn geometry(bytes i64) !Geometry {
	if bytes < i64(4) * 1024 * 1024 * 1024 || bytes % 4096 != 0 || bytes > i64(1) << 50 {
		return error('root must be >=4 GiB, 4096-byte aligned, and <=1 PiB')
	}
	return Geometry{bytes, ((root_start + bytes + mib - 1) / mib + 1) * mib}
}

fn put(mut b []u8, at int, value u64, width int) {
	for i in 0 .. width { b[at + i] = u8(value >> (8 * i)) }
}

fn get(b []u8, at int, width int) u64 {
	mut v := u64(0)
	for i in 0 .. width { v |= u64(b[at + i]) << (8 * i) }
	return v
}

fn stamp(mut b []u8, at int, data []u8) {
	for i, v in data { b[at + i] = v }
}

fn crc(data []u8, polynomial u32) u32 {
	mut c := u32(0xffffffff)
	for byte in data {
		c ^= byte
		for _ in 0 .. 8 { c = (c >> 1) ^ (polynomial & (u32(0) - (c & 1))) }
	}
	return ~c
}

fn crc32(data []u8) u32 { return crc(data, 0xedb88320) }

fn guid(token string, kind string) []u8 {
	return sha256.sum((token + ':' + kind).bytes())[..16].clone()
}

fn gpt_entries(g Geometry, token string) ![]u8 {
	mut e := []u8{len: 16384}
	stamp(mut e, 0, hex.decode('28732ac11ff8d211ba4b00a0c93ec93b')!)
	stamp(mut e, 16, guid(token, 'esp'))
	put(mut e, 32, u64(mib / 512), 8)
	put(mut e, 40, u64(root_start / 512 - 1), 8)
	stamp(mut e, 128, hex.decode('af3dc60f838472478e793d69d8477de4')!)
	stamp(mut e, 144, guid(token, 'root'))
	put(mut e, 160, u64(root_start / 512), 8)
	put(mut e, 168, u64((root_start + g.root_bytes) / 512 - 1), 8)
	for i, ch in 'VINIX ESP'.bytes() { e[56 + 2 * i] = ch }
	for i, ch in 'VINIX ROOT'.bytes() { e[184 + 2 * i] = ch }
	return e
}

fn gpt_header(g Geometry, token string, entries []u8, backup bool) []u8 {
	last := u64(g.disk_bytes / 512 - 1)
	mut b := []u8{len: 512}
	stamp(mut b, 0, 'EFI PART'.bytes())
	put(mut b, 8, 0x10000, 4)
	put(mut b, 12, 92, 4)
	put(mut b, 24, if backup { last } else { u64(1) }, 8)
	put(mut b, 32, if backup { u64(1) } else { last }, 8)
	put(mut b, 40, 34, 8)
	put(mut b, 48, last - 33, 8)
	stamp(mut b, 56, guid(token, 'disk'))
	put(mut b, 72, if backup { last - 32 } else { u64(2) }, 8)
	put(mut b, 80, 128, 4)
	put(mut b, 84, 128, 4)
	put(mut b, 88, crc32(entries), 4)
	put(mut b, 16, crc32(b[..92]), 4)
	return b
}

fn mbr(g Geometry) []u8 {
	mut b := []u8{len: 512}
	b[447] = 0
	b[448] = 2
	b[450] = 0xee
	for i in 451 .. 454 { b[i] = 0xff }
	put(mut b, 454, 1, 4)
	sectors := u64(g.disk_bytes / 512 - 1)
	put(mut b, 458, if sectors > 0xffffffff { u64(0xffffffff) } else { sectors }, 4)
	b[510] = 0x55
	b[511] = 0xaa
	return b
}

fn write_gpt(fd int, g Geometry, token string) ! {
	e := gpt_entries(g, token)!
	write_at(fd, 0, mbr(g))!
	write_at(fd, 512, gpt_header(g, token, e, false))!
	write_at(fd, 1024, e)!
	write_at(fd, g.disk_bytes - 33 * 512, e)!
	write_at(fd, g.disk_bytes - 512, gpt_header(g, token, e, true))!
}

fn verify_gpt(fd int, g Geometry, token string) ! {
	e := gpt_entries(g, token)!
	if read_at(fd, 0, 512)! != mbr(g) || read_at(fd, 512, 512)! != gpt_header(g, token, e, false)
		|| read_at(fd, 1024, e.len)! != e || read_at(fd, g.disk_bytes - 33 * 512, e.len)! != e
		|| read_at(fd, g.disk_bytes - 512, 512)! != gpt_header(g, token, e, true) {
		return error('GPT/MBR geometry, ownership or CRC mismatch')
	}
}

fn hex_text(s string, n int) bool {
	return s.len == n && s.bytes().all(it.is_digit() || (it >= `a` && it <= `f`))
}

fn marker(token string, bytes i64, image_id string) ![]u8 {
	if !hex_text(token, 32) || !hex_text(image_id, 16) || bytes <= 0 {
		return error('invalid root marker fields')
	}
	mut b := []u8{len: 512}
	// Exactly sixteen ASCII bytes, including the final newline (no NUL).
	stamp(mut b, 0, 'VINIX-SYSDISK-1\n'.bytes())
	stamp(mut b, 16, token.bytes())
	stamp(mut b, 48, '${u64(bytes):016x}'.bytes())
	stamp(mut b, 64, image_id.bytes())
	return b
}

fn validate_root(fd int, at i64, bytes i64) ! {
	geometry(bytes)!
	sb := read_at(fd, at + 1024, 1024)!
	if get(sb, 56, 2) != 0x4a56 {
		return error('source/root is not private VJFS (signature 0x4a56 at 1080)')
	}
	journal_at := bytes / 4096 * 4096 - 4 * 1024 * 1024
	mut journal := read_at(fd, at + journal_at, 4096)!
	stored := get(journal, 56, 4)
	put(mut journal, 56, 0, 4)
	if journal[..8].bytestr() != 'VNIXJNL1' || get(journal, 8, 4) != 1 || get(journal, 12, 4) != 4096
		|| get(journal, 24, 8) != u64(journal_at) || get(journal, 32, 8) != 4 * 1024 * 1024
		|| get(journal, 16, 8) != get(sb, 4, 4) * 4096 || get(sb, 24, 4) != 2
		|| get(journal, 16, 8) == 0 || get(journal, 16, 8) > u64(journal_at)
		|| journal[40..56] != sb[104..120] || u64(crc(journal, 0x82f63b78)) != stored {
		return error('invalid fixed-end VJFS journal configuration/CRC/UUID/geometry')
	}
	if read_at(fd, at + journal_at + 4096, 4096)!.any(it != 0) {
		return error('VJFS has pending journal data; recover and cleanly shut down before offline use')
	}
}
