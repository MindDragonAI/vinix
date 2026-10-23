// SPDX-License-Identifier: GPL-2.0-or-later
module main

const max_packet = 262144
const max_command = 8192

struct Reader {
	data []u8
mut:
	pos int
}

fn (mut r Reader) byte() !u8 {
	if r.pos < 0 || r.pos >= r.data.len { return error('truncated byte') }
	b := r.data[r.pos]
	r.pos++
	return b
}

fn (mut r Reader) uint() !u32 {
	if r.pos < 0 || r.pos > r.data.len || r.data.len - r.pos < 4 {
		return error('truncated uint32')
	}
	p := r.pos
	r.pos += 4
	return u32(r.data[p]) << 24 | u32(r.data[p + 1]) << 16 | u32(r.data[p + 2]) << 8 | u32(r.data[p + 3])
}

fn (mut r Reader) string_bytes(limit int) ![]u8 {
	return r.string_view(limit)!.clone()
}

// Borrowed until the packet owner frees it; consumers must copy before retaining.
fn (mut r Reader) string_view(limit int) ![]u8 {
	if limit < 0 { return error('invalid string limit') }
	n := r.uint()!
	if n > u32(limit) || n > u32(r.data.len - r.pos) { return error('invalid string length') }
	p := r.pos
	r.pos += int(n)
	return unsafe { r.data[p..r.pos] }
}

fn (r Reader) end() ! {
	if r.pos != r.data.len { return error('trailing data') }
}

fn put_u32(mut b []u8, n u32) {
	b << u8(n >> 24)
	b << u8(n >> 16)
	b << u8(n >> 8)
	b << u8(n)
}

fn put_string(mut b []u8, s []u8) {
	put_u32(mut b, u32(s.len))
	b << s
}

fn text_packet(id u8, text string) []u8 {
	mut b := [id]
	put_string(mut b, text.bytes())
	return b
}

// RFC 8731: X25519 output is interpreted as an unsigned, big-endian integer.
fn secret_mpint(secret []u8) ![]u8 {
	if secret.len != 32 { return error('invalid shared secret size') }
	mut start := 0
	for start < secret.len && secret[start] == 0 { start++ }
	if start == secret.len { return error('zero shared secret') }
	mut value := []u8{}
	if secret[start] & 128 != 0 { value << u8(0) }
	value << secret[start..]
	mut out := []u8{}
	put_string(mut out, value)
	return out
}

fn payload_from_plain(plain []u8, block int) ![]u8 {
	if block !in [8, 16] || plain.len < 8 || plain.len % block != 0 {
		return error('packet alignment')
	}
	mut r := Reader{ data: plain }
	n := r.uint()!
	padding := int(r.byte()!)
	if n < 6 || n > max_packet || int(n) != plain.len - 4 || padding < 4 || padding >= int(n) - 1 {
		return error('invalid packet padding/length')
	}
	return plain[5..plain.len - padding].clone()
}
