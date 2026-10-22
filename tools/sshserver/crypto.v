// SPDX-License-Identifier: GPL-2.0-or-later
module main

import crypto.aes
import crypto.cipher
import crypto.hmac
import crypto.sha256
import x.crypto.curve25519

// Entropy comes from a fully-read OS device, including on targets whose
// crypto.rand backend deliberately returns "not implemented".
fn entropy(n int) ![]u8 {
	if n < 1 || n > max_packet { return error('entropy size') }
	fd := C.open(c'/dev/urandom', C.O_RDONLY | C.O_CLOEXEC | C.O_NOFOLLOW)
	if fd < 0 { return error('OS entropy unavailable') }
	defer { C.close(fd) }
	return read_exact_fd(fd, n)!
}

fn x_public(mut scalar []u8) ![]u8 {
	mut point := []u8{len: 32}
	point[0] = 9
	return curve25519.x25519(mut scalar, point)!
}

fn x_shared(mut scalar []u8, point []u8) ![]u8 {
	if scalar.len != 32 || point.len != 32 { return error('invalid X25519 size') }
	shared := curve25519.x25519(mut scalar, point)!
	_ := secret_mpint(shared)!
	return shared
}

fn kdf(k []u8, h []u8, letter u8, session []u8, count int) []u8 {
	mut input := k.clone()
	input << h
	input << letter
	input << session
	return sha256.sum(input)[..count].clone()
}

fn mac(key []u8, seq u32, plain []u8) []u8 {
	mut input := []u8{cap: plain.len + 4}
	put_u32(mut input, seq)
	input << plain
	return hmac.new(key, input, sha256.sum, 64)
}

// Keep the stream behind its public interface; no local AES implementation.
fn ctr(key []u8, iv []u8) !cipher.Stream {
	if key.len != 16 || iv.len != 16 { return error('invalid AES key/IV size') }
	return cipher.new_ctr(aes.new_cipher(key)!, iv)
}
