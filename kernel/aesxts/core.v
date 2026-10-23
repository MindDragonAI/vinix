// SPDX-License-Identifier: GPL-2.0-or-later
module aesxts

fn C.__builtin_alloca(usize) voidptr

// AES-256-XTS with full 512/4096-byte storage data units. State and all
// workspaces are caller-owned. No secret-indexed tables or secret branches.
pub struct Cipher {
mut:
	data [240]u8
	tweak [240]u8
	ready bool
}

struct SecretByte {
mut:
	volatile value u8
}

struct SecretWord {
mut:
	volatile value u64
}

struct Workspace {
mut:
	states [4][16]u8
	tweaks [4][16]u8
}

// Volatile byte stores survive dead-store elimination, including on failure.
pub fn erase(buffer voidptr, bytes usize) {
	for i := usize(0); i < bytes; i++ { unsafe { (&SecretByte(usize(buffer) + i)).value = 0 } }
}

// Internal planes are aligned u64 arrays. Preserve volatile erasure while
// clearing a whole native word per store, rather than eight byte stores.
fn erase_lanes(buffer &u64, count usize) {
	for i := usize(0); i < count; i++ { unsafe { (&SecretWord(usize(buffer) + i * sizeof(u64))).value = 0 } }
}

pub fn clear(mut cipher Cipher) { erase(unsafe { &cipher }, sizeof(Cipher)) }

@[inline]
fn xtime(value u8) u8 { return (value << 1) ^ (u8(0x1b) & (u8(0) - (value >> 7))) }

@[inline]
fn multiply(a u8, b u8) u8 {
	mut x := a; mut y := b; mut result := u8(0)
	for _ in 0 .. 8 { result ^= x & (u8(0) - (y & 1)); x = xtime(x); y >>= 1 }
	return result
}

// Fixed addition chain for x^254 in GF(2^8); zero maps to zero too.
@[inline]
fn inverse(value u8) u8 {
	x2 := multiply(value, value); x4 := multiply(x2, x2); x8 := multiply(x4, x4)
	x16 := multiply(x8, x8); x32 := multiply(x16, x16); x64 := multiply(x32, x32); x128 := multiply(x64, x64)
	return multiply(multiply(multiply(x2, x4), multiply(x8, x16)), multiply(multiply(x32, x64), x128))
}

@[inline]
fn rotate(value u8, bits u8) u8 { return (value << bits) | (value >> (8 - bits)) }

@[inline]
fn substitute(value u8) u8 {
	x := inverse(value)
	return x ^ rotate(x, 1) ^ rotate(x, 2) ^ rotate(x, 3) ^ rotate(x, 4) ^ 0x63
}

// Independent bit lanes share each finite-field operation. Each polynomial
// reduction follows the AES modulus x^8 + x^4 + x^3 + x + 1.
@[direct_array_access]
fn multiply_lanes(a &u64, b &u64, output &u64) {
	mut product := [15]u64{}; defer { erase_lanes(unsafe { &product[0] }, 15) }
	unsafe { for i in 0 .. 8 { for j in 0 .. 8 { product[i + j] ^= a[i] & b[j] } } }
	for i := 14; i >= 8; i-- { carry := product[i]; product[i - 8] ^= carry; product[i - 7] ^= carry; product[i - 5] ^= carry; product[i - 4] ^= carry }
	unsafe { for i in 0 .. 8 { output[i] = product[i] } }
}

// Squaring in characteristic two is linear: cross terms cancel. Reduce each
// x^(2*i) modulo x^8+x^4+x^3+x+1 once, rather than doing a general multiply.
// Inputs and output must be distinct. These are fixed XORs, with no lookup
// indexed by key or plaintext bits.
@[direct_array_access]
fn square_lanes(a &u64, output &u64) {
	unsafe {
		output[0] = a[0] ^ a[4] ^ a[6]
		output[1] = a[4] ^ a[6] ^ a[7]
		output[2] = a[1] ^ a[5]
		output[3] = a[4] ^ a[5] ^ a[6] ^ a[7]
		output[4] = a[2] ^ a[4] ^ a[7]
		output[5] = a[5] ^ a[6]
		output[6] = a[3] ^ a[5]
		output[7] = a[6] ^ a[7]
	}
}

// x^254, including 0 -> 0, using seven linear squares and four general
// multiplies. The former chain used thirteen general multiplies per S-box.
@[direct_array_access]
fn inverse_lanes(input &u64, output &u64) {
	mut x2 := [8]u64{}; mut x12 := [8]u64{}; mut a := [8]u64{}; mut b := [8]u64{}
	defer { erase_lanes(&x2[0], 8); erase_lanes(&x12[0], 8); erase_lanes(&a[0], 8); erase_lanes(&b[0], 8) }
	square_lanes(input, &x2[0])
	multiply_lanes(input, &x2[0], &a[0]) // x^3
	square_lanes(&a[0], &b[0]) // x^6
	square_lanes(&b[0], &x12[0])
	multiply_lanes(&a[0], &x12[0], output) // x^15
	square_lanes(output, &a[0]) // x^30
	square_lanes(&a[0], &b[0]) // x^60
	square_lanes(&b[0], &a[0]) // x^120
	square_lanes(&a[0], &b[0]) // x^240
	multiply_lanes(&b[0], &x12[0], output) // x^252
	multiply_lanes(output, &x2[0], output)
}

@[direct_array_access]
fn substitute_lanes(mut lanes [8]u64, decrypt bool, mask u64) {
	mut result := [8]u64{}; mut transformed := [8]u64{}
	defer { erase_lanes(unsafe { &result[0] }, 8); erase_lanes(unsafe { &transformed[0] }, 8) }
	if decrypt { for bit in 0 .. 8 { transformed[bit] = lanes[(bit + 7) & 7] ^ lanes[(bit + 5) & 7] ^ lanes[(bit + 2) & 7] ^ ((u64(0) - u64((0x05 >> bit) & 1)) & mask) }; lanes = transformed }
	inverse_lanes(&lanes[0], &result[0])
	if !decrypt { for bit in 0 .. 8 { transformed[bit] = result[bit] ^ result[(bit + 7) & 7] ^ result[(bit + 6) & 7] ^ result[(bit + 5) & 7] ^ result[(bit + 4) & 7] ^ ((u64(0) - u64((0x63 >> bit) & 1)) & mask) }; result = transformed }
	lanes = result
}

@[direct_array_access]
fn sub_bytes(mut state [16]u8, decrypt bool) {
	mut lanes := [8]u64{}; defer { erase_lanes(&lanes[0], 8) }
	for bit in 0 .. 8 { for lane in 0 .. 16 { lanes[bit] |= u64((state[lane] >> bit) & 1) << lane } }
	substitute_lanes(mut lanes, decrypt, 0xffff)
	for lane in 0 .. 16 { state[lane] = 0; for bit in 0 .. 8 { state[lane] |= u8((lanes[bit] >> lane) & 1) << bit } }
}

// Fill all 64 lanes of native integer bit planes with four independent AES
// blocks. XTS already has full sectors, so no padding or partial-block case.
@[direct_array_access]
fn sub_bytes_quad(mut states [4][16]u8, decrypt bool) {
	mut lanes := [8]u64{}; defer { erase_lanes(&lanes[0], 8) }
	for bit in 0 .. 8 { for index in 0 .. 4 { for lane in 0 .. 16 {
		lanes[bit] |= u64((states[index][lane] >> bit) & 1) << (index * 16 + lane)
	} } }
	substitute_lanes(mut lanes, decrypt, u64(-1))
	for index in 0 .. 4 { for lane in 0 .. 16 {
		states[index][lane] = 0
		for bit in 0 .. 8 { states[index][lane] |= u8((lanes[bit] >> (index * 16 + lane)) & 1) << bit }
	} }
}

@[direct_array_access]
fn expand(key &u8, schedule &u8) {
	unsafe { for i in 0 .. 32 { schedule[i] = key[i] } }
	mut rcon := u8(1); mut word := [4]u8{}; defer { erase(&word[0], sizeof(word)) }
	for at := 32; at < 240; at += 4 {
		unsafe { for i in 0 .. 4 { word[i] = schedule[at - 4 + i] } }
		if at % 32 == 0 {
			first := word[0]; word[0] = substitute(word[1]) ^ rcon; word[1] = substitute(word[2])
			word[2] = substitute(word[3]); word[3] = substitute(first); rcon = xtime(rcon)
		} else if at % 32 == 16 { for i in 0 .. 4 { word[i] = substitute(word[i]) } }
		unsafe { for i in 0 .. 4 { schedule[at + i] = schedule[at + i - 32] ^ word[i] } }
	}
}

// Both key halves must be independent AES-256 keys. Invalid initialization
// preserves the caller; callers erase rejected key material explicitly.
@[direct_array_access]
pub fn initialize(mut cipher Cipher, key &[64]u8) bool {
	mut difference := u8(0); unsafe { for i in 0 .. 32 { difference |= key[i] ^ key[i + 32] } }
	if difference == 0 { return false }
	expand(unsafe { &key[0] }, &cipher.data[0]); expand(unsafe { &key[32] }, &cipher.tweak[0]); cipher.ready = true
	return true
}

@[direct_array_access]
fn add_key(mut state [16]u8, schedule &u8, round int) {
	unsafe { for i in 0 .. 16 { state[i] ^= schedule[round * 16 + i] } }
}

@[direct_array_access]
fn shift(mut state [16]u8, decrypt bool) {
	mut previous := state; defer { erase(&previous[0], sizeof(previous)) }
	for row in 0 .. 4 { for column in 0 .. 4 {
		from := if decrypt { (column + 4 - row) & 3 } else { (column + row) & 3 }
		state[column * 4 + row] = previous[from * 4 + row]
	} }
}

@[direct_array_access]
fn mix(mut state [16]u8, decrypt bool) {
	for column in 0 .. 4 {
		at := column * 4
		if decrypt {
			u := xtime(xtime(state[at] ^ state[at + 2])); v := xtime(xtime(state[at + 1] ^ state[at + 3]))
			state[at] ^= u; state[at + 2] ^= u; state[at + 1] ^= v; state[at + 3] ^= v
		}
		a := state[at]; b := state[at + 1]; c := state[at + 2]; d := state[at + 3]; all := a ^ b ^ c ^ d
		state[at] = a ^ all ^ xtime(a ^ b); state[at + 1] = b ^ all ^ xtime(b ^ c)
		state[at + 2] = c ^ all ^ xtime(c ^ d); state[at + 3] = d ^ all ^ xtime(d ^ a)
	}
}

@[direct_array_access]
fn block(schedule &u8, mut state [16]u8, decrypt bool) {
	add_key(mut state, schedule, if decrypt { 14 } else { 0 })
	for step in 1 .. 15 {
		if decrypt {
			shift(mut state, true); sub_bytes(mut state, true)
			add_key(mut state, schedule, 14 - step); if step != 14 { mix(mut state, true) }
		} else {
			sub_bytes(mut state, false); shift(mut state, false)
			if step != 14 { mix(mut state, false) }; add_key(mut state, schedule, step)
		}
	}
}

@[direct_array_access]
fn block_quad(schedule &u8, mut states [4][16]u8, decrypt bool) {
	for index in 0 .. 4 { add_key(mut states[index], schedule, if decrypt { 14 } else { 0 }) }
	for step in 1 .. 15 {
		if decrypt {
			for index in 0 .. 4 { shift(mut states[index], true) }
			sub_bytes_quad(mut states, true)
			for index in 0 .. 4 {
				add_key(mut states[index], schedule, 14 - step)
				if step != 14 { mix(mut states[index], true) }
			}
		} else {
			sub_bytes_quad(mut states, false)
			for index in 0 .. 4 {
				shift(mut states[index], false)
				if step != 14 { mix(mut states[index], false) }
				add_key(mut states[index], schedule, step)
			}
		}
	}
}

@[direct_array_access]
fn advance(mut tweak [16]u8) {
	mut carry := u8(0)
	for i in 0 .. 16 { next := tweak[i] >> 7; tweak[i] = (tweak[i] << 1) | carry; carry = next }
	tweak[0] ^= u8(0x87) & (u8(0) - carry)
}

// In-place, complete native-sector units, with little-endian 64-bit unit
// numbers in a zero-extended 128-bit tweak. Bounds reject before mutation.
@[direct_array_access]
pub fn crypt(cipher &Cipher, data &u8, bytes u64, sector u64, first u64, decrypt bool) bool {
	if !cipher.ready || (sector != 512 && sector != 4096) || bytes % sector != 0
		|| bytes > 65536 || (bytes != 0 && data == unsafe { nil })
		|| (bytes != 0 && bytes / sector - 1 > u64(-1) - first) { return false }
	mut workspace := unsafe { &Workspace(C.__builtin_alloca(sizeof(Workspace))) }; unsafe { *workspace = Workspace{} }
	defer { erase(workspace, sizeof(Workspace)) }
	for at := u64(0); at < bytes; at += sector {
		unit := first + at / sector; workspace.tweaks[0] = [16]u8{}
		for i in 0 .. 8 { workspace.tweaks[0][i] = u8(unit >> (i * 8)) }; block(unsafe { &cipher.tweak[0] }, mut workspace.tweaks[0], false)
		for offset := u64(0); offset < sector; offset += 64 {
			for index in 0 .. 4 {
				if index > 0 { workspace.tweaks[index] = workspace.tweaks[index - 1]; advance(mut workspace.tweaks[index]) }
				unsafe { for i in 0 .. 16 { workspace.states[index][i] = data[at + offset + u64(index * 16 + i)] ^ workspace.tweaks[index][i] } }
			}
			block_quad(unsafe { &cipher.data[0] }, mut workspace.states, decrypt)
			unsafe { for index in 0 .. 4 { for i in 0 .. 16 { data[at + offset + u64(index * 16 + i)] = workspace.states[index][i] ^ workspace.tweaks[index][i] } } }
			advance(mut workspace.tweaks[3]); workspace.tweaks[0] = workspace.tweaks[3]
		}
	}
	return true
}
