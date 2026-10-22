// SPDX-License-Identifier: GPL-2.0-or-later
module main

import encoding.hex
import crypto.sha256
import crypto.hmac
import tools.packages.signing

fn unhex(s string) []u8 { return hex.decode(s) or { panic(err) } }

fn hmac_vector_result() []u8 {
	return hmac.new([]u8{len: 20, init: 0x0b}, 'Hi There'.bytes(), sha256.sum, 64)
}

fn self_test() ! {
	// RFC 7748 section 6.1 Alice/Bob shared secret.
	mut alice := unhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
	bob := unhex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')
	assert x_public(mut alice)!.hex() == '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'
	assert x_shared(mut alice, bob)!.hex() == '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'
	// RFC 8032 section 7.1 test 1.
	key := signing.new_key_from_seed(unhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'))
	assert key.public_key().hex() == 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
	sig := signing.sign(key, [])!
	assert sig.hex() == 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'
	assert signing.verify(key.public_key(), [], sig)!
	assert !signing.verify(key.public_key(), [u8(1)], sig)!
	assert sha256.sum('abc'.bytes()).hex() == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
	// NIST SP800-38A F.5.1 AES128-CTR first block.
	mut stream := ctr(unhex('2b7e151628aed2a6abf7158809cf4f3c'), unhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'))!
	source := unhex('6bc1bee22e409f96e93d7e117393172a')
	mut encrypted := []u8{len: 16}
	stream.xor_key_stream(mut encrypted, source)
	assert encrypted.hex() == '874d6191b620e3261bef6864990db6ce'
	// RFC 4231 test 1 HMAC-SHA256 (without SSH sequence prefix).
	assert hmac_vector_result().hex() == 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'
	for sample in [[]u8{}, [u8(255), 255, 255, 255], [u8(0), 0, 0, 5, 1]] {
		mut r := Reader{ data: sample }
		if _ := r.string_bytes(64) { return error('malformed string accepted') }
	}
	if _ := secret_mpint([]u8{len: 32}) { return error('zero secret accepted') }
	for name in ['..', '/absolute', 'a/b', 'a\\b', 'a\n'] {
		assert !safe_name(name)
	}
	if _ := scp_record('C0600 4294967295 file') { return error('oversized file accepted') }
	if _ := parse_authorized('restrict ssh-ed25519 AAAA') { return error('options accepted') }
}
