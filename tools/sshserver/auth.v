// SPDX-License-Identifier: GPL-2.0-or-later
module main

import tools.packages.signing
import crypto.hmac
import time

struct FailureBudget {
mut:
	failures int
	epoch    i64
}

fn (mut b FailureBudget) available() bool {
	now := time.now().unix()
	if now - b.epoch >= 60 {
		b.epoch = now
		b.failures = 0
	}
	return b.failures < 12
}

fn verify_auth(session []u8, request []u8, username string, keys [][]u8) !(bool, bool, []u8) {
	mut r := Reader{ data: request }
	if r.byte()! != 50 { return error('expected auth request') }
	user := r.string_bytes(128)!.bytestr()
	service := r.string_bytes(64)!.bytestr()
	method := r.string_bytes(64)!.bytestr()
	if method != 'publickey' { return false, false, []u8{} }
	signed := r.byte()!
	if signed > 1 { return error('invalid auth boolean') }
	algorithm := r.string_bytes(64)!.bytestr()
	blob := r.string_bytes(256)!
	key := parse_public(blob)!
	prefix_len := r.pos
	mut signature := []u8{}
	if signed == 1 {
		wrapper := r.string_bytes(256)!
		mut sr := Reader{ data: wrapper }
		if sr.string_bytes(64)!.bytestr() != 'ssh-ed25519' {
			return error('invalid signature algorithm')
		}
		signature = sr.string_bytes(64)!
		sr.end()!
		if signature.len != 64 { return error('invalid signature size') }
	}
	r.end()!
	mut matched := false
	for allowed in keys { if hmac.equal(blob, allowed) { matched = true } }
	if user != username || service != 'ssh-connection' || algorithm != 'ssh-ed25519' || !matched {
		return false, false, blob
	}
	if signed == 0 { return false, true, blob }
	mut message := []u8{}
	put_string(mut message, session)
	message << request[..prefix_len]
	return signing.verify(signing.PublicKey(key), message, signature)!, false, blob
}

fn (mut t Transport) authenticate(user string, keys [][]u8, mut budget FailureBudget) ! {
	service := t.next()!
	mut r := Reader{ data: service }
	if r.byte()! != 5 || r.string_bytes(64)!.bytestr() != 'ssh-userauth' {
		return error('expected userauth service')
	}
	r.end()!
	t.send(text_packet(6, 'ssh-userauth'))!
	for _ in 0 .. 16 {
		if !budget.available() { return error('global authentication budget exceeded') }
		request := t.next()!
		// OpenSSH normally discovers available methods with "none" before offering
		// a key. This is bounded by the per-connection request cap, not a failed key.
		discovery := auth_discovery(request, user) or { false }
		if discovery {
			mut response := text_packet(51, 'publickey')
			response << u8(0)
			t.send(response)!
			continue
		}
		ok, query, blob := verify_auth(t.session, request, user, keys) or {
			budget.failures++
			return err
		}
		if ok {
			t.send([u8(52)])!
			return
		}
		if query {
			mut response := text_packet(60, 'ssh-ed25519')
			put_string(mut response, blob)
			t.send(response)!
		} else {
			budget.failures++
			mut response := text_packet(51, 'publickey')
			response << u8(0)
			t.send(response)!
		}
	}
	return error('authentication request limit')
}

fn auth_discovery(request []u8, username string) !bool {
	mut r := Reader{ data: request }
	if r.byte()! != 50 { return false }
	user := r.string_bytes(128)!.bytestr()
	service := r.string_bytes(64)!.bytestr()
	method := r.string_bytes(64)!.bytestr()
	if method != 'none' { return false }
	r.end()!
	return user == username && service == 'ssh-connection'
}
