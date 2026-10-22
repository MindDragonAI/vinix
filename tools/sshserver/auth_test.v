module main

import encoding.base64
import tools.packages.signing

fn signed_auth(key signing.PrivateKey, session []u8, user string) []u8 {
	mut request := text_packet(50, user)
	put_string(mut request, 'ssh-connection'.bytes())
	put_string(mut request, 'publickey'.bytes())
	request << u8(1)
	put_string(mut request, 'ssh-ed25519'.bytes())
	put_string(mut request, public_blob(key.public_key()))
	mut message := []u8{}
	put_string(mut message, session)
	message << request
	mut signature := []u8{}
	put_string(mut signature, 'ssh-ed25519'.bytes())
	put_string(mut signature, signing.sign(key, message) or { panic(err) })
	put_string(mut request, signature)
	return request
}

fn test_auth_session_username_and_key_binding() {
	key := signing.new_key_from_seed([]u8{len: 32, init: 7})
	other := signing.new_key_from_seed([]u8{len: 32, init: 8})
	session := []u8{len: 32, init: 1}
	keys := [public_blob(key.public_key())]
	request := signed_auth(key, session, 'tester')
	ok, query, _ := verify_auth(session, request, 'tester', keys) or { panic(err) }
	assert ok && !query
	for which in 0 .. 3 {
		got, _, _ := verify_auth(if which == 0 { []u8{len: 32, init: 2} } else { session }, request,
			if which == 1 { 'wrong' } else { 'tester' }, if which == 2 {
				[public_blob(other.public_key())]
			} else {
				keys
			}) or { panic(err) }
		assert !got
	}
	for n in 0 .. request.len {
		if result, _, _ := verify_auth(session, request[..n], 'tester', keys) {
			assert !result
		}
	}
	line := 'ssh-ed25519 ' + base64.encode(keys[0]) + ' test'
	assert (parse_authorized(line) or { panic(err) }).len == 1
	for prefix in ['restrict ', 'command="true" ', 'no-pty ', 'from="127.0.0.1" '] {
		if _ := parse_authorized(prefix + line) {
			assert false
		}
	}
	mut query_request := text_packet(50, 'tester')
	put_string(mut query_request, 'ssh-connection'.bytes())
	put_string(mut query_request, 'publickey'.bytes())
	query_request << u8(0)
	put_string(mut query_request, 'ssh-ed25519'.bytes())
	put_string(mut query_request, keys[0])
	success, pk_ok, _ := verify_auth(session, query_request, 'tester', keys) or { panic(err) }
	assert !success && pk_ok
}

fn test_none_auth_discovery_is_bounded_and_user_bound() {
	mut request := text_packet(50, 'tester')
	put_string(mut request, 'ssh-connection'.bytes())
	put_string(mut request, 'none'.bytes())
	assert auth_discovery(request, 'tester') or { panic(err) }
	assert !(auth_discovery(request, 'other') or { panic(err) })
	request << u8(0)
	if _ := auth_discovery(request, 'tester') {
		assert false
	}
}
