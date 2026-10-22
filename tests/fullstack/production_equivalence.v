// Source-level boundary check for the frozen Mission 15 production artifact.
module main

import os

fn functions(path string) !map[string]string {
	mut result := map[string]string{}
	mut name := ''
	mut body := ''
	for line in os.read_lines(path)! {
		if name == '' && !line.starts_with('	') && line.contains(' volumecli__') && line.contains('(') && line.ends_with(' {') {
			name = line.all_after(' volumecli__').all_before('(')
			body = line + '\n'
		} else if name != '' {
			body += line + '\n'
			if line == '}' { result[name] = body; name = ''; body = '' }
		}
	}
	if name != '' || result.len < 20 { return error('generated function parsing incomplete') }
	return result
}

fn run() ! {
	if os.args.len != 3 { return error('usage: production_equivalence PRODUCTION_C DIAGNOSTIC_C') }
	a := functions(os.args[1])!
	b := functions(os.args[2])!
	allowed := ['home_activation_failed', 'home_session_note', 'home_test_event', 'home_run', 'home_ui']
	mut equal := 0
	for name, body in a {
		if name !in b { return error('production function absent from diagnostic: ' + name) }
		if body == b[name] { println('IDENTICAL volumecli__' + name); equal++ }
		else {
			println('DIFF volumecli__' + name)
			if name !in allowed { return error('unexplained function difference: ' + name) }
		}
	}
	for name, _ in b {
		if name !in a {
			println('DIAGNOSTIC_ONLY volumecli__' + name)
			if name !in ['home_probe', 'home_probe_round', 'home_probe_client'] { return error('unexplained diagnostic function: ' + name) }
		}
	}
	for name in ['home_prepare', 'home_enroll', 'home_unlock', 'home_wrap', 'home_unwrap', 'home_header_valid', 'home_normalize', 'home_phrase', 'home_entropy', 'home_serve', 'home_activate', 'home_publish', 'home_blank', 'home_boot', 'home_spawn_ui', 'home_session', 'home_private_scratch', 'home_transfer', 'home_send', 'home_receive', 'sealed_derive', 'encode_volume_seal', 'decode_volume_seal', 'key_random_bytes'] {
		if name !in a || a[name] != b[name] { return error('security path not identical: ' + name) }
		println('SECURITY_PATH_IDENTICAL volumecli__' + name)
	}
	println('PASS generated source security/storage functions identical; enumerated differences require human review')
	println('IDENTICAL_FUNCTIONS:' + equal.str())
}

fn main() { run() or { eprintln('FAIL ' + err.msg()); exit(1) } }
