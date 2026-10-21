// SPDX-License-Identifier: GPL-2.0-or-later
// Run with V run tests/encrypted-home/run.v /absolute/path/to/v
module main

import os

fn run(command string, args []string) ! {
	mut child := os.new_process(command)
	child.set_args(args)
	child.run(); child.wait()
	status := child.code
	child.close()
	if status != 0 { return error('command failed: ' + command + ' status ' + status.str()) }
}

fn function(source string, name string) !string {
	start := source.index('fn ' + name + '(') or { return error('production function missing') }
	brace := start + (source[start..].index('{') or { return error('function body missing') })
	mut end := brace + 1; mut depth := 1
	for end < source.len && depth > 0 {
		if source[end] == `{` { depth++ } else if source[end] == `}` { depth-- }
		end++
	}
	if depth != 0 { return error('unterminated function') }
	return source[start..end] + '\n'
}

fn main() {
	if os.args.len != 2 { eprintln('usage: V run tests/encrypted-home/run.v /absolute/path/to/v'); exit(2) }
	v := os.real_path(os.args[1])
	root := os.dir(os.dir(os.dir(@FILE)))
	work := os.join_path(os.temp_dir(), 'vinix-home-tests-' + os.getpid().str())
	os.mkdir(work) or { panic(err) }
	defer { os.rmdir_all(work) or {} }
	source := root + '/tools/volumes/volumecli'
	run(v, ['-nocache', '-enable-globals', '-cc', 'clang', '-cflags', '-O2 -I' + source,
		'-d', 'volume_library', '-o', work + '/home-test', source + '/home_test.v']) or { eprintln(err); exit(1) }
	run(work + '/home-test', []) or { eprintln(err); exit(1) }
	run(v, ['-nocache', '-enable-globals', '-cc', 'clang', '-cflags', '-O2 -I' + source,
		'-d', 'volume_library', '-d', 'home_entropy_failure', '-o', work + '/entropy-test', source + '/home_test.v']) or { eprintln(err); exit(1) }
	run(work + '/entropy-test', []) or { eprintln(err); exit(1) }
	seed := work + '/seed'
	os.mkdir(seed) or { panic(err) }
	actual := os.read_file(root + '/kernel/krandom/random_amd64.v') or { panic(err) }
	body := function(actual, 'architecture_seed') or { panic(err) }
	os.write_file(seed + '/core.v', 'module krandom\n' + body) or { panic(err) }
	os.cp(root + '/kernel/krandom/erase.v', seed + '/erase.v') or { panic(err) }
	os.cp(root + '/tests/encrypted-home/seed_test.v', seed + '/seed_test.v') or { panic(err) }
	run(v, ['-nocache', '-enable-globals', '-cc', 'clang', '-o', work + '/seed-test', seed + '/seed_test.v']) or { eprintln(err); exit(1) }
	run(work + '/seed-test', []) or { eprintln(err); exit(1) }
	// Test the real mapper/formatter with the repository's existing host
	// fixtures, independently of its unrelated library-AES oracle API.
	kernel := work + '/kernel'
	os.cp_all(root + '/tests/storage-volumes/hostfixtures', kernel, false) or { panic(err) }
	for path in ['fs/storage_control.v', 'fs/storage_health.v', 'fs/storage_crypt.v', 'fs/storage_format.v',
		'aesxts/core.v', 'resource/block_health.v', 'resource/block_health_arm64.v',
		'resource/block_health_amd64.v', 'resource/block_status.v', 'resource/block_discard.v',
		'resource/block_identity.v', 'security/device_policy.v'] {
		os.mkdir_all(os.dir(kernel + '/' + path)) or { panic(err) }
		os.cp(root + '/kernel/' + path, kernel + '/' + path) or { panic(err) }
	}
	os.write_file(kernel + '/v.mod', "Module { name: 'home_kernel_host' }\n") or { panic(err) }
	os.cp(root + '/tests/storage-volumes/volume_test.v', kernel + '/fs/volume_test.v') or { panic(err) }
	run(v, ['-nocache', '-enable-globals', '-cc', 'clang', '-o', work + '/mapper-test', kernel + '/fs/volume_test.v']) or { eprintln(err); exit(1) }
	run(work + '/mapper-test', []) or { eprintln(err); exit(1) }
	println('HOME-HOST: production phrase, envelopes, entropy denial, rate budget, header and state tests PASS')
}
