// SPDX-License-Identifier: GPL-2.0-or-later
// Diagnostic callback for the existing literal-ISO controller. Does not claim
// combined acceptance: deliberately leaves acceptance.receipt absent.
module main

import os
import time
import crypto.sha256

fn step(dir string, name string, args []string, bound int) !string {
	start := time.sys_mono_now()
	mut p := os.new_process('/bin/sh')
	p.set_args(['-c', ['timeout', '-k', '3', bound.str(), ...args].map(os.quoted_path(it)).join(' ')
		+ ' </dev/null >' + os.quoted_path(dir + '/scp-' + name + '.stdout')
		+ ' 2>' + os.quoted_path(dir + '/scp-' + name + '.stderr')])
	p.run()
	for p.is_alive() {
		os.write_file(dir + '/acceptance-progress', '${time.sys_mono_now()} diagnostic-scp-${name}\n')!
		time.sleep(100 * time.millisecond)
	}
	p.wait()
	code := p.code
	p.close()
	ns := time.sys_mono_now() - start
	line := 'SCP-GUEST ${name} exit=${code} elapsed_ms=${ns / 1000000}'
	println(line)
	os.write_file(dir + '/scp-' + name + '.receipt', line + '\n')!
	if name.contains('upload') || name.contains('download') {
		println('SCP-GUEST-RATE ${name} bytes=52428800 seconds=${f64(ns)/1e9:.3f} MiB_s=${50.0e9/f64(ns):.3f}')
	}
	if code != 0 { return error('failed ' + name) }
	return os.read_file(dir + '/scp-' + name + '.stdout')!
}

fn run() ! {
	dir := os.getenv('M17C_RUN')
	key := os.getenv('M17C_KEY')
	if !os.is_abs_path(dir) || !os.is_file(key) { return error('controller environment required') }
	keys := step(dir, 'keyscan', ['ssh-keyscan', '-T', '5', '-p', '22291', '-t', 'ed25519', '127.0.0.1'], 10)!
	lines := keys.split_into_lines().filter(it.starts_with('[127.0.0.1]:22291 ssh-ed25519 '))
	if lines.len != 1 { return error('ambiguous guest host key') }
	os.write_file(dir + '/scp-known_hosts', lines[0] + '\n')!
	options := ['-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
		'-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + dir + '/scp-known_hosts', '-i', key]
	ssh := ['ssh', ...options, '-p', '22291', 'm17c@127.0.0.1']
	scp := ['scp', '-O', ...options, '-P', '22291']
	mut file := os.create(dir + '/scp-source.bin')!
	mut block := []u8{len: 65536}
	for i in 0 .. block.len { block[i] = u8((i * 13 + 7) & 255) }
	mut hash := sha256.new()
	for _ in 0 .. 800 {
		if file.write(block)! != block.len { return error('short fixture write') }
		hash.write(block)!
	}
	file.close()
	expected := hash.sum([]u8{}).hex()
	if sha256.sum(os.read_bytes(dir + '/scp-source.bin')!).hex() != expected { return error('source digest mismatch') }
	step(dir, 'before', [...ssh, 'cat /proc/meminfo; cat /root/.vinix-service-logs/ssh-server.log'], 30)!
	// An identical transfer to tmpfs separates SSH/pipe cost from encrypted HOME.
	for pair in [['tmp', '/tmp/m17c-scp.bin'], ['home', '/root/home/m17c/upload.bin']] {
		name, target := pair[0], pair[1]
		step(dir, name + '-upload', [...scp, dir + '/scp-source.bin', 'm17c@127.0.0.1:' + target], 900)!
		// A separate diagnostic bound measures the unchanged harness's 30s failure.
		// It neither changes nor substitutes for that acceptance assertion.
		remote := step(dir, name + '-digest', [...ssh, 'sha256sum ' + target], 900)!
		if remote.fields()[0] != expected { return error('guest digest mismatch') }
		step(dir, name + '-download', [...scp, 'm17c@127.0.0.1:' + target, dir + '/scp-' + name + '-returned.bin'], 900)!
		if sha256.sum(os.read_bytes(dir + '/scp-' + name + '-returned.bin')!).hex() != expected { return error('download digest mismatch') }
		println('SCP-GUEST-SHA256 ' + name + ' source=guest=download ' + expected)
		step(dir, name + '-after', [...ssh, 'cat /proc/meminfo; cat /root/.vinix-service-logs/ssh-server.log'], 30)!
	}
	os.write_file(dir + '/scp-proof.receipt', 'PASS 50MiB tmpfs and encrypted HOME upload/download with host-computed SHA256=' + expected + '\n')!
	println('SCP-GUEST PROOF PASS; combined acceptance intentionally not claimed')
}

// Optional observer around the ORIGINAL acceptance binary. It forwards its
// exact exit code, never supplies a receipt, and changes none of its bounds.
// Read its progress file to retain timing observations before they disappear.
fn observe(original string) !int {
	if !os.is_abs_path(original) || !os.is_file(original) || os.real_path(original) == os.executable() {
		return error('original acceptance binary required')
	}
	dir := os.getenv('M17C_RUN')
	mut p := os.new_process(original)
	p.set_args(['--run'])
	p.run()
	mut previous := ''
	mut observed := []string{}
	for p.is_alive() {
		line := os.read_file(dir + '/acceptance-progress') or { '' }
		if line.contains('command=') {
			id := line.all_after('command=').all_before(' ')
			if previous != '' && id != previous.all_after('command=').all_before(' ') { observed << previous.trim_space() }
			previous = line
		}
		time.sleep(25 * time.millisecond)
	}
	p.wait()
	code := p.code
	p.close()
	if previous != '' { observed << previous.trim_space() }
	os.write_file(dir + '/scp-observed-command-timings.txt', observed.join('\n') + '\n')!
	os.write_file(dir + '/scp-original-acceptance.exit', '${code}\n')!
	// Collect AFTER the original worker exits so this connection cannot delay
	// its serialized SSH sessions. Contents are fixed diagnostic metadata.
	options := ['-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
		'-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + dir + '/known_hosts', '-o', 'ConnectTimeout=5',
		'-i', os.getenv('M17C_KEY'), '-p', '22291', 'm17c@127.0.0.1']
	step(dir, 'final-diagnostics', ['ssh', ...options, 'cat /root/.vinix-service-logs/ssh-server.log; cat /proc/meminfo'], 30) or {
		eprintln('SCP-GUEST post-worker diagnostic collection failed')
	}
	return code
}

fn main() {
	original := os.getenv('M17C_ORIGINAL_ACCEPTANCE')
	if original != '' {
		code := observe(original) or { eprintln('SCP-GUEST observer FAIL ' + err.msg()); exit(1) }
		exit(code)
	}
	run() or { eprintln('SCP-GUEST FAIL ' + err.msg()); exit(1) }
}
