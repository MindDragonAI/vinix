// SPDX-License-Identifier: GPL-2.0-or-later
// Disposable fecv3 callback for the encrypted-HOME SSH controller.
module main

import os
import time
import crypto.sha256

fn step(dir string, name string, args []string, expected int, input string) !string {
	start := time.sys_mono_now()
	mut p := os.new_process('/usr/bin/timeout')
	defer { p.close() }
	p.set_args(['-k', '3', '180', 'setsid', ...args])
	p.set_redirect_stdio()
	p.set_stdin_path(if input == '' { '/dev/null' } else { input })
	p.run()
	p.wait()
	text := p.stdout_slurp() + p.stderr_slurp()
	os.write_file(dir + '/' + name + '.log', text)!
	os.write_file(dir + '/' + name + '.exit', p.code.str() + '\n')!
	println('M16B-GUEST ${name} exit=${p.code} expected=${expected} elapsed_ms=${(time.sys_mono_now()-start)/1000000}')
	if p.code != expected { return error('${name} failed') }
	return text
}

fn main() { qualify() or { eprintln('M16B-GUEST FAIL: ${err}'); exit(1) } }

fn hash_file(path string) !string {
	mut file := os.open(path)!
	defer { file.close() }
	mut digest := sha256.new()
	mut buffer := []u8{len: 1024 * 1024}
	for {
		n := file.read(mut buffer) or { break }
		if n == 0 { break }
		digest.write(buffer[..n])!
	}
	return digest.sum([]u8{}).hex()
}

fn qualify() ! {
	root := os.getenv('SSH_RUN_DIR')
	if root == '' || !os.is_dir(root) { return error('controller run directory required') }
	dir := root + '/acceptance'
	if os.exists(dir) { return error('receipts already exist; do not repeat') }
	os.mkdir(dir)!
	port := os.getenv('SSH_PORT')
	key := os.getenv('SSH_KEY')
	if port != '22289' || key == '' { return error('unexpected endpoint') }
	known := step(dir, 'host-key-scan', ['ssh-keyscan', '-T', '5', '-p', port, '-t', 'ed25519', '127.0.0.1'], 0, '')!
	lines := known.split_into_lines().filter(it.starts_with('[127.0.0.1]:22289 ssh-ed25519 '))
	if lines.len != 1 { return error('host key scan ambiguous') }
	os.write_file(dir + '/known_hosts', lines[0] + '\n')!
	options := ['-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
		'-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + dir + '/known_hosts']
	ssh := ['ssh', ...options, '-p', port, '-i', key]
	target := 'm16b@127.0.0.1'
	text := step(dir, 'exec', [...ssh, target, 'echo OK'], 0, '')!
	if !text.split_into_lines().any(it.trim_space() == 'OK') { return error('exec marker absent') }
	_ := step(dir, 'exec-status', [...ssh, target, 'echo EXEC_STDERR >&2; exit 7'], 7, '')!
	mounts := step(dir, 'post-unlock-mount-and-broker', [...ssh, target,
		'cat /proc/self/mounts; cat /root/.vinix-service-logs/ssh-server.log; echo M16B-SSH-EXEC-OK > /dev/com1'], 0, '')!
	if !mounts.contains('/dev/mapper/vinix63 /root ext2') || !mounts.contains('vinix-sshd: listening') {
		return error('encrypted mount or broker start receipt absent')
	}
	os.write_file(dir + '/shell-input', 'tty\necho M16B_SHELL_OK\nexit\n')!
	os.setenv('TERM', 'xterm', true)
	shell := step(dir, 'shell-pty', [...ssh, '-tt', target], 0, dir + '/shell-input')!
	if !shell.contains('M16B_SHELL_OK') || !shell.contains('/dev/pts/') { return error('real PTY shell not proven') }
	for i in 0 .. 20 {
		result := step(dir, 'sequential-${i}', [...ssh, target, 'echo SESSION-${i}'], 0, '')!
		if !result.contains('SESSION-${i}') { return error('sequential output absent') }
	}
	_ := step(dir, 'wrong-keygen', ['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', dir + '/wrong'], 0, '')!
	wrong := step(dir, 'wrong-key', ['ssh', ...options, '-p', port, '-i', dir + '/wrong', target, 'true'], 255, '')!
	if !wrong.contains('Permission denied (publickey)') { return error('wrong key not cleanly rejected') }
	no_key_reply := step(dir, 'no-key', ['ssh', ...options, '-p', port, '-o', 'PubkeyAuthentication=no', target, 'true'], 255, '')!
	if !no_key_reply.contains('Permission denied (publickey)') { return error('no key not cleanly rejected') }
	scp := ['scp', '-O', ...options, '-P', port, '-i', key]
	source := '/home/agent/build/m16b-receipts/host-interop-r1/large'
	if os.file_size(source) != 50 * 1024 * 1024 { return error('50 MiB source checkpoint missing') }
	_ := step(dir, 'scp-upload-50m', [...scp, source, target + ':/root/home/m16b/large-copy'], 0, '')!
	remote := step(dir, 'remote-sha256', [...ssh, target, 'sha256sum /root/home/m16b/large-copy'], 0, '')!
	_ := step(dir, 'scp-download-50m', [...scp, target + ':/root/home/m16b/large-copy', dir + '/roundtrip'], 0, '')!
	a := hash_file(source)!
	b := hash_file(dir + '/roundtrip')!
	os.write_file(dir + '/large-sha256.txt', 'source ${a}\nroundtrip ${b}\nremote ' + remote)!
	if a != b || !remote.starts_with(a + ' ') { return error('large SCP checksum mismatch') }
	os.mkdir_all(dir + '/tree/nested')!
	os.write_file(dir + '/tree/nested/marker', 'M16B recursive SCP\n')!
	_ := step(dir, 'scp-recursive-upload', [...scp, '-r', dir + '/tree', target + ':/root/home/m16b/tree'], 0, '')!
	_ := step(dir, 'scp-recursive-download', [...scp, '-r', target + ':/root/home/m16b/tree', dir + '/returned'], 0, '')!
	if os.read_file(dir + '/returned/nested/marker')! != 'M16B recursive SCP\n' { return error('recursive readback differs') }
	_ := step(dir, 'post-transfer-exec', [...ssh, target, 'echo AFTER_SCP_OK'], 0, '')!
	os.write_file(dir + '/PASS', 'M16B_GUEST_ACCEPTANCE_PASS\n')!
	println('M16B_GUEST_ACCEPTANCE_PASS')
}
