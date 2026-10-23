// SPDX-License-Identifier: GPL-2.0-or-later
// Real OpenSSH legacy-SCP interop; every command has a finite deadline.
module main

import os
import time
import crypto.rand
import crypto.sha256

fn step(dir string, name string, args []string, expected int, bound int) !string {
	start := time.sys_mono_now()
	mut process := os.new_process('/bin/sh')
	process.set_args(['-c', ['timeout', '-k', '3', bound.str(), ...args].map(os.quoted_path(it)).join(' ')
		+ ' </dev/null >' + os.quoted_path(dir + '/' + name + '.stdout')
		+ ' 2>' + os.quoted_path(dir + '/' + name + '.stderr')])
	process.run()
	process.wait()
	code := process.code
	process.close()
	ns := time.sys_mono_now() - start
	line := 'SCP-TRANSFER ${name} exit=${code} expected=${expected} elapsed_ms=${ns / 1000000}'
	println(line)
	os.write_file(dir + '/' + name + '.receipt', line + '\n')!
	if name in ['upload', 'download'] {
		println('SCP-RATE ${name} bytes=52428800 seconds=${f64(ns)/1e9:.3f} MiB_s=${50.0e9/f64(ns):.3f}')
	}
	if code != expected { return error('failed ' + name) }
	return os.read_file(dir + '/' + name + '.stdout')!
}

fn main() {
	run() or { eprintln('SCP-TRANSFER FAIL ' + err.msg()); exit(1) }
}

fn run() ! {
	if os.args.len != 3 { return error('usage: transfer SERVER FRESH-DIR') }
	server := os.real_path(os.args[1])
	dir := os.args[2]
	if os.exists(dir) { return error('fresh directory required') }
	os.mkdir_all(dir + '/home/.ssh')!
	for path in [dir, dir + '/home', dir + '/home/.ssh'] { os.chmod(path, 0o700)! }
	step(dir, 'keygen', ['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', dir + '/key'], 0, 10)!
	os.cp(dir + '/key.pub', dir + '/home/.ssh/authorized_keys')!
	os.chmod(dir + '/home/.ssh/authorized_keys', 0o600)!
	mut seed := 'Vinix SSH Ed25519 seed v1\n'.bytes()
	seed << rand.bytes(32)!
	os.write_file_array(dir + '/seed', seed)!
	os.chmod(dir + '/seed', 0o600)!
	public := step(dir, 'public', [server, '--host-key', dir + '/seed', '--public-key'], 0, 10)!
	os.write_file(dir + '/known_hosts', '[127.0.0.1]:22396 ' + public)!
	mut daemon := os.new_process('/bin/sh')
	daemon.set_args(['-c', 'exec ' + [server, '--listen', '127.0.0.1:22396', '--user', 'm17c',
		'--home', dir + '/home', '--host-key', dir + '/seed'].map(os.quoted_path(it)).join(' ')
		+ ' >' + os.quoted_path(dir + '/daemon.log') + ' 2>&1'])
	daemon.run()
	defer { if daemon.is_alive() { daemon.signal_kill() }; daemon.wait(); daemon.close() }
	time.sleep(500 * time.millisecond)
	if !daemon.is_alive() { return error('daemon failed') }
	options := ['-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
		'-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + dir + '/known_hosts']
	ssh := ['ssh', ...options, '-p', '22396', '-i', dir + '/key', 'm17c@127.0.0.1']
	scp := ['scp', '-O', ...options, '-P', '22396', '-i', dir + '/key']
	mut block := []u8{len: 65536}
	for i in 0 .. block.len { block[i] = u8((i * 31 + i / 251) % 256) }
	mut file := os.create(dir + '/upload.bin')!
	mut digest := sha256.new()
	for _ in 0 .. 800 {
		if file.write(block)! != block.len { return error('short fixture write') }
		digest.write(block)!
	}
	file.close()
	hash := digest.sum([]u8{}).hex()
	if sha256.sum(os.read_bytes(dir + '/upload.bin')!).hex() != hash { return error('source hash mismatch') }
	step(dir, 'upload', [...scp, dir + '/upload.bin', 'm17c@127.0.0.1:' + dir + '/home/upload.bin'], 0, 900)!
	remote := step(dir, 'digest', [...ssh, 'sha256sum ' + os.quoted_path(dir + '/home/upload.bin')], 0, 30)!
	if remote.fields()[0] != hash { return error('remote hash mismatch') }
	step(dir, 'download', [...scp, 'm17c@127.0.0.1:' + dir + '/home/upload.bin', dir + '/download.bin'], 0, 900)!
	if sha256.sum(os.read_bytes(dir + '/download.bin')!).hex() != hash { return error('download hash mismatch') }
	println('SCP-SHA256 source=remote=download ' + hash)
	for i in 0 .. 20 {
		if step(dir, 'sequential-${i}', [...ssh, 'echo SESSION-${i}'], 0, 30)!.trim_space() != 'SESSION-${i}' { return error('session output') }
	}
	if step(dir, 'status', [...ssh, 'echo OUTPUT; echo ERRORS >&2; exit 7'], 7, 30)! != 'OUTPUT\n'
		|| !os.read_file(dir + '/status.stderr')!.split_into_lines().contains('ERRORS') { return error('stderr/status separation') }
	pty := step(dir, 'pty', ['env', '-i', 'PATH=/usr/bin:/bin', 'HOME=' + dir, 'LC_ALL=C',
		'ssh', ...options, '-p', '22396', '-i', dir + '/key', '-tt', 'm17c@127.0.0.1', 'echo M17C-PTY'], 0, 30)!
	if pty.replace('\r', '') != 'M17C-PTY\n' { return error('PTY output') }
	step(dir, 'wrong-keygen', ['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', dir + '/wrong'], 0, 10)!
	step(dir, 'wrong-key', ['ssh', ...options, '-p', '22396', '-i', dir + '/wrong', 'm17c@127.0.0.1', 'true'], 255, 30)!
	step(dir, 'no-key', ['ssh', ...options, '-p', '22396', '-o', 'PubkeyAuthentication=no', 'm17c@127.0.0.1', 'true'], 255, 30)!
	for name in ['wrong-key', 'no-key'] {
		if !os.read_file(dir + '/' + name + '.stderr')!.contains('Permission denied (publickey)') { return error('denial missing') }
	}
	if step(dir, 'sustained', [...ssh, 'echo BEGIN; sleep 210; echo END'], 0, 240)! != 'BEGIN\nEND\n' { return error('sustained markers') }
	println('SCP-TRANSFER PASS')
}
