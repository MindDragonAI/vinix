// SPDX-License-Identifier: GPL-2.0-or-later
// Bounded diagnostic callback. Client logs go to files, never unread pipes.
module main

import os
import time

#include <signal.h>
fn C.kill(int, int) int

fn paused_step(dir string, args []string) int {
	command := ['timeout', '--foreground', '-k', '3', '900', ...args].map(os.quoted_path(it)).join(' ')
	mut p := os.new_process('/bin/sh')
	defer { p.close() }
	p.use_pgroup = true
	p.set_args(['-c', command + ' > ' + os.quoted_path(dir + '/upload-paused.log') + ' 2>&1'])
	start := time.sys_mono_now()
	p.run()
	time.sleep(20 * time.second)
	if p.is_alive() {
		if C.kill(-p.pid, C.SIGSTOP) != 0 { return 2 }
		println('M16B3 PAUSE elapsed_ms=${(time.sys_mono_now()-start)/1000000}')
		time.sleep(35 * time.second)
		if C.kill(-p.pid, C.SIGCONT) != 0 { return 2 }
		println('M16B3 RESUME elapsed_ms=${(time.sys_mono_now()-start)/1000000}')
	}
	p.wait()
	os.write_file(dir + '/upload-paused.exit', '${p.code}\n') or { panic(err) }
	os.write_file(dir + '/upload-paused.elapsed_ns', '${time.sys_mono_now()-start}\n') or { panic(err) }
	println('M16B3 upload-paused exit=${p.code} elapsed_ms=${(time.sys_mono_now()-start)/1000000}')
	return p.code
}

fn run_step(dir string, name string, args []string, limit int) int {
	start := time.sys_mono_now()
	command := ['timeout', '-k', '3', limit.str(), ...args].map(os.quoted_path(it)).join(' ')
	result := os.execute(command + ' > ' + os.quoted_path(dir + '/' + name + '.log') + ' 2>&1')
	elapsed := time.sys_mono_now() - start
	os.write_file(dir + '/' + name + '.exit', '${result.exit_code}\n') or { panic(err) }
	os.write_file(dir + '/' + name + '.elapsed_ns', '${elapsed}\n') or { panic(err) }
	println('M16B3 ${name} exit=${result.exit_code} elapsed_ms=${elapsed / 1000000}')
	return result.exit_code
}

fn main() {
	root := os.getenv('SSH_RUN_DIR')
	key := os.getenv('SSH_KEY')
	port := os.getenv('SSH_PORT')
	if root == '' || key == '' || port !in ['22289', '22290'] { exit(2) }
	dir := root + '/diagnose'
	os.mkdir(dir) or { panic(err) }
	if run_step(dir, 'keyscan', ['ssh-keyscan', '-T', '5', '-p', port, '-t', 'ed25519', '127.0.0.1'], 15) != 0 { exit(1) }
	known := os.read_file(dir + '/keyscan.log') or { panic(err) }
	lines := known.split_into_lines().filter(it.starts_with('[127.0.0.1]:' + port + ' ssh-ed25519 '))
	if lines.len != 1 { exit(2) }
	os.write_file(dir + '/known_hosts', lines[0] + '\n') or { panic(err) }
	opts := ['-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + dir + '/known_hosts', '-i', key]
	target := 'm16b@127.0.0.1'
	ssh := ['ssh', ...opts, '-p', port]
	scp := ['scp', '-S', '/home/agent/build/m16b3-receipts/debug-ssh', '-O', ...opts, '-P', port]
	_ := run_step(dir, 'sampler', [...ssh, target, 'setsid /usr/bin/vinix-desktop --perf-sampler </dev/null >/dev/null 2>&1 &'], 15)
	source := '/home/agent/build/m16b-receipts/host-interop-r1/large'
	if os.file_size(source) != 50 * 1024 * 1024 { exit(2) }
	mode := os.getenv('SSH_STAGE3_MODE')
	if mode == 'download' {
		if run_step(dir, 'create-download', [...ssh, target, 'dd if=/dev/zero of=/tmp/m16b3-download bs=1048576 count=50; sha256sum /tmp/m16b3-download'], 45) != 0 { exit(1) }
		exit(run_step(dir, 'download-50m', [...scp, target + ':/tmp/m16b3-download', dir + '/download-copy'], 900))
	}
	if mode == 'multi' {
		mut files := []string{}
		mut f := os.open(source) or { panic(err) }
		defer { f.close() }
		for i in 0 .. 8 {
			data := f.read_bytes(5 * 1024 * 1024)
			if data.len != 5 * 1024 * 1024 { exit(2) }
			path := dir + '/chunk-${i}'
			os.write_file_array(path, data) or { panic(err) }
			files << path
		}
		exit(run_step(dir, 'upload-8x5m-one-session', [...scp, ...files, target + ':/root/home/m16b/'], 900))
	}
	if mode == 'pause' { exit(paused_step(dir, [...scp, source, target + ':/root/home/m16b/large-copy'])) }
	code := run_step(dir, 'upload-50m', [...scp, source, target + ':/root/home/m16b/large-copy'], 900)
	_ := run_step(dir, 'after', [...ssh, '-vvv', target, 'ls -l /root/home/m16b/large-copy; cat /root/.vinix-service-logs/ssh-server.log; cat /proc/meminfo'], 25)
	exit(code)
}
