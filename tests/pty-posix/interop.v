// SPDX-License-Identifier: GPL-2.0-or-later
// Reproduce the acceptance worker's exact stripped client environment.
module main

import os
import time
import crypto.rand

fn command(args []string, log string) !int {
	r := os.execute(args.map(os.quoted_path(it)).join(' ') + ' < /dev/null > ' + os.quoted_path(log + '.stdout') + ' 2> ' + os.quoted_path(log + '.stderr'))
	os.write_file(log + '.exit', '${r.exit_code}\n')!
	return r.exit_code
}

fn main() {
	if os.args.len != 4 { eprintln('Usage: interop.v SERVER FRESH-DIR baseline|fixed'); exit(2) }
	server, work, mode := os.real_path(os.args[1]), os.args[2], os.args[3]
	if os.exists(work) { eprintln('fresh work directory required'); exit(2) }
	os.mkdir_all(work + '/home/.ssh')!
	for path in [work, work + '/home', work + '/home/.ssh'] { os.chmod(path, 0o700)! }
	assert command(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', work + '/key'], work + '/keygen')! == 0
	os.cp(work + '/key.pub', work + '/home/.ssh/authorized_keys')!
	os.chmod(work + '/home/.ssh/authorized_keys', 0o600)!
	mut seed := 'Vinix SSH Ed25519 seed v1\n'.bytes()
	seed << rand.bytes(32)!
	os.write_file_array(work + '/seed', seed)!
	os.chmod(work + '/seed', 0o600)!
	mut daemon := os.new_process(server)
	daemon.set_args(['--listen', '127.0.0.1:22296', '--user', 'm17c', '--home', work + '/home', '--host-key', work + '/seed'])
	daemon.set_redirect_stdio()
	daemon.run()
	defer { if daemon.is_alive() { daemon.signal_kill() }; daemon.wait(); daemon.close() }
	time.sleep(500 * time.millisecond)
	assert daemon.is_alive(), 'host server failed to start'
	for term in ['', 'xterm'] {
		name := if term == '' { 'no-term' } else { 'xterm' }
		mut env := ['env', '-i', 'PATH=/usr/bin:/bin', 'HOME=' + work, 'LC_ALL=C']
		if term != '' { env << 'TERM=' + term }
		args := [...env, 'ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
			'-o', 'IdentityAgent=none', '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
			'-o', 'ConnectTimeout=5', '-i', work + '/key', '-tt', '-p', '22296', 'm17c@127.0.0.1', 'echo M17C-PTY']
		code := command(['timeout', '-k', '3', '15', ...args], work + '/' + name)!
		out := os.read_file(work + '/' + name + '.stdout')!
		err := os.read_file(work + '/' + name + '.stderr')!
		println('SSH-PTY ${name} exit=${code} stdout=${out.replace('\r', '').trim_space()} rejected=${err.contains('PTY allocation request failed')}')
		if mode == 'baseline' && term == '' {
			assert code != 0 && err.contains('PTY allocation request failed') && out == ''
		} else {
			assert code == 0 && out.replace('\r', '') == 'M17C-PTY\n'
		}
	}
	println('SSH-PTY ${mode} PASS')
}
