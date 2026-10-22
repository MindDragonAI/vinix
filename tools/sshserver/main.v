// SPDX-License-Identifier: GPL-2.0-or-later
module main

import os
import net
import time
import encoding.base64
import tools.packages.signing

struct Config {
mut:
	listen      string = '0.0.0.0:22'
	user        string
	home        string
	host_key    string = '/etc/ssh/ssh_host_ed25519_key'
	public_only bool
}

fn main() {
	run() or {
		eprintln('vinix-sshd: ${err}')
		exit(1)
	}
}

fn run() ! {
	mut config := Config{}
	mut i := 1
	for i < os.args.len {
		arg := os.args[i]
		if arg in ['--help', '-h'] {
			println('Usage: vinix-sshd --user USER --home /home/USER [--listen address:port] [--host-key /etc/ssh/ssh_host_ed25519_key]\n  --public-key  print host public key and exit\n  --self-test   run built-in crypto/codec checks\n  --scp ...     internal legacy SCP helper; use scp -O on clients')
			return
		}
		if arg == '--self-test' {
			self_test()!
			println('self-test passed')
			return
		}
		if arg == '--scp' {
			scp_main(os.args[i + 1..])!
			return
		}
		if arg == '--public-key' {
			config.public_only = true
			i++
			continue
		}
		if i + 1 >= os.args.len { return error('missing option value') }
		value := os.args[i + 1]
		match arg {
			'--listen' { config.listen = value }
			'--user' { config.user = value }
			'--home' { config.home = value }
			'--host-key' { config.host_key = value }
			else { return error('unknown option ${arg}') }
		}
		i += 2
	}
	key := load_host_key(config.host_key)!
	if config.public_only {
		println('ssh-ed25519 ${base64.encode(public_blob(key.public_key()))} Vinix')
		return
	}
	if config.user == '' || config.user.len > 128 || config.user.contains('\x00') || !config.home.starts_with('/') {
		return error('--user and absolute --home are required')
	}
	// Run as the unlocked home owner. Startup/privilege transition belongs to launcher.
	_ := authorized_keys(config.home)!
	unsafe { C.signal(C.SIGPIPE, C.SIG_IGN) }
	mut listener := net.listen_tcp(.ip, config.listen)!
	defer { listener.close() or {} }
	eprintln('vinix-sshd: listening on ${config.listen}; user ${config.user}')
	mut local_budget := FailureBudget{}
	mut budget := &local_budget
	mut shared_storage := unsafe { voidptr(nil) }
	defer { if shared_storage != unsafe { nil } { C.munmap(shared_storage, sizeof(FailureBudget)) } }
	$if ssh_session_workers ? {
		// Production builds use -gc none. A private worker owns all per-session
		// allocations; only this small, serialized retry budget survives its exit.
		storage := C.mmap(unsafe { nil }, sizeof(FailureBudget), C.PROT_READ | C.PROT_WRITE,
			C.MAP_SHARED | C.MAP_ANONYMOUS, -1, 0)
		if storage == unsafe { voidptr(-1) } {
			return error('shared authentication budget unavailable')
		}
		shared_storage = storage
		budget = unsafe { &FailureBudget(storage) }
	}
	for {
		mut socket := listener.accept()!
		$if ssh_session_workers ? {
			pid := C.fork()
			if pid < 0 {
				socket.close() or {}
				unsafe { free(socket) }
				return error('session worker fork failed')
			}
			if pid > 0 {
				// TcpConn.close also calls shutdown, which would close the worker's
				// inherited endpoint. Close only this process's descriptor reference.
				C.close(socket.sock.handle)
				unsafe { free(socket) }
				mut status := i32(0)
				for C.waitpid(pid, &status, 0) < 0 {
					if C.errno != C.EINTR { return error('session worker wait failed') }
				}
				continue
			}
			// Likewise, do not shut down the supervisor's inherited listening socket.
			C.close(listener.sock.handle)
		}
		socket.set_read_timeout(15 * time.second)
		socket.set_write_timeout(15 * time.second)
		socket.set_read_deadline(time.now().add(30 * time.second))
		socket.set_write_deadline(time.now().add(30 * time.second))
		mut t := Transport{ socket: socket, started: time.now().unix() }
		serve(mut t, config, key, mut budget) or { eprintln('vinix-sshd: session ended: ${err}') }
		t.drain_disconnect()
		socket.close() or {}
		$if ssh_session_workers ? {
			C._exit(0)
		}
	}
}

fn serve(mut t Transport, config Config, key signing.PrivateKey, mut budget FailureBudget) ! {
	if !budget.available() { return error('authentication budget exhausted') }
	t.handshake(key)!
	keys := authorized_keys(config.home)!
	t.authenticate(config.user, keys, mut budget)!
	t.socket.set_read_deadline(time.now().add(3600 * time.second))
	t.socket.set_write_deadline(time.now().add(3600 * time.second))
	t.session_loop(config)!
}
