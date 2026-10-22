// SPDX-License-Identifier: GPL-2.0-or-later
// Wire/QMP/Secrets and enrollment flow adapted from tests/fullstack/controller.v.
// COM2 is secret: never serialize it, screenshot enrollment, or print QMP errors.
// Mission16B ISO qualification controller. Local Linux/KVM only.
// Guest fixture MUST enable home_test_bridge and home_mask_enrollment_words,
// with the diagnostic home gate enrolling /dev/sd0. Never use a production ISO.
module main

import os
import net
import net.unix
import json2
import crypto.rand
import time

#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

$if linux {
	#include <sys/prctl.h>
	fn C.sigpending(&C.sigset_t) int
	fn C.sigismember(&C.sigset_t, int) int
}

struct C.pollfd {
mut:
	fd      int
	events  i16
	revents i16
}

struct C.rlimit {
	rlim_cur u64
	rlim_max u64
}

fn C.poll(&C.pollfd, usize, int) int
fn C.setrlimit(int, &C.rlimit) int
fn C.mlock(voidptr, usize) int
fn C.munlock(voidptr, usize) int
fn C.explicit_bzero(voidptr, usize)
fn C.umask(u32) u32
fn C.mkdir(&char, u32) int
fn C.ftruncate(int, u64) int
fn C.fsync(int) int
fn C.prctl(int, ...) int

const firmware = '/usr/share/edk2/x64/OVMF_CODE.4m.fd'
const firmware_vars = '/usr/share/edk2/x64/OVMF_VARS.4m.fd'
const disk_bytes = 128 * 1024 * 1024

struct Secrets {
mut:
	phrase     [128]u8
	phrase_len int
	password   [32]u8
	entropy    [16]u8
}

struct Wire {
mut:
	conn     &unix.StreamConn = unsafe { nil }
	deadline u64
	sequence int
}

struct Receipt {
	op   u32
	size int
}

struct Boot {
mut:
	process    &os.Process = unsafe { nil }
	qmp        Wire
	serial     Wire
	dir        string
	serial_log string
	active     bool
}

struct Report {
mut:
	file    os.File
	stage   string = 'startup'
	started u64
}

fn after(seconds int) u64 { return time.sys_mono_now() + u64(seconds) * u64(time.second) }

fn (mut report Report) pass(stage string) ! {
	report.stage = stage
	report.file.writeln('PASS ' + stage)!
	report.file.flush()
	println('PASS ' + stage)
}

fn check_cancelled() ! {
	$if linux {
		pending := C.sigset_t{}
		if C.sigpending(&pending) != 0 || C.sigismember(&pending, C.SIGINT) == 1 || C.sigismember(&pending, C.SIGTERM) == 1 {
			return error('controller interrupted')
		}
	}
}

fn settle(seconds int) ! {
	for _ in 0 .. seconds * 10 {
		check_cancelled()!
		time.sleep(100 * time.millisecond)
	}
}

fn erase(data voidptr, size usize) {
	$if linux {
		C.explicit_bzero(data, size)
	} $else {
		unsafe { C.memset(data, 0, size) }
	}
}

// Own the descriptor during failed connects; SDK connect_stream alone leaks it.
fn connect_bounded(path string, deadline u64) !Wire {
	if path.len >= 104 || path.contains('\x00') { return error('socket path rejected') }
	addresses := net.resolve_addrs(path, .unix, .tcp)!
	address := addresses[0]
	for time.sys_mono_now() < deadline {
		check_cancelled()!
		fd := C.socket(C.AF_UNIX, C.SOCK_STREAM, 0)
		if fd < 0 { return error('socket unavailable') }
		if C.fcntl(fd, C.F_SETFD, C.FD_CLOEXEC) != 0 || C.fcntl(fd, C.F_SETFL, C.O_NONBLOCK) != 0 {
			C.close(fd)
			return error('socket configuration failed')
		}
		mut connected := C.connect(fd, voidptr(&address), address.len()) == 0
		if !connected && C.errno in [C.EINPROGRESS, C.EAGAIN, C.EINTR] {
			mut p := C.pollfd{ fd: fd, events: i16(C.POLLOUT) }
			for time.sys_mono_now() < deadline {
				check_cancelled() or {
					C.close(fd)
					return err
				}
				n := C.poll(&p, 1, 50)
				if n < 0 && C.errno != C.EINTR { break }
				if n <= 0 { continue }
				mut status := i32(0)
				mut size := u32(sizeof(i32))
				connected = C.getsockopt(fd, C.SOL_SOCKET, C.SO_ERROR, &status, &size) == 0 && status == 0
				break
			}
		}
		if connected {
			socket := unix.stream_socket_from_handle(fd) or {
				C.close(fd)
				return error('socket failed')
			}
			return Wire{ conn: &unix.StreamConn{ sock: *socket }, deadline: deadline }
		}
		C.close(fd)
		time.sleep(50 * time.millisecond)
	}
	return error('connect timeout')
}

fn (mut w Wire) close() {
	if !isnil(w.conn) {
		w.conn.close() or {}
		w.conn = unsafe { nil }
	}
}

fn (w &Wire) ready(write bool) ! {
	if isnil(w.conn) { return error('socket not connected') }
	mut p := C.pollfd{ fd: w.conn.sock.handle, events: i16(if write { C.POLLOUT } else { C.POLLIN }) }
	for time.sys_mono_now() < w.deadline {
		check_cancelled()!
		n := C.poll(&p, 1, 50)
		if n < 0 {
			if C.errno == C.EINTR { continue }
			return error('poll failed')
		}
		if n > 0 {
			if p.revents & i16(C.POLLNVAL | C.POLLERR) != 0 { return error('socket failed') }
			return
		}
	}
	return error('socket timeout')
}

fn (mut w Wire) exact(data &u8, size int) ! {
	mut pos := 0
	for pos < size {
		w.ready(false)!
		n := unsafe { C.recv(w.conn.sock.handle, data + pos, usize(size - pos), 0) }
		if n < 0 {
			if C.errno in [C.EINTR, C.EAGAIN] { continue }
			return error('read failed')
		}
		if n == 0 { return error('socket closed') }
		pos += int(n)
	}
}

fn (mut w Wire) send(data string) ! {
	mut pos := 0
	for pos < data.len {
		w.ready(true)!
		n := unsafe { C.send(w.conn.sock.handle, data.str + pos, usize(data.len - pos), 0) }
		if n < 0 {
			if C.errno in [C.EINTR, C.EAGAIN] { continue }
			return error('write failed')
		}
		if n == 0 { return error('socket closed') }
		pos += int(n)
	}
}

fn (mut w Wire) line() !map[string]json2.Any {
	mut data := []u8{cap: 1024}
	mut byte := [1]u8{}
	for data.len < 1024 * 1024 {
		w.exact(&byte[0], 1)!
		if byte[0] == `\n` {
			return json2.decode[json2.Any](data.bytestr())!.as_map()
		}
		data << byte[0]
	}
	return error('QMP reply exceeded bound')
}

fn (mut w Wire) request(name string, args map[string]json2.Any) !json2.Any {
	w.deadline = after(15)
	w.sequence++
	id := 'm15-' + w.sequence.str()
	w.send(json2.encode({
		'execute':   json2.Any(name)
		'arguments': json2.Any(args)
		'id':        json2.Any(id)
	}) + '\n')!
	for {
		reply := w.line()!
		if 'event' in reply { continue }
		if (reply['id'] or { json2.Null{} }) != json2.Any(id) { continue }
		// Never surface QMP descriptions: a peer may echo input commands.
		if 'error' in reply { return error('QMP command rejected') }
		return reply['return'] or { return error('QMP result missing') }
	}
	return error('QMP closed')
}

fn open_qmp(path string) !Wire {
	mut w := connect_bounded(path, after(30))!
	mut good := false
	defer { if !good { w.close() } }
	greeting := w.line()!
	if 'QMP' !in greeting { return error('QMP greeting missing') }
	w.request('qmp_capabilities', {})!
	kvm := w.request('query-kvm', {})!.as_map()
	if (kvm['enabled'] or { json2.Any(false) }) != json2.Any(true) {
		return error('KVM not enabled')
	}
	good = true
	return w
}

fn key(mut w Wire, name string) ! {
	w.request('human-monitor-command', {
		'command-line': json2.Any('sendkey ' + name + ' 35')
	})!
	time.sleep(100 * time.millisecond)
}

fn type_byte(mut w Wire, ch u8) ! {
	name := match ch {
		`a`...`z`, `0`...`9` { ch.ascii_str() }
		`A`...`Z` { 'shift-' + (ch + 32).ascii_str() }
		` ` { 'spc' }
		`\n` { 'ret' }
		`-` { 'minus' }
		`_` { 'shift-minus' }
		`/` { 'slash' }
		`.` { 'dot' }
		`>` { 'shift-dot' }
		`|` { 'shift-backslash' }
		`'` { 'apostrophe' }
		else { return error('unsupported input byte') }
	}
	key(mut w, name)!
}

// Never construct a string containing a credential; only one key at a time.
fn type_secret(mut w Wire, data &u8, size int) ! {
	for i in 0 .. size { type_byte(mut w, unsafe { data[i] })! }
}

fn le32(data []u8) u32 {
	return u32(data[0]) | u32(data[1]) << 8 | u32(data[2]) << 16 | u32(data[3]) << 24
}

fn (mut w Wire) header() !Receipt {
	magic := 'M14A-HM1'
	mut matched := 0
	mut byte := u8(0)
	for matched < magic.len {
		w.exact(&byte, 1)!
		if byte == magic[matched] {
			matched++
		} else {
			matched = if byte == magic[0] { 1 } else { 0 }
		}
	}
	mut h := [8]u8{}
	w.exact(&h[0], 8)!
	op := le32(h[..4])
	length := le32(h[4..])
	if length > 128 { return error('bridge length rejected') }
	if op !in [u32(2), 10, 11, 12, 13] { return error('bridge operation rejected') }
	if op != 2 && length != 0 { return error('status payload rejected') }
	if op == 13 { return error('guest entropy failed') }
	return Receipt{ op: op, size: int(length) }
}

fn (mut w Wire) expect(op u32, seconds int) ! {
	w.deadline = after(seconds)
	receipt := w.header()!
	// No op2 payload is ever read on a later boot; abort without logging it.
	if receipt.op != op || receipt.size != 0 { return error('unexpected bridge state') }
}

fn read_phrase(mut w Wire, mut s Secrets) ! {
	w.deadline = after(180)
	receipt := w.header()!
	if receipt.op != 2 || receipt.size < 23 { return error('phrase frame missing') }
	s.phrase_len = receipt.size
	w.exact(&s.phrase[0], s.phrase_len)!
	mut words := 1
	for i in 0 .. s.phrase_len {
		ch := s.phrase[i]
		if ch == ` ` {
			if i == 0 || i == s.phrase_len - 1 || s.phrase[i - 1] == ` ` {
				return error('phrase format rejected')
			}
			words++
		} else if ch < `a` || ch > `z` {
			return error('phrase alphabet rejected')
		}
	}
	if words != 12 { return error('phrase count rejected') }
}

fn create_disk(path string) ! {
	fd := C.open(&char(path.str), C.O_RDWR | C.O_CREAT | C.O_EXCL | C.O_NOFOLLOW | C.O_CLOEXEC, 0o600)
	if fd < 0 { return error('disk must be new') }
	defer { C.close(fd) }
	if C.ftruncate(fd, disk_bytes) != 0 || C.fsync(fd) != 0 { return error('disk creation failed') }
}

fn flush_disk(path string) ! {
	fd := C.open(&char(path.str), C.O_RDWR | C.O_NOFOLLOW | C.O_CLOEXEC)
	if fd < 0 { return error('disk reopen failed') }
	defer { C.close(fd) }
	if C.fsync(fd) != 0 { return error('disk flush failed') }
}

fn exclusive_dir(path string) ! {
	if C.mkdir(&char(path.str), 0o700) != 0 { return error('directory must be new') }
}

fn (mut b Boot) cleanup() ! {
	b.serial.close()
	defer { b.qmp.close() }
	if isnil(b.process) || !b.active { return }
	defer {
		b.process.close()
		b.active = false
	}
	if b.process.is_alive() {
		b.qmp.deadline = after(2)
		b.qmp.send('{"execute":"quit"}\n') or {}
		end := after(5)
		for b.process.is_alive() && time.sys_mono_now() < end { time.sleep(50 * time.millisecond) }
		if b.process.is_alive() { C.kill(b.process.pid, C.SIGKILL) }
		endkill := after(5)
		for b.process.is_alive() && time.sys_mono_now() < endkill {
			time.sleep(50 * time.millisecond)
		}
	}
	if b.process.is_alive() {
		return error('QEMU cleanup still alive')
	} else {
		b.process.wait()
		println('EXIT qemu code=${b.process.code} state=${b.process.status}')
	}
}

fn (mut b Boot) launch(root string, iso string, disk string, qemu string) ! {
	b.dir = root
	b.serial_log = root + '/com1.log'
	qmp_path := root + '/qmp.sock'
	secret_path := root + '/secret.sock'
	if qmp_path.len >= 104 || secret_path.len >= 104 { return error('run path too long') }
	code := root + '/OVMF_CODE.4m.fd'
	vars := root + '/OVMF_VARS.4m.fd'
	args := ['-name', 'vinix-m16b-ssh', '-nodefaults', '-M', 'q35,smm=off', '-enable-kvm', '-cpu',
		'host', '-smp', '4', '-m', '4096', '-vga', 'std', '-drive',
		'if=pflash,format=raw,unit=0,readonly=on,file=' + code, '-drive',
		'if=pflash,format=raw,unit=1,file=' + vars, '-drive',
		'if=none,id=home,format=raw,cache=writeback,file=' + disk, '-device',
		'ide-hd,drive=home,bus=ide.0', '-drive',
		'if=none,id=cdrom,media=cdrom,readonly=on,format=raw,file=' + iso, '-device',
		'ide-cd,drive=cdrom,bus=ide.2,bootindex=1', '-netdev',
		'user,id=sshnet,hostfwd=tcp:127.0.0.1:22289-:22', '-device', 'virtio-net-pci,netdev=sshnet',
		'-display', 'none', '-monitor', 'none', '-serial', 'file:' + b.serial_log, '-serial',
		'unix:' + secret_path + ',server=on,wait=off', '-qmp',
		'unix:' + qmp_path + ',server=on,wait=off', '-no-reboot', '-S']
	b.process = os.new_process(qemu)
	b.process.set_args(args)
	b.process.set_redirect_stdio()
	b.process.set_stdin_path('/dev/null')
	b.process.run()
	b.active = true
	if b.process.pid <= 0 || !b.process.is_alive() { return error('QEMU failed to start') }
	b.qmp = open_qmp(qmp_path)!
	mut expected := [qemu]
	expected << args
	actual := os.read_file('/proc/${b.process.pid}/cmdline')!.trim_right('\x00').split('\x00')
	if actual != expected { return error('QEMU actual argv differs') }
	os.write_file(root + '/qemu-argv.json', json2.encode(actual) + '\n')!
	b.serial = connect_bounded(secret_path, after(30))!
	blocks := b.qmp.request('query-block', {})!
	mut home_found := false
	mut iso_found := false
	for block in blocks.as_array() {
		entry := block.as_map()
		inserted := (entry['inserted'] or { return error('empty block device') }).as_map()
		file := (inserted['file'] or { json2.Null{} }).str()
		if file !in [disk, iso, code, vars] { return error('unexpected backing file') }
		ro := (inserted['ro'] or { json2.Any(false) }) == json2.Any(true)
		if file == iso {
			if iso_found || !ro { return error('ISO block invalid') }
			iso_found = true
		}
		if file == disk {
			if home_found || ro { return error('HOME block invalid') }
			home_found = true
		}
	}
	if !home_found || !iso_found { return error('required block missing') }
	os.write_file(root + '/query-block.json', json2.encode(blocks) + '\n')!
	b.qmp.request('cont', {})!
}

fn pre_enrollment_refused(serial_log string) ! {
	ssh := os.find_abs_path_of_executable('ssh')!
	mut p := os.new_process(ssh)
	defer { p.close() }
	mut env := os.environ()
	env['LC_ALL'] = 'C'
	p.set_environment(env)
	p.set_args(['-F', '/dev/null', '-p', '22289', '-o', 'ConnectTimeout=2', '-o', 'ConnectionAttempts=1',
		'-o', 'BatchMode=yes', '-o', 'IdentityAgent=none', '-o', 'IdentitiesOnly=yes', '-o',
		'PubkeyAuthentication=no', '-o', 'PasswordAuthentication=no', '-o',
		'KbdInteractiveAuthentication=no', '-o', 'StrictHostKeyChecking=yes', 'm16b@127.0.0.1',
		'true'])
	p.set_redirect_stdio()
	p.set_stdin_path('/dev/null')
	p.run()
	end := after(5)
	for p.is_alive() && time.sys_mono_now() < end {
		check_cancelled() or {
			C.kill(p.pid, C.SIGKILL)
			finish_child(mut p, 'pre-enrollment-ssh') or {}
			return err
		}
		time.sleep(50 * time.millisecond)
	}
	if p.is_alive() { C.kill(p.pid, C.SIGKILL) }
	finish_child(mut p, 'pre-enrollment-ssh')!
	output := p.stderr_slurp()
	// Slirp owns the host listening socket even while the guest port is closed.
	// Require an actual guest-side ECONNREFUSED receipt as well as the outer
	// client failure. A host-forward reset alone is not sufficient evidence.
	os.write_file(os.dir(serial_log) + '/preunlock-client.log', output)!
	guest := os.read_file(serial_log)!
	closed := output.contains('Connection refused') || output.contains('Connection reset by peer')
		|| output.contains('Connection closed')
	if p.code != 255 || !closed || !guest.contains('M16B-PREUNLOCK: CONNECT_REFUSED locked_HOME=true') {
		return error('pre-enrollment refusal not proven')
	}
}

fn wait_for_ssh() ! {
	end := after(180)
	// Reserve the SDK's 5s connect timeout + 2s read + 1s retry delay.
	for time.sys_mono_now() + u64(8 * time.second) < end {
		check_cancelled()!
		mut conn := net.dial_tcp('127.0.0.1:22289') or {
			settle(1)!
			continue
		}
		conn.set_read_timeout(2 * time.second)
		mut buf := [256]u8{}
		n := conn.read(mut buf) or {
			conn.close() or {}
			settle(1)!
			continue
		}
		conn.close() or {}
		if n >= 8 && unsafe { buf[..n].bytestr() }.starts_with('SSH-2.0-') { return }
		settle(1)!
	}
	return error('post-unlock SSH timeout')
}

fn callback(path string, root string) ! {
	mut p := os.new_process(path)
	defer { p.close() }
	mut env := os.environ()
	env['SSH_PORT'] = '22289'
	env['SSH_USER'] = 'm16b'
	env['SSH_HOST'] = '127.0.0.1'
	env['SSH_KEY'] = '/home/agent/build/m16b-receipts/host-interop-r1/client'
	env['SSH_RUN_DIR'] = root
	p.set_environment(env)
	p.use_pgroup = true
	p.run()
	// Two large SCP commands each have a 900-second budget.
	end := after(2100)
	for p.is_alive() && time.sys_mono_now() < end {
		check_cancelled() or {
			p.signal_pgkill()
			finish_child(mut p, 'acceptance-callback') or {}
			return err
		}
		time.sleep(100 * time.millisecond)
	}
	if p.is_alive() { p.signal_pgkill() }
	finish_child(mut p, 'acceptance-callback')!
	if p.code != 0 { return error('acceptance callback failed') }
}

fn finish_child(mut p os.Process, label string) ! {
	end := after(5)
	for p.is_alive() && time.sys_mono_now() < end { time.sleep(50 * time.millisecond) }
	if p.is_alive() {
		println('FAIL ${label} cleanup-still-alive')
		return error('child cleanup still alive')
	}
	p.wait()
	println('EXIT ${label} code=${p.code} state=${p.status}')
}

fn qualify(mut report Report, root string, iso string, callback_path string, qemu string) ! {
	mut secrets := &Secrets{}
	if C.mlock(secrets, sizeof(Secrets)) != 0 { return error('credential memory lock failed') }
	defer {
		erase(secrets, sizeof(Secrets))
		C.munlock(secrets, sizeof(Secrets))
	}
	mut entropy := unsafe { (&secrets.entropy[0]).vbytes(16) }
	rand.read(mut entropy)!
	for i in 0 .. 16 {
		secrets.password[i * 2] = '0123456789abcdef'[secrets.entropy[i] >> 4]
		secrets.password[i * 2 + 1] = '0123456789abcdef'[secrets.entropy[i] & 15]
	}
	erase(&secrets.entropy[0], 16)
	os.cp(firmware, root + '/OVMF_CODE.4m.fd')!
	os.cp(firmware_vars, root + '/OVMF_VARS.4m.fd')!
	os.chmod(root + '/OVMF_CODE.4m.fd', 0o600)!
	os.chmod(root + '/OVMF_VARS.4m.fd', 0o600)!
	flush_disk(root + '/OVMF_CODE.4m.fd')!
	flush_disk(root + '/OVMF_VARS.4m.fd')!
	disk := root + '/home.raw'
	create_disk(disk)!
	mut b := Boot{}
	defer { b.cleanup() or { eprintln('FAIL qemu-cleanup-still-alive') } }
	report.stage = 'ISO-boot-KVM-q35-4cpu-4gib-private-network'
	b.launch(root, iso, disk, qemu)!
	report.pass(report.stage)!
	report.stage = 'masked-enrollment-frame'
	read_phrase(mut b.serial, mut secrets) or {
		// The fixture masks enrollment words. Capture only this masked screen;
		// never save the secret UART or a QMP input transcript.
		b.qmp.request('screendump', {
			'filename': json2.Any(root + '/masked-enrollment-timeout.ppm')
		}) or {}
		return err
	}
	report.pass('12word-frame-locked-memory')!
	report.stage = 'pre-enrollment-SSH-refused'
	mut refusal_passed := true
	pre_enrollment_refused(b.serial_log) or {
		refusal_passed = false
		report.file.writeln('FAIL pre-enrollment-SSH-refused (continue diagnostic transport checks; final gate stays NO-GO)')!
		report.file.flush()
		println('FAIL pre-enrollment-SSH-refused; collecting remaining diagnostic receipts')
	}
	if refusal_passed { report.pass(report.stage)! }
	report.stage = 'enrollment-verified-QMP-flow'
	key(mut b.qmp, 'ret')!
	settle(1)!
	type_secret(mut b.qmp, &secrets.phrase[0], secrets.phrase_len)!
	key(mut b.qmp, 'ret')!
	settle(1)!
	type_secret(mut b.qmp, &secrets.password[0], 32)!
	key(mut b.qmp, 'ret')!
	settle(1)!
	type_secret(mut b.qmp, &secrets.password[0], 32)!
	key(mut b.qmp, 'ret')!
	report.stage = 'op12-mounted'
	b.serial.expect(12, 240)!
	erase(secrets, sizeof(Secrets))
	report.pass(report.stage)!
	report.stage = 'post-unlock-SSH-banner-180s'
	wait_for_ssh()!
	report.pass(report.stage)!
	report.stage = 'parent-OpenSSH-acceptance-callback'
	callback(callback_path, root)!
	report.pass(report.stage)!
	report.stage = 'bounded-QEMU-cleanup'
	b.cleanup()!
	report.pass(report.stage)!
	if !refusal_passed {
		report.stage = 'pre-enrollment-SSH-refused'
		return error('pre-unlock refusal unqualified')
	}
}

fn run() ! {
	$if !linux {
		return error('Linux KVM host required')
	}
	limit := C.rlimit{}
	if C.setrlimit(C.RLIMIT_CORE, &limit) != 0 { return error('core dump protection failed') }
	$if linux {
		if C.prctl(C.PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 { return error('dump protection failed') }
	}
	C.umask(0o077)
	os.signal_ignore(.pipe)
	$if linux {
		blocked := C.sigset_t{}
		C.sigemptyset(&blocked)
		if C.sigaddset(&blocked, C.SIGINT) != 0 || C.sigaddset(&blocked, C.SIGTERM) != 0
			|| C.sigprocmask(C.SIG_BLOCK, &blocked, unsafe { nil }) != 0 {
			return error('signal setup failed')
		}
	}
	if os.args.len != 4 { return error('expected RUN_DIR ISO POST_UNLOCK_CALLBACK') }
	for arg in os.args[1..] {
		if !os.is_abs_path(arg) || arg.contains_any('\x00\n\r,') {
			return error('absolute nonsecret paths required')
		}
	}
	root := os.real_path(os.dir(os.args[1])) + '/' + os.file_name(os.args[1])
	iso := os.real_path(os.args[2])
	cb := os.real_path(os.args[3])
	if !os.is_file(iso) || !os.is_executable(cb) || !os.is_file(firmware) || !os.is_file(firmware_vars)
		|| !os.exists('/dev/kvm') {
		return error('input or host requirement unavailable')
	}
	qemu := os.find_abs_path_of_executable('qemu-system-x86_64')!
	exclusive_dir(root)!
	mut report := Report{ file: os.create(root + '/status.txt')!, started: time.sys_mono_now() }
	defer { report.file.close() }
	report.file.writeln('MODEL gpt-6.1-sol implementation lane 2')!
	qualify(mut report, root, iso, cb, qemu) or {
		report.file.writeln('FAIL ' + report.stage) or {}
		report.file.writeln('ELAPSED seconds=' + ((time.sys_mono_now() - report.started) / u64(time.second)).str()) or {}
		println('FAIL ' + report.stage)
		return error('qualification failed')
	}
	report.pass('controller-complete-callback-exit-zero')!
	report.file.writeln('ELAPSED seconds=' + ((time.sys_mono_now() - report.started) / u64(time.second)).str())!
}

fn main() {
	run() or {
		eprintln('FAIL controller; inspect nonsecret status.txt if created')
		exit(1)
	}
}
