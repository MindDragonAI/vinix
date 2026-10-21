// Mission15 combined qualification controller. Local Linux/KVM only.
// Guest fixture MUST enable home_test_bridge, home_guest_probe and
// home_mask_enrollment_words. No credential logging or ISO attachment.
module main

import os
import net
import net.unix
import json2
import crypto.rand
import crypto.sha256
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

const marker = 'M15_ENCRYPTED_HOME_PLAINTEXT_PROBE_20261021_unique_c4f9e21d'
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
				mut status := int(0)
				mut size := u32(sizeof(int))
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

fn type_public(mut w Wire, text string) ! {
	for ch in text { type_byte(mut w, ch)! }
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

fn checksum(path string) !string {
	fd := C.open(&char(path.str), C.O_RDONLY | C.O_CLOEXEC | C.O_NOFOLLOW)
	if fd < 0 { return error('checksum input unavailable') }
	defer { C.close(fd) }
	mut digest := sha256.new()
	mut buffer := []u8{len: 1024 * 1024}
	for {
		check_cancelled()!
		n := C.read(fd, buffer.data, usize(buffer.len))
		if n < 0 && C.errno == C.EINTR { continue }
		if n < 0 || n > buffer.len { return error('checksum input read failed') }
		if n == 0 { break }
		digest.write(buffer[..int(n)])!
	}
	return digest.sum([]u8{}).hex()
}

fn (mut b Boot) cleanup() {
	b.serial.close()
	if !isnil(b.process) && b.active {
		if b.process.is_alive() {
			b.qmp.deadline = after(2)
			b.qmp.send('{"execute":"quit"}\n') or {}
			end := after(5)
			for b.process.is_alive() && time.sys_mono_now() < end {
				time.sleep(50 * time.millisecond)
			}
			if b.process.is_alive() { C.kill(b.process.pid, C.SIGKILL) }
			kill_end := after(5)
			for b.process.is_alive() && time.sys_mono_now() < kill_end {
				time.sleep(50 * time.millisecond)
			}
		}
		if !b.process.is_alive() { b.process.wait() }
		b.process.close()
		b.active = false
	}
	b.qmp.close()
}

fn verify_blocks(blocks json2.Any, boot_disk string, home_disk string, code string, vars string) ! {
	mut boot_found := false
	mut home_found := false
	for block in blocks.as_array() {
		entry := block.as_map()
		if (entry['removable'] or { json2.Any(true) }) != json2.Any(false) {
			return error('removable or optical device rejected')
		}
		inserted := (entry['inserted'] or { return error('empty block device rejected') }).as_map()
		file := (inserted['file'] or { json2.Null{} }).str()
		if file !in [boot_disk, home_disk, code, vars] {
			return error('unexpected block backing file')
		}
		if (inserted['drv'] or { json2.Null{} }) != json2.Any('raw') {
			return error('nonraw block device rejected')
		}
		if file == boot_disk || file == home_disk {
			if (inserted['ro'] or { json2.Any(true) }) != json2.Any(false) {
				return error('qualification disk is readonly')
			}
			if file == boot_disk {
				if boot_found { return error('duplicate boot disk') }
				boot_found = true
			}
			if file == home_disk {
				if home_found { return error('duplicate home disk') }
				home_found = true
			}
		}
	}
	if !boot_found || !home_found { return error('required disks missing') }
}

fn (mut b Boot) launch(root string, n int, boot_disk string, disk string, qemu string) ! {
	b.dir = os.join_path(root, 'boot' + n.str())
	exclusive_dir(b.dir)!
	b.serial_log = os.join_path(b.dir, 'boot' + n.str() + '.serial.log')
	qmp_path := os.join_path(b.dir, 'qmp.sock')
	secret_path := os.join_path(b.dir, 'secret.sock')
	if qmp_path.len >= 104 || secret_path.len >= 104 { return error('run path too long') }
	b.process = os.new_process(qemu)
	code := os.join_path(root, 'OVMF_CODE.4m.fd')
	vars := os.join_path(root, 'OVMF_VARS.4m.fd')
	args := ['-name', 'vinix-m15-boot' + n.str(), '-nodefaults', '-M', 'q35,smm=off', '-enable-kvm',
		'-cpu', 'host', '-smp', '4', '-m', '4096', '-vga', 'std', '-drive',
		'if=pflash,format=raw,unit=0,readonly=on,file=' + code, '-drive',
		'if=pflash,format=raw,unit=1,file=' + vars, '-drive',
		'if=none,id=system,format=raw,cache=writeback,file=' + boot_disk.replace(',', ',,'), '-device',
		'ide-hd,drive=system,bus=ide.0,bootindex=1', '-drive',
		'if=none,id=home,format=raw,cache=writeback,file=' + disk.replace(',', ',,'), '-device',
		'ide-hd,drive=home,bus=ide.1', '-nic', 'none', '-display', 'none',
		'-monitor', 'none', '-serial', 'file:' + b.serial_log, '-serial',
		'unix:' + secret_path + ',server=on,wait=off', '-qmp',
		'unix:' + qmp_path + ',server=on,wait=off', '-no-reboot', '-S']
	b.process.set_args(args)
	// No QMP command log, debug log, credential argv or credential environment.
	b.process.set_redirect_stdio()
	b.process.set_stdin_path('/dev/null')
	b.process.run()
	b.active = true
	if b.process.pid <= 0 || !b.process.is_alive() { return error('QEMU failed to start') }
	b.qmp = open_qmp(qmp_path)!
	// Record the actual Linux process argv, not a shell-rendered approximation.
	// A live QMP handshake also proves exec completed before reading /proc.
	mut expected_argv := [qemu]
	expected_argv << args
	actual_argv := os.read_file('/proc/' + b.process.pid.str() + '/cmdline')!.trim_right('\x00').split('\x00')
	if actual_argv != expected_argv { return error('QEMU actual argv differs') }
	os.write_file(os.join_path(b.dir, 'qemu-argv.json'), json2.encode(actual_argv) + '\n')!
	b.serial = connect_bounded(secret_path, after(30))!
	blocks := b.qmp.request('query-block', {})!
	// Persist only this nonsecret response, never the QMP command stream.
	os.write_file(os.join_path(b.dir, 'query-block.json'), json2.encode(blocks) + '\n')!
	verify_blocks(blocks, boot_disk, disk, code, vars)!
	// Prevent loss of a one-shot UART frame before the host socket is connected.
	b.qmp.request('cont', {})!
}

fn (mut b Boot) cold_quit(boot_disk string, disk string, vars string) ! {
	b.qmp.deadline = after(10)
	// A successful complete write proves the quit request reached the socket.
	b.qmp.send('{"execute":"quit","id":"cold-quit"}\n')!
	end := after(30)
	for b.process.is_alive() && time.sys_mono_now() < end { time.sleep(50 * time.millisecond) }
	if b.process.is_alive() { return error('QEMU quit timeout') }
	b.process.wait()
	if b.process.code != 0 { return error('QEMU exit unsuccessful') }
	b.serial.close()
	b.qmp.close()
	b.process.close()
	b.active = false
	flush_disk(boot_disk)!
	flush_disk(disk)!
	flush_disk(vars)!
}

fn screen(mut b Boot, name string) ! {
	b.qmp.request('screendump', {
		'filename': json2.Any(os.join_path(b.dir, name + '.ppm'))
	})!
	status := b.qmp.request('query-status', {})!.as_map()
	if (status['status'] or { json2.Null{} }) != json2.Any('running') {
		return error('guest not running')
	}
	os.write_file(os.join_path(b.dir, name + '.status.txt'), 'PASS qemu-running\n')!
}

fn denial(mut b Boot, mut report Report, s &Secrets, kind int, label string) ! {
	// The masked input is ready. Generate wrong input directly into the key stream.
	key(mut b.qmp, 'esc')!
	if kind == 0 {
		mut ends := [12]int{}
		mut starts := [12]int{}
		mut count := 0
		for i in 0 .. s.phrase_len {
			if s.phrase[i] == ` ` {
				ends[count] = i
				count++
				starts[count] = i + 1
			}
		}
		ends[11] = s.phrase_len
		mut other := 1
		for other < 12 {
			mut equal := ends[0] == ends[other] - starts[other]
			if equal {
				for j in 0 .. ends[0] {
					if s.phrase[j] != s.phrase[starts[other] + j] {
						equal = false
						break
					}
				}
			}
			if !equal { break }
			other++
		}
		if other == 12 { return error('cannot reorder identical words') }
		for word in 0 .. 12 {
			index := if word == 0 {
				other
			} else if word == other {
				0
			} else {
				word
			}
			if word > 0 { type_byte(mut b.qmp, ` `)! }
			for j in starts[index] .. ends[index] { type_byte(mut b.qmp, s.phrase[j])! }
		}
	} else if kind == 1 {
		mut end := 0
		for end < s.phrase_len && s.phrase[end] != ` ` { end++ }
		same := end == 7 && unsafe { C.memcmp(&s.phrase[0], c'abandon', 7) == 0 }
		type_public(mut b.qmp, if same { 'zoo' } else { 'abandon' })!
		for i in end .. s.phrase_len { type_byte(mut b.qmp, s.phrase[i])! }
	} else if kind == 2 {
		for i in 0 .. 12 {
			if i > 0 { type_byte(mut b.qmp, ` `)! }
			type_public(mut b.qmp, 'zzzz')!
		}
	} else {
		for i in 0 .. 32 {
			type_byte(mut b.qmp, if i == 0 {
				if s.password[i] == `a` { u8(`b`) } else { u8(`a`) }
			} else {
				s.password[i]
			})!
		}
	}
	key(mut b.qmp, 'ret')!
	report.pass(label + '-submitted')!
	report.stage = label + '-await-denial-receipt'
	b.serial.expect(11, 180)!
	report.pass(label + '-denied-or-rate-limited-receipt')!
	screen(mut b, label + '-denied')!
	key(mut b.qmp, 'ret')!
	b.serial.expect(10, 30)!
	// Four failures reach at most 4s backoff. This is a denial matrix, not
	// the separate private-protocol test of shared-budget timing/replacement.
	settle(5)!
}

fn marker_probe(mut b Boot, mut report Report, create bool) !string {
	settle(30)!
	key(mut b.qmp, 'shift-tab')!
	key(mut b.qmp, 'ret')!
	report.pass('desktop-continue-submitted')!
	settle(10)!
	key(mut b.qmp, 'alt-f4')!
	settle(1)!
	key(mut b.qmp, 'alt-f4')!
	key(mut b.qmp, 'ctrl-p')!
	type_public(mut b.qmp, 'Terminal')!
	key(mut b.qmp, 'ret')!
	settle(5)!
	command := if create {
		"/usr/libexec/vinix-home-gate --protocol-probe > /dev/com1\n/usr/libexec/vinix-home-qualify --write '" + marker + "'\n"
	} else {
		"/usr/libexec/vinix-home-qualify --read '" + marker + "'\n"
	}
	// sysdisk's committed image ID has no trailing newline. Frame it explicitly
	// instead of assuming the archive marker's newline survives installation.
	type_public(mut b.qmp, command + 'echo M15-IMAGE-ID-BEGIN > /dev/com1\ncat /.vinix-image-id > /dev/com1\necho > /dev/com1\necho M15-IMAGE-ID-END > /dev/com1\n')!
	report.pass('marker-command-submitted')!
	report.stage = 'marker-await-serial-readback'
	end := after(45)
	for time.sys_mono_now() < end {
		// This UART must be nonsecret by bridge contract. Never print its contents.
		log := read_serial(b.serial_log)!
		mut found := 0
		mut identity := ''
		mut in_identity := false
		mut identity_complete := false
		for line in log.split_into_lines() {
			text := line.trim_space()
			if text == 'M15-IMAGE-ID-BEGIN' {
				in_identity = true
				continue
			}
			if text == 'M15-IMAGE-ID-END' {
				identity_complete = in_identity
				in_identity = false
				continue
			}
			if in_identity { identity += text }
			if text == marker {
				found++
			}
		}
		if found == 1 && log.contains('HOME-QUALIFY ' + (if create { 'WRITE' } else { 'READ' }) + ' PASS')
			&& identity_complete && valid_image_id(identity)
			&& log.contains('sysdisk: running from the system on /dev/sd0-1 (')
			&& (!create || log.contains('HOME-PROBE: private protocol, dual-slot equality, shared rate and UI replacement PASS')) {
			if !create && log.contains('HOME-QUALIFY WRITE PASS') {
				return error('cold boot unexpectedly rewrote marker')
			}
			report.pass('marker-serial-readback-' + os.file_name(b.dir))!
			report.pass('installed-sd0-1-image-id-' + identity)!
			screen(mut b, 'desktop-marker-verified')!
			settle(5)!
			return identity
		}
		check_cancelled()!
		time.sleep(100 * time.millisecond)
	}
	return error('marker serial readback unverified')
}

fn valid_image_id(identity string) bool {
	if identity.len != 16 { return false }
	for ch in identity {
		if !(ch >= `0` && ch <= `9`) && !(ch >= `a` && ch <= `f`) { return false }
	}
	return true
}

fn read_serial(path string) !string {
	// Bound diagnostic reads; COM1 is nonsecret by the fixture contract.
	if os.file_size(path) > 16 * 1024 * 1024 { return error('serial log exceeded bound') }
	return os.read_file(path)!
}

fn qualify(mut report Report, root string, boot_disk string, kernel string, disk string, qemu string) ! {
	report.stage = 'credential-memory-lock'
	mut secrets := &Secrets{}
	if C.mlock(secrets, sizeof(Secrets)) != 0 { return error('credential memory lock failed') }
	defer {
		erase(secrets, sizeof(Secrets))
		C.munlock(secrets, sizeof(Secrets))
	}
	report.stage = 'secure-controller-rng'
	mut entropy := unsafe { (&secrets.entropy[0]).vbytes(16) }
	rand.read(mut entropy)!
	for i in 0 .. 16 {
		secrets.password[i * 2] = '0123456789abcdef'[secrets.entropy[i] >> 4]
		secrets.password[i * 2 + 1] = '0123456789abcdef'[secrets.entropy[i] & 15]
	}
	erase(&secrets.entropy[0], 16)
	report.stage = 'input-boot-disk-sha256'
	boot_hash := checksum(boot_disk)!
	report.stage = 'input-kernel-sha256'
	kernel_hash := checksum(kernel)!
	os.write_file(os.join_path(root, 'inputs.sha256'), boot_hash + '  BOOT_DISK\n' + kernel_hash + '  KERNEL\n')!
	report.stage = 'private-firmware-copy'
	code := os.join_path(root, 'OVMF_CODE.4m.fd')
	vars := os.join_path(root, 'OVMF_VARS.4m.fd')
	// RUN_DIR was created exclusively; copy once, then preserve both files.
	os.cp(firmware, code)!
	os.cp(firmware_vars, vars)!
	os.chmod(code, 0o600)!
	os.chmod(vars, 0o600)!
	flush_disk(code)!
	flush_disk(vars)!
	report.pass('private-matching-firmware-pair-preserved-across-boots')!
	report.stage = 'new-disposable-disk'
	create_disk(disk)!
	report.pass('new-disposable-128mib-home-disk')!
	mut installed_identity := ''
	for n in 1 .. 4 {
		mut b := Boot{}
		defer { b.cleanup() }
		report.stage = 'boot-' + n.str() + '-launch'
		b.launch(root, n, boot_disk, disk, qemu)!
		report.pass('boot-' + n.str() + '-kvm-and-required-blocks-no-optical')!
		// This controller requires the masked-word fixture, so startup frames
		// remain secret-safe even if the guest reaches enrollment immediately.
		settle(3)!
		screen(mut b, 'boot-startup')!
		if n == 1 {
			report.stage = 'enrollment-phrase-frame'
			read_phrase(mut b.serial, mut secrets) or {
				screen(mut b, 'enrollment-frame-failure') or {}
				return err
			}
			report.pass('enrollment-frame-received-in-locked-memory')!
			// Mandatory masked-word fixture: never run against a production word UI.
			screen(mut b, 'masked-word-enrollment-fixture')!
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
			report.pass('enrollment-submitted')!
			report.stage = 'enrollment-mounted-receipt'
			b.serial.expect(12, 240)!
			// op12 is sent only after enrollment pixels have been cleared.
			settle(30)!
			report.pass('enrollment-mounted-receipt')!
			screen(mut b, 'post-enrollment-unlocked')!
			report.stage = 'marker-create-readback'
			installed_identity = marker_probe(mut b, mut report, true)!
		} else {
			report.stage = 'boot-' + n.str() + '-locked-receipt'
			b.serial.expect(10, 180)!
			report.pass('boot-' + n.str() + '-locked-ready-receipt')!
			screen(mut b, 'locked')!
			if n == 2 {
				report.stage = 'wrong-reordered-phrase'
				denial(mut b, mut report, secrets, 0, 'wrong-reordered-phrase')!
				report.stage = 'wrong-changed-phrase'
				denial(mut b, mut report, secrets, 1, 'wrong-changed-phrase')!
				report.stage = 'wrong-unknown-phrase'
				denial(mut b, mut report, secrets, 2, 'wrong-unknown-phrase')!
				key(mut b.qmp, 'tab')!
				b.serial.expect(10, 30)!
				report.stage = 'wrong-password'
				denial(mut b, mut report, secrets, 3, 'wrong-password')!
				// Return from password mode: every cold boot must use the phrase.
				key(mut b.qmp, 'tab')!
				b.serial.expect(10, 30)!
			}
			type_secret(mut b.qmp, &secrets.phrase[0], secrets.phrase_len)!
			key(mut b.qmp, 'ret')!
			report.pass('cold-phrase-submitted-boot' + n.str())!
			report.stage = 'cold-phrase-mounted-receipt-boot' + n.str()
			b.serial.expect(12, 240)!
			report.pass('cold-phrase-mounted-receipt-boot' + n.str())!
			screen(mut b, 'unlocked')!
			report.stage = 'cold-phrase-marker-readback-boot' + n.str()
			identity := marker_probe(mut b, mut report, false)!
			if identity != installed_identity { return error('installed image identity changed') }
			report.pass('unchanged-installed-image-identity-boot' + n.str())!
		}
		report.stage = 'boot-' + n.str() + '-cold-quit'
		b.cold_quit(boot_disk, disk, vars)!
		report.pass('boot-' + n.str() + '-qmp-quit-dead-both-disks-and-vars-fsynced')!
	}
}

fn run() ! {
	$if !linux {
		return error('Linux host required')
	}
	limit := C.rlimit{}
	if C.setrlimit(C.RLIMIT_CORE, &limit) != 0 { return error('core dumps could not be disabled') }
	$if linux {
		if C.prctl(C.PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 { return error('dump protection failed') }
	}
	C.umask(0o077)
	// Ignore SIGPIPE so socket failures take the normal defer cleanup path.
	os.signal_ignore(.pipe)
	$if linux {
		// Poll pending signals on normal control paths, so defers remain effective.
		blocked := C.sigset_t{}
		C.sigemptyset(&blocked)
		if C.sigaddset(&blocked, C.SIGINT) != 0 || C.sigaddset(&blocked, C.SIGTERM) != 0 || C.sigprocmask(C.SIG_BLOCK, &blocked, unsafe { nil }) != 0 {
			return error('signal setup failed')
		}
	}
	if os.args.len != 5 { return error('expected RUN_DIR BOOT_DISK KERNEL HOME_DISK') }
	for value in os.args[1..] {
		if !os.is_abs_path(value) || value.contains_any('\x00\n\r') {
			return error('absolute nonsecret paths required')
		}
	}
	root := os.join_path(os.real_path(os.dir(os.args[1])), os.file_name(os.args[1]))
	if root.contains(',') || os.file_name(root) in ['', '.', '..'] {
		return error('run directory rejected')
	}
	boot_disk := os.real_path(os.args[2])
	kernel := os.real_path(os.args[3])
	disk := if os.dir(os.args[4]) == os.args[1] {
		os.join_path(root, os.file_name(os.args[4]))
	} else {
		os.join_path(os.real_path(os.dir(os.args[4])), os.file_name(os.args[4]))
	}
	if !os.is_file(boot_disk) || !os.is_file(kernel) || !os.is_dir(os.dir(root)) || (os.dir(disk) != root && !os.is_dir(os.dir(disk))) {
		return error('input paths unavailable')
	}
	if os.file_name(disk) in ['', '.', '..'] || disk == boot_disk || disk == kernel || os.exists(disk) || os.is_link(disk) {
		return error('existing or invalid HOME disk rejected')
	}
	if !os.is_file(firmware) || !os.is_file(firmware_vars) || !os.exists('/dev/kvm') {
		return error('QEMU host requirements unavailable')
	}
	qemu := os.find_abs_path_of_executable('qemu-system-x86_64')!
	exclusive_dir(root)!
	mut report := Report{ file: os.create(os.join_path(root, 'status.txt'))!, started: time.sys_mono_now() }
	defer { report.file.close() }
	qualify(mut report, os.real_path(root), boot_disk, kernel, disk, qemu) or {
		// No err.msg(), stack trace, QMP data, UART data, or secret serialization.
		reason := match err.msg() {
			'socket timeout' { 'timeout' }
			'socket closed' { 'socket-closed' }
			'bridge operation rejected' { 'unexpected-op' }
			'bridge length rejected' { 'unexpected-length' }
			'guest entropy failed' { 'entropy-unavailable' }
			'phrase frame missing' { 'phrase-frame-missing' }
			'controller interrupted' { 'interrupted' }
			else { 'other' }
		}
		report.file.writeln('FAIL reason-' + reason) or {}
		report.file.writeln('FAIL elapsed-seconds-' + ((time.sys_mono_now() - report.started) / u64(time.second)).str()) or {}
		report.file.writeln('FAIL ' + report.stage) or {}
		report.file.flush()
		println('FAIL ' + report.stage)
		return error('qualification failed')
	}
	report.pass('qualification-complete')!
	elapsed := (time.sys_mono_now() - report.started) / u64(time.second)
	report.file.writeln('PASS elapsed-seconds-' + elapsed.str())!
}

fn main() {
	$if m15_selftest ? {
		protocol_selftest() or {
			eprintln('FAIL protocol-selftest')
			exit(1)
		}
		println('PASS protocol-selftest')
		return
	}
	run() or {
		eprintln('FAIL controller (see nonsecret status.txt if created)')
		exit(1)
	}
}

// Build-only transport probes. No guest, credentials, disks or external sockets.
$if m15_selftest ? {
	fn C.socketpair(int, int, int, &i32) int

	fn probe_pair() !(Wire, int) {
		mut handles := [2]i32{}
		if C.socketpair(C.AF_UNIX, C.SOCK_STREAM, 0, &handles[0]) != 0 {
			return error('pair failed')
		}
		socket := unix.stream_socket_from_handle(int(handles[0])) or {
			C.close(handles[0])
			C.close(handles[1])
			return error('pair wrapper failed')
		}
		C.fcntl(handles[0], C.F_SETFL, C.O_NONBLOCK)
		return Wire{ conn: &unix.StreamConn{ sock: *socket }, deadline: after(3) }, int(handles[1])
	}
	fn probe_fragment_writer(fd int, frame []u8) bool {
		defer { C.close(fd) }
		magic := 'M14A-HM1'
		for ch in magic {
			byte := ch
			if C.send(fd, &byte, 1, 0) != 1 { return false }
		}
		for ch in frame {
			byte := ch
			if C.send(fd, &byte, 1, 0) != 1 { return false }
			time.sleep(2 * time.millisecond)
		}
		return true
	}
	fn probe_frame(frame []u8, expected u32, reject bool) ! {
		mut w, fd := probe_pair()!
		defer { w.close() }
		sender := spawn probe_fragment_writer(fd, frame)
		mut failed := false
		w.expect(expected, 3) or { failed = true }
		sent := sender.wait()
		if !sent || failed != reject { return error('frame probe failed') }
	}
	fn probe_drain(fd int, expected int) bool {
		defer { C.close(fd) }
		mut buffer := [137]u8{}
		mut total := 0
		for total < expected {
			count := C.recv(fd, &buffer[0], 137, 0)
			if count <= 0 { return false }
			for i in 0 .. int(count) { if buffer[i] != `x` { return false } }
			total += int(count)
		}
		return total == expected
	}
	fn protocol_selftest() ! {
		os.signal_ignore(.pipe)
		// Qualification topology must reject missing disks and optical devices.
		good_blocks := '[{"removable":false,"inserted":{"file":"/boot","drv":"raw","ro":false}},{"removable":false,"inserted":{"file":"/home","drv":"raw","ro":false}}]'
		verify_blocks(json2.decode[json2.Any](good_blocks)!, '/boot', '/home', '/code', '/vars')!
		for invalid in [good_blocks.replace('"/home"', '"/unapproved.iso"'),
			good_blocks.replace('"removable":false', '"removable":true'),
			good_blocks.replace('"ro":false', '"ro":true'),
			good_blocks.replace('"drv":"raw"', '"drv":"qcow2"')] {
			mut rejected := false
			verify_blocks(json2.decode[json2.Any](invalid)!, '/boot', '/home', '/code', '/vars') or { rejected = true }
			if !rejected { return error('topology rejection probe failed') }
		}
		if !valid_image_id('0123456789abcdef') || valid_image_id('pending') || valid_image_id('0123456789abcdeF') {
			return error('image identity probe failed')
		}
		probe_frame([u8(10), 0, 0, 0, 0, 0, 0, 0], 10, false)!
		probe_frame([u8(11), 0, 0, 0, 0, 0, 0, 0], 11, false)!
		probe_frame([u8(12), 0, 0, 0, 0, 0, 0, 0], 12, false)!
		probe_frame([u8(13), 0, 0, 0, 0, 0, 0, 0], 10, true)!
		probe_frame([u8(2), 0, 0, 0, 129, 0, 0, 0], 10, true)!
		probe_frame([u8(10), 0, 0, 0, 1, 0, 0, 0], 10, true)!
		probe_frame([u8(2), 0, 0, 0, 32, 0, 0, 0], 10, true)!
		probe_frame([u8(99), 0, 0, 0, 0, 0, 0, 0], 10, true)!
		probe_frame([u8(10), 0, 0], 10, true)!
		// Synthetic alphabet-only payload, never a guest credential or image fixture.
		mut frame := [u8(2), 0, 0, 0, 23, 0, 0, 0]
		for i in 0 .. 12 {
			if i > 0 { frame << u8(` `) }
			frame << u8(`a` + i)
		}
		mut phrase_wire, phrase_peer := probe_pair()!
		defer { phrase_wire.close() }
		phrase_sender := spawn probe_fragment_writer(phrase_peer, frame)
		mut synthetic := Secrets{}
		defer { erase(&synthetic, sizeof(Secrets)) }
		mut phrase_failed := false
		read_phrase(mut phrase_wire, mut synthetic) or { phrase_failed = true }
		phrase_sent := phrase_sender.wait()
		if phrase_failed || !phrase_sent || synthetic.phrase_len != 23 || synthetic.phrase[0] != `a` || synthetic.phrase[22] != `l` {
			return error('phrase buffer probe failed')
		}
		mut timeout_wire, timeout_peer := probe_pair()!
		defer {
			timeout_wire.close()
			C.close(timeout_peer)
		}
		timeout_wire.deadline = time.sys_mono_now() + u64(80 * time.millisecond)
		mut byte := u8(0)
		mut timed_out := false
		timeout_wire.exact(&byte, 1) or { timed_out = true }
		if !timed_out { return error('deadline probe failed') }
		mut writer, reader_fd := probe_pair()!
		defer { writer.close() }
		buffer_size := i32(1024)
		if C.setsockopt(writer.conn.sock.handle, C.SOL_SOCKET, C.SO_SNDBUF, &buffer_size, sizeof(i32)) != 0 {
			C.close(reader_fd)
			return error('send buffer probe failed')
		}
		payload := 'x'.repeat(512 * 1024)
		reader := spawn probe_drain(reader_fd, payload.len)
		mut send_failed := false
		writer.send(payload) or { send_failed = true }
		writer.close()
		drained := reader.wait()
		if send_failed || !drained { return error('short write probe failed') }
		mut fixed := [16]u8{}
		mut alias := unsafe { (&fixed[0]).vbytes(16) }
		alias[0] = 42
		if fixed[0] != 42 { return error('fixed buffer alias probe failed') }
		rand.read(mut alias)!
		erase(&fixed[0], 16)
		for ch in fixed { if ch != 0 { return error('wipe probe failed') } }
	}
}
