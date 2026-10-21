// Disposable fecv3 source-root provisioning. Diagnostic ISO only; no HOME attached.
module main

import os
import time
import net.unix
import json2

#include <fcntl.h>
#include <unistd.h>
fn C.ftruncate(int, u64) int
fn C.fsync(int) int

fn qmp(path string, command string) !string {
	mut c := unix.connect_stream(path)!
	defer { c.close() or {} }
	c.set_read_timeout(5 * time.second)
	c.set_write_timeout(5 * time.second)
	c.write_string('{"execute":"qmp_capabilities","id":"cap"}\n' + command + '\n')!
	mut pending := ''
	mut output := ''
	deadline := time.sys_mono_now() + u64(10 * time.second)
	for time.sys_mono_now() < deadline && output.len < 1024 * 1024 {
		mut data := []u8{len: 65536}
		n := c.read(mut data)!
		if n == 0 { break }
		pending += data[..n].bytestr()
		for pending.contains('\n') {
			at := pending.index('\n') or { return error('QMP frame missing newline') }
			line := pending[..at]
			pending = pending[at + 1..]
			output += line + '\n'
			m := json2.decode[map[string]json2.Any](line) or { continue }
			if (m['id'] or { json2.Null{} }).str() == 'action' {
				if 'error' in m { return error('QMP returned error') }
				return output
			}
		}
	}
	return error('QMP response deadline or size bound')
}

fn run() ! {
	$if !linux { return error('Linux host required') }
	if os.args.len !in [3, 4] || (os.args.len == 4 && os.args[3] != '--resume') {
		return error('usage: source_provision EXISTING_RUN_DIR DIAGNOSTIC_ISO [--resume]')
	}
	r := os.real_path(os.args[1])
	iso := os.real_path(os.args[2])
	if !os.is_dir(r) || !os.is_file(iso) || r.contains_any(',\n\r') || iso.contains_any(',\n\r') {
		return error('input paths unavailable or unsafe')
	}
	root := r + '/m15-source-root.raw'
	vars := r + '/m15-source-vars.fd'
	// A new UART path per process prevents an old successful log from admitting
	// this attempt before QEMU opens and truncates its serial backend.
	serial := r + '/m15-source-' + os.getpid().str() + '.serial.log'
	if os.exists(serial) || os.is_link(serial) { return error('attempt serial log must be new') }
	os.write_file(r + '/m15-source-active-serial.txt', serial + '\n')!
	socket := r + '/m15-source.qmp'
	resume := os.args.len == 4
	if resume {
		if !os.is_file(root) || os.is_link(root) || os.file_size(root) != u64(4294967296)
			|| !os.is_file(vars) || os.is_link(vars) { return error('resume source unavailable') }
		if os.exec(['fuser', '--', root]).exit_code != 1 { return error('source open or offline check failed') }

	} else {
		if os.exists(vars) || os.is_link(vars) { return error('VARS must be new') }
		fd := C.open(&char(root.str), C.O_RDWR | C.O_CREAT | C.O_EXCL | C.O_NOFOLLOW | C.O_CLOEXEC, 0o600)
		if fd < 0 { return error('source must be a new regular file') }
		created := C.ftruncate(fd, u64(4294967296)) == 0 && C.fsync(fd) == 0
		closed := C.close(fd) == 0
		if !created || !closed { return error('source creation failed') }
		os.cp('/usr/share/edk2/x64/OVMF_VARS.4m.fd', vars)!
		os.chmod(vars, 0o600)!
	}
	if os.exists(socket) { os.rm(socket)! }
	mut p := os.new_process('/usr/bin/qemu-system-x86_64')
	args := ['-name', 'vinix-m15-source', '-machine', 'q35,smm=off', '-enable-kvm', '-cpu', 'host',
		'-smp', '4', '-m', '4096', '-vga', 'std', '-drive',
		'if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.4m.fd', '-drive',
		'if=pflash,format=raw,unit=1,file=' + vars, '-drive',
		'if=none,id=cd,media=cdrom,format=raw,readonly=on,file=' + iso, '-device', 'ide-cd,drive=cd,bus=ide.2',
		'-drive', 'if=none,id=root,format=raw,file=' + root, '-device', 'ide-hd,drive=root,bus=ide.0',
		'-boot', 'order=d', '-nic', 'none', '-display', 'none', '-monitor', 'none', '-serial', 'file:' + serial,
		'-qmp', 'unix:' + socket + ',server=on,wait=off', '-no-reboot']
	os.write_file(r + '/m15-source-qemu-argv.json', json2.encode(args) + '\n')!
	p.set_args(args)
	p.set_redirect_stdio()
	p.set_stdin_path('/dev/null')
	p.run()
	defer { if p.is_alive() { p.signal_kill(); p.wait() }; p.close() }
	end := time.sys_mono_now() + u64(600 * time.second)
	mut progressed := time.sys_mono_now()
	mut previous_size := u64(0)
	mut previous_mtime := i64(0)
	mut ready := false
	for p.is_alive() && time.sys_mono_now() < end {
		log := os.read_file(serial) or { '' }
		booted := log.contains('sysdisk: running from the system on /dev/sd0 (4 GiB)')
		installed := log.contains('sysdisk: installed; later boots start from the disk')
		recovered := log.contains('sysdisk: updating the system on /dev/sd0 (4 GiB)') && log.contains('initramfs: Done (')
		// The auth init intentionally removed the old plaintext desktop banner.
		// This real supervisor receipt occurs after the kernel commits the root.
		if (booted || installed || recovered) && log.contains('HOME-UI: budget failures=0') { ready = true; break }
		size := os.file_size(serial)
		mtime := os.file_last_mod_unix(root)
		if size != previous_size || mtime != previous_mtime {
			progressed = time.sys_mono_now(); previous_size = size; previous_mtime = mtime
		}
		if time.sys_mono_now() - progressed > u64(120 * time.second) { return error('source stalled for 120 seconds') }
		time.sleep(time.second)
	}
	if !ready { return error('source completion receipt absent') }
	println('PASS committed source root reached the real auth supervisor; HOME intentionally absent')
	os.write_file(r + '/m15-source-screen.qmp.json', qmp(socket, '{"execute":"screendump","arguments":{"filename":"' + r + '/m15-source-installed.ppm"},"id":"action"}')!)!
	os.write_file(r + '/m15-source-blocks.json', qmp(socket, '{"execute":"query-block","id":"action"}')!)!
	os.write_file(r + '/m15-source-quit.json', qmp(socket, '{"execute":"quit","id":"action"}')!)!
	stop := time.sys_mono_now() + u64(15 * time.second)
	for p.is_alive() && time.sys_mono_now() < stop { time.sleep(100 * time.millisecond) }
	if p.is_alive() { return error('source QEMU did not stop') }
	p.wait()
	if p.code != 0 { return error('source QEMU nonzero') }
	os.cp(serial, r + '/m15-source.serial.log')!
	synced := os.exec(['sync', '-f', root])
	if synced.exit_code != 0 { return error('source host fsync failed') }
	digest := os.exec(['sha256sum', '--', root])
	if digest.exit_code != 0 { return error('source checksum failed') }
	os.write_file(r + '/m15-source-offline.log', digest.output)!
	print(digest.output)
}

fn main() {
	run() or { eprintln('FAIL ' + err.msg()); exit(1) }
}
