// Offline whole-image marker scan with a mandatory plaintext positive control.
module main

import os

const marker = 'M15_ENCRYPTED_HOME_PLAINTEXT_PROBE_20261021_unique_c4f9e21d'

fn scan(path string) !int {
	result := os.exec(['grep', '-aFob', '--', marker, path])
	if result.exit_code !in [0, 1] { return error('scanner I/O or execution error') }
	mut count := 0
	for line in result.output.split_into_lines() {
		if line == '' { continue }
		colon := line.index(':') or { return error('scanner offset missing') }
		if colon == 0 || line[colon + 1..] != marker { return error('scanner output malformed') }
		for ch in line[..colon] { if ch < `0` || ch > `9` { return error('scanner offset invalid') } }
		count++
	}
	if (count > 0) != (result.exit_code == 0) { return error('scanner exit/output mismatch') }
	println('SCAN path=' + path + ' exit=' + result.exit_code.str() + ' matches=' + count.str())
	return count
}

fn run() ! {
	if os.args.len != 4 { return error('usage: offline_scan RUN_DIR BOOT_DISK HOME_DISK') }
	status := os.read_file(os.args[1] + '/status.txt')!
	for boot in 1 .. 4 {
		for receipt in ['PASS marker-serial-readback-boot' + boot.str(),
			'PASS boot-' + boot.str() + '-qmp-quit-dead-both-disks-and-vars-fsynced'] {
			if receipt !in status.split_into_lines() { return error('missing exact prerequisite: ' + receipt) }
		}
	}
	if 'PASS qualification-complete' !in status.split_into_lines() { return error('qualification incomplete') }
	control := os.args[1] + '/m15-positive-control.bin'
	if os.exists(control) || os.is_link(control) { return error('control must be new') }
	os.write_file(control, '\x00'.repeat(65536) + marker + '\n' + '\x00'.repeat(65536))!
	if scan(control)! != 1 { return error('plaintext positive control not found exactly once') }
	mut covered := u64(0)
	for path in os.args[2..] {
		if !os.is_file(path) || os.is_link(path) { return error('regular raw image required') }
		info := os.stat(path)!
		open := os.exec(['fuser', '--', path])
		if open.exit_code != 1 { return error('image open or offline check failed') }
		if scan(path)! != 0 { return error('plaintext marker found in disk') }
		println('LOGICAL_BYTES_COVERED path=' + path + ' bytes=' + info.size.str())
		covered += info.size
		digest := os.exec(['sha256sum', '--', path])
		if digest.exit_code != 0 { return error('whole-image hash failed') }
		print(digest.output)
	}
	println('TOTAL_LOGICAL_BYTES_COVERED:' + covered.str())
	println('PASS offline positive control found; zero plaintext marker matches in both whole raw disks')
}

fn main() {
	run() or { eprintln('FAIL ' + err.msg()); exit(1) }
}
