// SPDX-License-Identifier: GPL-2.0-or-later
// Run on fecv3 in an ordinary shell. Keeps the parent's ISO/disks untouched.
module main

import os
import crypto.sha256

fn digest(path string) !string { return sha256.sum(os.read_bytes(path)!).hex() }

fn step(args []string, log string, seconds int) !string {
	command := ['timeout', '-k', '30', seconds.str(), ...args].map(os.quoted_path(it)).join(' ')
	os.write_file(log + '.command', command + '\n')!
	r := os.execute(command + ' > ' + os.quoted_path(log) + ' 2>&1')
	os.write_file(log + '.exit', '${r.exit_code}\n')!
	println('${os.file_name(log)} EXIT=${r.exit_code}')
	if r.exit_code != 0 { return error('see ' + log) }
	return os.read_file(log)!
}

fn package(root string, fresh string) ! {
	if os.exists(fresh) { return error('package destination must be fresh') }
	os.mkdir_all(fresh)!
	base := '/home/agent/build/vinix-m17c-b2/build/m17c-r2/root'
	compiler := '/home/agent/code/v/v'
	// Copy the frozen production userspace and change only its SSH daemon.
	step(['cp', '-a', '--reflink=auto', base, fresh + '/root'], fresh + '/copy-root.log', 180)!
	step([compiler, '-gc', 'none', '-d', 'no_segfault_handler', '-d', 'no_backtrace',
		'-o', fresh + '/builder.c', root + '/tools/sshserver-build.v'], fresh + '/builder-generate.log', 180)!
	step(['clang', '-O2', '-D_GNU_SOURCE', '-w', '-pthread', fresh + '/builder.c', '-lm', '-o', fresh + '/builder'], fresh + '/builder-link.log', 180)!
	os.setenv('V', compiler, true)
	step([fresh + '/builder', '--arch=amd64', '--sysroot=/home/agent/build/vinix-m15/build-amd64-userland/staging',
		'--output=' + fresh + '/sshd', '--staging=' + fresh + '/root'], fresh + '/sshd-build.log', 300)!
	os.rm(fresh + '/root/.vinix-image-id') or {}
	step(['tar', '--format=ustar', '--owner=0', '--group=0', '-cf', fresh + '/initramfs.tar', '-C', fresh + '/root', '.'], fresh + '/archive.log', 180)!
	os.setenv('VINIX_AMD64_KERNEL', root + '/kernel/bin/vinix', true)
	os.setenv('VINIX_AMD64_INITRAMFS', fresh + '/initramfs.tar', true)
	os.setenv('VINIX_AMD64_ISO', fresh + '/production.iso', true)
	os.setenv('VINIX_AMD64_ISO_BUILD_DIR', fresh + '/iso-build', true)
	step(['bash', root + '/build-support/build-amd64-iso.sh'], fresh + '/iso.log', 600)!
	step(['xorriso', '-osirrox', 'on', '-indev', fresh + '/production.iso', '-extract', '/boot/vinix', fresh + '/extracted-kernel',
		'-extract', '/boot/initramfs.tar.gz', fresh + '/extracted-initramfs.tar.gz'], fresh + '/extract.log', 180)!
	if digest(fresh + '/extracted-kernel')! != digest(root + '/kernel/bin/vinix')! { return error('ISO kernel differs from receipt ELF') }
	// Inspect bytes from the finished ISO, not the pre-packaging staging tree.
	os.mkdir(fresh + '/extracted')!
	step(['tar', '-xzf', fresh + '/extracted-initramfs.tar.gz', '-C', fresh + '/extracted',
		'./usr/libexec/vinix-sshd', './.vinix-image-id'], fresh + '/extract-userspace.log', 180)!
	if digest(fresh + '/extracted/usr/libexec/vinix-sshd')! != digest(fresh + '/sshd/vinix-sshd')! { return error('ISO sshd differs') }
	id := digest(fresh + '/initramfs.tar')![..16]
	if os.read_file(fresh + '/extracted/.vinix-image-id')!.trim_space() != id { return error('ISO image ID differs') }
	lines := ['iso_sha256=' + digest(fresh + '/production.iso')!, 'image_id=' + id,
		'kernel_sha256=' + digest(fresh + '/extracted-kernel')!, 'sshd_sha256=' + digest(fresh + '/extracted/usr/libexec/vinix-sshd')!,
		'gate_sha256=' + digest(fresh + '/root/usr/libexec/vinix-home-gate')!,
		'base_gate_sha256=' + digest(base + '/usr/libexec/vinix-home-gate')!]
	if lines[4].all_after('=') != lines[5].all_after('=') { return error('production gate changed') }
	os.write_file(fresh + '/image.receipt', lines.join('\n') + '\n')!
	println(lines.join('\n'))
}

fn qualify(parent string, fresh string, smoke_only bool) ! {
	// The parent env contains nonsecret paths and dedicated container IDs.
	// Do not print it or copy private keys, phrases, or private captures.
	for line in os.read_lines(parent + '/env.sh')! {
		if !line.starts_with('export ') || !line.contains('=') { continue }
		name := line.all_after('export ').all_before('=')
		value := line.all_after('=').replace('$PATH', os.getenv('PATH'))
		os.setenv(name, value, true)
	}
	mut receipt := map[string]string{}
	for line in os.read_lines(fresh + '/image.receipt')! { receipt[line.all_before('=')] = line.all_after('=') }
	if digest(fresh + '/production.iso')! != receipt['iso_sha256'] { return error('production ISO changed') }
	if !smoke_only && (os.exists(fresh + '/m17c-provision') || os.exists(fresh + '/m17c-smoke')) { return error('qualification already attempted; retain evidence') }
	os.setenv('M17C_ISO', fresh + '/production.iso', true)
	os.setenv('M17C_ISO_SHA256', receipt['iso_sha256'], true)
	os.setenv('M17C_IMAGE_ID', receipt['image_id'], true)
	os.mkdir_all(fresh + '/tmp')!
	os.setenv('TMPDIR', fresh + '/tmp', true)
	controller := parent + '/bin/controller'
	disk := fresh + '/system.raw'
	if !smoke_only {
	step([controller, 'provision', fresh + '/m17c-provision', fresh + '/production.iso'], fresh + '/provision.log', 1200)!
	tool := '/home/agent/build/m15-receipts/m15-selfboot'
	source := fresh + '/m17c-provision/m17c-source-root.raw'
	if os.file_size(source) != u64(4294967296) { return error('source root size differs') }
	if os.exec(['fuser', '--', source]).exit_code != 1 { return error('source root is not offline') }
	bundle := fresh + '/bundle'
	step([tool, 'bundle', '--iso', fresh + '/production.iso', '--iso-sha256', receipt['iso_sha256'], '--output', bundle], fresh + '/bundle.log', 300)!
	step([tool, 'plan', '--source', source], fresh + '/source-plan.log', 300)!
	if os.exists(disk) { return error('target already exists') }
	step(['truncate', '-s', '5370806272', '--', disk], fresh + '/blank.log', 10)!
	text := step([tool, 'inspect', '--target', disk, '--source', source], fresh + '/inspect.log', 60)!
	mut identity := map[string]string{}
	for line in text.split_into_lines() { if line.contains('=') { identity[line.all_before('=')] = line.all_after('=') } }
	for key in ['dev', 'inode', 'bytes'] { if identity[key] == '' { return error('target identity absent') } }
	step(['sudo', '-n', tool, 'install', '--target', disk, '--expect-dev', identity['dev'], '--expect-inode', identity['inode'],
		'--expect-bytes', identity['bytes'], '--source', source, '--source-image-id', receipt['image_id'], '--bundle', bundle,
		'--bundle-sha256', digest(bundle + '/manifest.json')!], fresh + '/install.log', 600)!
	step(['sudo', '-n', 'chown', '${os.getuid()}:${os.getgid()}', disk], fresh + '/disk-owner.log', 10)!
	step(['sgdisk', '-v', disk], fresh + '/gpt.log', 30)!
	}
	if !os.is_file(disk) { return error('installed test GPT disk absent') }
	// A fixture outage may precede SSH. Retain the failed run and use a new
	// HOME and run directory with the same verified installed production disk.
	run_dir := fresh + if smoke_only { '/m17c-smoke-retry-' + os.getpid().str() } else { '/m17c-smoke' }
	// The unchanged worker includes the exact `ssh -tt ... echo M17C-PTY` gate.
	step([controller, 'smoke', run_dir, disk], fresh + '/' + os.file_name(run_dir) + '.log', 5400)!
	if os.read_file(run_dir + '/acceptance.receipt')! != 'PASS\n' { return error('combined acceptance absent') }
	os.write_file(fresh + '/guest-proof.receipt', 'PASS literal production ISO qualification\nrun_dir=' + run_dir + '\n')!
}

fn main() {
	if os.args.len != 5 { eprintln('Usage: guest-proof.v package|run|smoke ROOT PARENT-QUAL-DIR FRESH-PACKAGE-DIR'); exit(2) }
	os.setenv('PATH', '/home/agent/toolshim:/usr/bin:/bin:/usr/local/bin', true)
	if os.args[1] == 'package' {
		package(os.real_path(os.args[2]), os.args[4]) or { eprintln(err.msg()); exit(1) }
	} else if os.args[1] in ['run', 'smoke'] {
		exit_path := os.args[4] + if os.args[1] == 'run' { '/qualification.exit' } else { '/smoke-retry-' + os.getpid().str() + '.exit' }
		qualify(os.real_path(os.args[3]), os.args[4], os.args[1] == 'smoke') or {
			os.write_file(exit_path, '1\n') or {}
			eprintln(err.msg()); exit(1)
		}
		os.write_file(exit_path, '0\n') or { eprintln(err.msg()); exit(1) }
	} else { eprintln('unknown mode'); exit(2) }
}
