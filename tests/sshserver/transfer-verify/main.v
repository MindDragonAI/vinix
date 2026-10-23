// SPDX-License-Identifier: GPL-2.0-or-later
// Run inside a private fecv3 source/build root; never publishes artifacts.
module main

import os
import crypto.sha256

const compiler = '/home/agent/code/v/v'

fn step(root string, name string, args []string, seconds int) ! {
	command := ['timeout', '-k', '10', seconds.str(), ...args].map(os.quoted_path(it)).join(' ')
	os.write_file(root + '/' + name + '.command', command + '\n')!
	mut p := os.new_process('/bin/sh')
	p.set_args(['-c', command + ' >' + os.quoted_path(root + '/' + name + '.log') + ' 2>&1'])
	p.run(); p.wait()
	code := p.code
	p.close()
	os.write_file(root + '/' + name + '.exit', '${code}\n')!
	println('${name} EXIT=${code}')
	if code != 0 { return error('see ' + name + '.log') }
}

fn digest(path string) !string { return sha256.sum(os.read_bytes(path)!).hex() }

fn receipt(root string, dir string, arch string) ! {
	generated := os.read_file(dir + '/obj/blob.c')!
	if !generated.contains('aesxts__erase_lanes') || !generated.contains('fs__LogicalVolume__encrypted_io') { return error('stale kernel C') }
	os.write_file(root + '/build-' + arch + '.receipt', 'architecture=' + arch + '\ncompiler_sha256=' + digest(compiler)!
		+ '\nsource_sha256=' + digest(dir + '/aesxts/core.v')! + '\nstorage_source_sha256=' + digest(dir + '/fs/storage_crypt.v')!
		+ '\nkernel_sha256=' + digest(dir + '/bin/vinix')! + '\n')!
}

fn run() ! {
	if os.args.len != 3 { return error('usage: transfer-verify PRIVATE-ROOT build|build-aarch64|verify-builds|host|xts|observer') }
	root := os.real_path(os.args[1])
	os.chdir(root)!
	os.setenv('PATH', '/home/agent/toolshim:/usr/bin:/bin:/usr/local/bin', true)
	if os.args[2] in ['build', 'build-aarch64'] {
		architectures := if os.args[2] == 'build-aarch64' { ['aarch64'] } else { ['x86_64', 'aarch64'] }
		for arch in architectures {
			dir := root + if arch == 'x86_64' { '/kernel' } else { '/kernel-aarch64' }
			if arch == 'aarch64' {
				for file in ['aesxts/core.v', 'fs/storage_crypt.v'] { os.cp(root + '/kernel/' + file, dir + '/' + file)! }
			}
			step(root, 'touch-' + arch, ['touch', dir + '/aesxts/core.v', dir + '/fs/storage_crypt.v'], 5)!
			for name in ['obj/blob.c', 'obj/blob.c.o', 'obj/blob.c.d'] { os.rm(dir + '/' + name) or {} }
			os.rmdir_all(dir + '/obj/vsrc') or {}
			if arch == 'x86_64' {
				project := root + '/sampler'
				os.mkdir_all(project)!
				os.cp_all(dir + '/heapbench', project + '/heapbench', true)!
				os.write_file(project + '/v.mod', "Module { name: 'kernel_sampler' }\n")!
				os.write_file(project + '/entry.v', 'module main\nimport heapbench as _\n')!
				step(root, 'sampler', [compiler, '-shared', '-no-builtin', '-no-closures', '-os', 'vinix', '-arch', 'amd64',
					'-target-libc-headers', '-nofloat', '-gc', 'none', '-manualfree', '-o', dir + '/obj/heap_benchmark.c', project], 180)!
			}
			step(root, 'build-' + arch, ['make', '-C', dir, '-j4', 'ARCH=' + arch, 'PROD=true', 'V=' + compiler,
				'CC=clang', 'AR=llvm-ar', 'LD_X86_64=/usr/bin/ld.lld', 'LD_AARCH64=/usr/bin/ld.lld', 'LD_LLD=/usr/bin/ld.lld'], 1800)!
			receipt(root, dir, arch)!
		}
	} else if os.args[2] == 'receipt-x86_64' {
		receipt(root, root + '/kernel', 'x86_64')!
	} else if os.args[2] == 'verify-builds' {
		for arch in ['x86_64', 'aarch64'] {
			dir := root + if arch == 'x86_64' { '/kernel' } else { '/kernel-aarch64' }
			if os.read_file(root + '/build-' + arch + '.exit')!.trim_space() != '0' { return error('make did not exit zero') }
			for file in ['aesxts/core.v', 'fs/storage_crypt.v'] {
				if digest(dir + '/' + file)! != digest(root + '/kernel/' + file)! { return error('architecture source differs') }
				if os.file_last_mod_unix(dir + '/obj/blob.c') < os.file_last_mod_unix(dir + '/' + file) { return error('generated C predates source') }
			}
			if os.file_last_mod_unix(dir + '/obj/blob.c.o') < os.file_last_mod_unix(dir + '/obj/blob.c')
				|| os.file_last_mod_unix(dir + '/bin/vinix') < os.file_last_mod_unix(dir + '/obj/blob.c.o') { return error('stale object or ELF') }
			receipt(root, dir, arch)!
			println('BUILD-VERIFIED ${arch} make_exit=0 sources=current C/object/ELF=fresh')
		}
	} else if os.args[2] == 'host' {
		step(root, 'host-generate', [compiler, '-prod', '-gc', 'none', '-d', 'no_backtrace', '-d', 'no_segfault_handler',
			'-d', 'ssh_session_workers', '-path', root + '|@vlib|@vmodules', '-o', root + '/sshd.c', root + '/tools/sshserver'], 180)!
		step(root, 'host-link', ['clang', '-O2', '-D_GNU_SOURCE', '-w', root + '/sshd.c', '-pthread', '-lm', '-o', root + '/sshd'], 180)!
		step(root, 'transfer-generate', [compiler, '-gc', 'none', '-d', 'no_backtrace', '-d', 'no_segfault_handler',
			'-o', root + '/transfer.c', root + '/tests/sshserver/transfer'], 180)!
		step(root, 'transfer-link', ['clang', '-O2', '-D_GNU_SOURCE', '-w', root + '/transfer.c', '-pthread', '-lm', '-o', root + '/transfer'], 180)!
		step(root, 'host-after', [root + '/transfer', root + '/sshd', root + '/host-after'], 2100)!
	} else if os.args[2] == 'xts' {
		step(root, 'xts-generate', [compiler, '-prod', '-gc', 'none', '-d', 'no_backtrace', '-d', 'no_segfault_handler',
			'-path', '@vlib|@vmodules|' + root + '/kernel', '-o', root + '/xts-after.c', root + '/tests/sshserver/xts-throughput'], 180)!
		step(root, 'xts-link', ['clang', '-O2', '-D_GNU_SOURCE', '-w', root + '/xts-after.c', '-pthread', '-lm', '-o', root + '/xts-after'], 180)!
		step(root, 'xts-after', [root + '/xts-after'], 120)!
	} else if os.args[2] == 'observer' {
		parent := '/home/agent/build/m17c-qual-r3-parent'
		fresh := root + '/proof-parent'
		if os.exists(fresh) { return error('observer parent must be fresh') }
		mut lines := os.read_lines(parent + '/env.sh')!
		mut original := ''
		for i, line in lines {
			if line.starts_with('export M17C_ACCEPTANCE=') {
				original = line.all_after('=')
				lines[i] = 'export M17C_ACCEPTANCE=' + root + '/guest-observer'
			}
		}
		if !os.is_abs_path(original) || !os.is_file(original) { return error('original acceptance absent') }
		lines << 'export M17C_ORIGINAL_ACCEPTANCE=' + original
		os.mkdir_all(fresh + '/bin')!
		os.write_file(fresh + '/env.sh', lines.join('\n') + '\n')!
		os.symlink(parent + '/bin/controller', fresh + '/bin/controller')!
		os.write_file(root + '/original-acceptance.receipt', 'path=' + original + '\nsha256=' + digest(original)! + '\n')!
		step(root, 'observer-generate', [compiler, '-gc', 'none', '-d', 'no_backtrace', '-d', 'no_segfault_handler',
			'-o', root + '/guest-observer.c', root + '/tests/sshserver/transfer-guest'], 180)!
		step(root, 'observer-link', ['clang', '-O2', '-D_GNU_SOURCE', '-w', root + '/guest-observer.c', '-pthread', '-lm', '-o', root + '/guest-observer'], 180)!
	} else { return error('unknown mode') }
}

fn main() { run() or { eprintln(err.msg()); exit(1) } }
