// SPDX-License-Identifier: GPL-2.0-or-later
// Receipt-producing fecv3 build lane; deliberately does not publish anything.
module main

import os
import crypto.sha256

const compiler = '/home/agent/code/v/v'

fn run(args []string, log string, seconds int) ! {
	command := ['timeout', '-k', '10', seconds.str(), ...args].map(os.quoted_path(it)).join(' ')
	os.write_file(log + '.command', command + '\n')!
	result := os.execute(command + ' > ' + os.quoted_path(log) + ' 2>&1')
	os.write_file(log + '.exit', '${result.exit_code}\n')!
	println('${os.file_name(log)} EXIT=${result.exit_code}')
	if result.exit_code != 0 { return error('see ' + log) }
}

fn hash(path string) !string { return sha256.sum(os.read_bytes(path)!).hex() }

fn main() {
	if os.args.len != 3 { eprintln('Usage: verify.v REMOTE-ROOT build|host'); exit(2) }
	root := os.real_path(os.args[1])
	os.setenv('PATH', '/home/agent/toolshim:/usr/bin:/bin:/usr/local/bin', true)
	os.setenv('V', compiler, true)
	if os.args[2] in ['build', 'build-aarch64'] {
		architectures := if os.args[2] == 'build-aarch64' { ['aarch64'] } else { ['x86_64', 'aarch64'] }
		for arch in architectures {
			dir := root + if arch == 'x86_64' { '/kernel' } else { '/kernel-aarch64' }
			if arch == 'aarch64' {
				// The native runtime/dependencies were copied from the matching
				// already-built architecture, never from the x86 runtime.
				for file in os.read_lines(root + '/kernel-files.txt')! {
					if file == '' { continue }
					os.mkdir_all(os.dir(root + '/kernel-aarch64/' + file.all_after('kernel/')))!
					os.cp(root + '/' + file, root + '/kernel-aarch64/' + file.all_after('kernel/'))!
				}
			}
			for item in ['obj/blob.c', 'obj/blob.c.o', 'obj/blob.c.d'] { os.rm(dir + '/' + item) or {} }
			os.rmdir_all(dir + '/obj/vsrc') or {}
			run(['touch', dir + '/dev/pty/pty.v'], root + '/touch-' + arch + '.log', 5)!
			if arch == 'x86_64' {
			project := root + '/sampler-' + arch
			os.mkdir_all(project)!
			os.cp_all(dir + '/heapbench', project + '/heapbench', true)!
			os.write_file(project + '/v.mod', "Module { name: 'kernel_sampler' }\n")!
			os.write_file(project + '/entry.v', 'module main\nimport heapbench as _\n')!
			os.mkdir_all(dir + '/obj')!
			run([compiler, '-shared', '-no-builtin', '-no-closures', '-os', 'vinix', '-arch',
				if arch == 'x86_64' { 'amd64' } else { 'arm64' }, '-target-libc-headers',
				'-nofloat', '-gc', 'none', '-manualfree', '-o', dir + '/obj/heap_benchmark.c', project],
				root + '/sampler-' + arch + '.log', 180)!
			}
			run(['make', '-C', dir, '-j4', 'ARCH=' + arch, 'PROD=true', 'V=' + compiler,
				'CC=clang', 'AR=llvm-ar', 'LD_X86_64=/usr/bin/ld.lld', 'LD_AARCH64=/usr/bin/ld.lld', 'LD_LLD=/usr/bin/ld.lld'],
				root + '/build-' + arch + '.log', 1800)!
			generated := os.read_file(dir + '/obj/blob.c')!
			assert generated.contains('slave->stat.uid = process->euid;')
			assert generated.contains('slave->stat.gid = process->egid;')
			mut lines := ['architecture=' + arch, 'compiler_sha256=' + hash(compiler)!]
			for file in ['dev/pty/pty.v', 'obj/blob.c', 'obj/blob.c.o', 'bin/vinix'] {
				lines << hash(dir + '/' + file)! + '  ' + dir + '/' + file
			}
			os.write_file(root + '/receipt-' + arch + '.txt', lines.join('\n') + '\n')!
			println(lines.join('\n'))
		}
	} else if os.args[2] == 'host' {
		run([compiler, '-enable-globals', '-shared', '-no-builtin', '-no-closures', '-os', 'vinix',
			'-arch', 'amd64', '-target-libc-headers', '-gc', 'none', '-manualfree', '-o', root + '/probe.c',
			root + '/tests/pty-posix/probe'], root + '/probe-generate.log', 180)!
		run(['clang', '-D_GNU_SOURCE', '-w', '-o', root + '/probe-host', root + '/probe.c'], root + '/probe-link.log', 60)!
		run([root + '/probe-host'], root + '/probe-host.log', 15)!
		run([compiler, '-prod', '-gc', 'none', '-d', 'ssh_session_workers', '-path', '@vlib|@vmodules|' + root,
			'-o', root + '/sshd-after.c', root + '/tools/sshserver'], root + '/sshd-generate.log', 180)!
		run(['clang', '-O2', '-D_GNU_SOURCE', '-w', '-pthread', '-include',
			'/home/agent/code/v/vlib/builtin/segfault_handler_nix.h', root + '/sshd-after.c', '-lm', '-o', root + '/sshd-after'], root + '/sshd-link.log', 180)!
		run([compiler, '-cc', 'clang', 'run', root + '/tests/pty-posix/interop.v', root + '/sshd-after', root + '/interop-after-' + os.getpid().str(), 'fixed'], root + '/interop-after.log', 180)!
		// Generate monolithic C just as the production daemon build does.
		// This also avoids the compiler's unrelated cached-os waitpid ABI bug.
		// This compiler strips assert under -prod even in a test file.
		// Keep tests unoptimized at generation; clang still builds with -O2.
		run([compiler, '-gc', 'none', '-d', 'no_segfault_handler', '-d', 'no_backtrace',
			'-path', '@vlib|@vmodules|' + root, '-o', root + '/session-test.c',
			root + '/tools/sshserver/session_test.v'], root + '/session-generate.log', 180)!
		run(['clang', '-O2', '-D_GNU_SOURCE', '-w', '-pthread', root + '/session-test.c', '-lm', '-o', root + '/session-test'], root + '/session-link.log', 180)!
		run([root + '/session-test'], root + '/session-test.log', 30)!
	} else { eprintln('unknown mode'); exit(2) }
}
