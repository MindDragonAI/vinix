// SPDX-License-Identifier: GPL-2.0-or-later
// Build the V-native SSH daemon with a private process per serialized session.
module main

import os

fn run(program string, arguments []string) ! {
	mut process := os.new_process(program)
	defer { process.close() }
	process.set_args(arguments)
	process.set_stdin_path('/dev/null')
	process.run()
	process.wait()
	if process.code != 0 { return error('${program} failed (${process.code})') }
}

fn main() {
	build() or {
		eprintln('sshserver-build: ${err}')
		exit(1)
	}
}

fn build() ! {
	root := os.real_path(os.join_path(os.dir(@FILE), '..'))
	mut arch := 'native'
	mut sysroot := ''
	mut output := root + '/build/sshserver'
	mut staging := ''
	for arg in os.args[1..] {
		if arg == '--help' {
			println('Usage: sshserver-build.v --arch=native|amd64|arm64 --output=DIR [--sysroot=DIR] [--staging=DIR]')
			return
		} else if arg.starts_with('--arch=') {
			arch = arg['--arch='.len..]
		} else if arg.starts_with('--sysroot=') {
			sysroot = os.real_path(arg['--sysroot='.len..])
		} else if arg.starts_with('--output=') {
			output = os.abs_path(arg['--output='.len..])
		} else if arg.starts_with('--staging=') {
			staging = os.real_path(arg['--staging='.len..])
		} else {
			return error('unknown argument: ${arg}')
		}
	}
	if arch !in ['native', 'amd64', 'arm64'] { return error('unsupported architecture') }
	if arch != 'native' && !os.is_dir(sysroot) { return error('cross build requires --sysroot') }
	if staging != '' && (staging == '/' || !os.is_dir(staging)) {
		return error('staging must be an existing target filesystem, not /')
	}
	mut compiler := os.getenv('V')
	if compiler == '' { compiler = os.find_abs_path_of_executable('v')! }
	if os.is_dir(compiler) { compiler += '/v' }
	clang := os.find_abs_path_of_executable('clang')!
	os.mkdir_all(output)!
	generated := output + '/vinix-sshd.c'
	binary := output + '/vinix-sshd'
	mut flags := ['-prod', '-gc', 'none', '-d', 'no_backtrace', '-d', 'no_segfault_handler', '-d',
		'ssh_session_workers', '-path', root + '|@vlib|@vmodules']
	if arch != 'native' {
		flags << ['-os', 'linux', '-arch', if arch == 'amd64' { 'x64' } else { 'arm64' }]
	}
	run(compiler, [...flags, '-o', generated, root + '/tools/sshserver'])!
	if arch == 'native' {
		run(clang, ['-O2', '-D_GNU_SOURCE', '-w', generated, '-pthread', '-lm', '-o', binary + '.tmp'])!
	} else {
		triple := if arch == 'amd64' { 'x86_64' } else { 'aarch64' }
		base := sysroot + '/usr/lib/gcc/' + triple + '-alpine-linux-musl'
		mut versions := os.ls(base)!
		versions.sort()
		mut gcc := ''
		for version in versions {
			if os.is_file(base + '/' + version + '/crtbeginT.o') { gcc = base + '/' + version }
		}
		if gcc == '' { return error('missing static GCC target runtime') }
		run(clang, ['--target=' + triple + '-linux-musl', '-static', '-nostdinc', '-nostdlib',
			'-isystem', gcc + '/include', '-isystem', sysroot + '/usr/include', '-isystem',
			root + '/build-support/aarch64-cc-shim', '-D_GNU_SOURCE', '-O2', '-fno-stack-protector',
			'-w', sysroot + '/usr/lib/crt1.o', sysroot + '/usr/lib/crti.o', gcc + '/crtbeginT.o',
			generated, '-L' + sysroot + '/usr/lib', '-L' + gcc, '-lgcc_eh', '-lc', '-lgcc', '-lm',
			'-lpthread', gcc + '/crtend.o', sysroot + '/usr/lib/crtn.o', '-fuse-ld=lld', '-o',
			binary + '.tmp'])!
		data := os.read_bytes(binary + '.tmp')!
		expected := if arch == 'amd64' { 62 } else { 183 }
		if data.len < 20 || data[..6] != [u8(0x7f), `E`, `L`, `F`, 2, 1]
			|| int(data[18]) + (int(data[19]) << 8) != expected {
			return error('wrong target ELF')
		}
	}
	os.rename(binary + '.tmp', binary)!
	if staging != '' {
		destination := staging + '/usr/libexec/vinix-sshd'
		if os.is_link(staging + '/usr') || os.is_link(staging + '/usr/libexec') || os.is_link(destination) {
			return error('symlink in daemon staging path')
		}
		os.mkdir_all(os.dir(destination))!
		os.cp(binary, destination)!
		os.chmod(destination, 0o755)!
	}
	println('Built ${binary} (${arch}); no listener or credentials created.')
}
