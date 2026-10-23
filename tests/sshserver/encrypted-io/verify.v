// SPDX-License-Identifier: GPL-2.0-or-later
// Copy the production transfer function verbatim into a counting host backend.
module main
import os

fn command(args []string, log string) !int {
	mut p := os.new_process('/bin/sh')
	p.set_args(['-c', args.map(os.quoted_path(it)).join(' ') + ' >' + os.quoted_path(log) + ' 2>&1'])
	p.run(); p.wait()
	code := p.code
	p.close()
	os.write_file(log + '.exit', '${code}\n')!
	println('${os.file_name(log)} EXIT=${code}')
	return code
}

fn main() { run() or { eprintln(err.msg()); exit(1) } }
fn run() ! {
	if os.args.len != 4 { return error('usage: verify.v REPO KERNEL-SOURCE FRESH-PROJECT') }
	root, kernel, fresh := os.real_path(os.args[1]), os.real_path(os.args[2]), os.args[3]
	if os.exists(fresh) { return error('fresh project required') }
	os.mkdir_all(fresh)!
	for name in ['fs', 'memory', 'proc', 'errno', 'kbudget'] {
		os.cp_all(root + '/tests/sshserver/encrypted-io/support/' + name, fresh + '/' + name, true)!
	}
	os.mkdir_all(fresh + '/aesxts')!
	os.cp(root + '/kernel/aesxts/core.v', fresh + '/aesxts/core.v')!
	os.cp(kernel + '/fs/storage_crypt.v', fresh + '/fs/storage_crypt.v')!
	os.write_file(fresh + '/v.mod', "Module { name: 'encrypted_io_test' }\n")!
	v := '/home/agent/code/v/v'
	if command([v, '-enable-globals', '-gc', 'none', '-d', 'no_backtrace', '-d', 'no_segfault_handler',
		'-path', fresh + '|@vlib|@vmodules', '-o', fresh + '/test.c', fresh + '/fs/transfer_test.v'], fresh + '/generate.log')! != 0 { return error('test generation failed') }
	if command(['clang', '-O2', '-D_GNU_SOURCE', '-w', fresh + '/test.c', '-pthread', '-lm', '-o', fresh + '/test'], fresh + '/link.log')! != 0 { return error('test link failed') }
	code := command([fresh + '/test'], fresh + '/test.log')!
	println(os.read_file(fresh + '/test.log')!)
	if code != 0 { return error('production transfer regression failed') }
}
