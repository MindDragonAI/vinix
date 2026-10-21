// SPDX-License-Identifier: GPL-2.0-or-later
module main

import os

fn main() {
	compiler := os.find_abs_path_of_executable(os.getenv_opt('V') or { 'v' })!
	root := os.real_path(os.dir(@FILE) + '/../..')
	work := os.join_path(os.temp_dir(), 'vinix-selfboot-policy-' + os.getpid().str())
	if os.exists(work) { panic('host test scratch directory must be fresh') }
	os.mkdir_all(work + '/sysdiskpolicy')!
	defer { os.rmdir_all(work) or {} }
	os.cp(root + '/kernel/sysdiskpolicy/policy.v', work + '/sysdiskpolicy/policy.v')!
	os.cp(root + '/tests/selfboot-policy/policy_test.v', work + '/policy_test.v')!
	os.write_file(work + '/v.mod', "Module { name: 'selfboot_policy_tests' }\n")!
	mut child := os.new_process(compiler)
	child.set_args(['-gc', 'none', 'test', work])
	child.set_work_folder(work)
	child.wait()
	code := child.code
	child.close()
	if code != 0 { exit(code) }
	println('Selfboot policy host tests: PASS')
}
