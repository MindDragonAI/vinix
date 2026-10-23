// SPDX-License-Identifier: GPL-2.0-or-later
module main

import os

fn checked(v string, args []string) {
	mut p := os.new_process(v)
	p.set_args(args)
	p.run(); p.wait()
	code := p.code
	p.close()
	if code != 0 { exit(code) }
}

fn function(source string, signature string) string {
	assert source.count(signature) == 1, signature
	tail := source.all_after(signature)
	mut opened := false
	mut depth := 0
	for i, c in tail {
		if c == `{` { depth++; opened = true }
		if c == `}` { depth-- }
		if opened && depth == 0 { return signature + tail[..i+1] + '\n' }
	}
	panic('unterminated function: ' + signature)
}

fn main() {
	root := os.real_path(os.join_path(os.dir(@FILE), '..', '..'))
	v := os.getenv_opt('V') or { @VEXE }
	os.setenv('VEXE', v, true)
	work := os.join_path(os.temp_dir(), 'vinix-network-mmap-${os.getpid()}')
	os.mkdir_all(work + '/fs/smb2')!
	defer { os.rmdir_all(work) or {} }
	os.write_file(work + '/v.mod', "Module { name: 'network_mmap_checks' }")!
	for name in ['memory', 'errno', 'klock', 'time', 'event'] {
		os.cp_all(root + '/tests/ninep/protocol/fixture/' + name, work + '/' + name, false)!
	}
	os.mkdir_all(work + '/stat')!
	os.cp(root + '/kernel/stat/stat.v', work + '/stat/stat.v')!
	os.cp(root + '/kernel/fs/network_mmap.v', work + '/fs/network_mmap.v')!
	os.cp(root + '/tests/network-mmap/smb2_client.vfixture', work + '/fs/smb2/client.v')!
	os.cp(root + '/tests/network-mmap/smb2_test.vfixture', work + '/fs/adapter_test.v')!
	// Compile the production type and method bodies verbatim; the wire service
	// and PMM are replaced. The independent SMB2 suite tests its actual client.
	source := os.read_file(root + '/kernel/fs/smb2.v')!
	mut adapter := 'module fs\nimport stat\nimport klock\nimport event.eventstruct\nimport resource\nimport fs.smb2\nimport time\nimport memory\nimport errno\n'
	adapter += 'struct SMB2Resource {' + source.all_after('struct SMB2Resource {').all_before('\n}') + '\n}\n'
	for signature in ['fn (r &SMB2Resource) remote_path(', 'fn smb2_time(',
		'fn (mut r SMB2Resource) set_stat(', 'fn (mut r SMB2Resource) open_checked(',
		'fn (mut r SMB2Resource) refresh_locked(', 'fn (mut r SMB2Resource) read_locked(',
		'fn (mut r SMB2Resource) mmap(', 'fn (mut r SMB2Resource) retain_mapping_range(',
		'fn (mut r SMB2Resource) release_mapping_range(', 'fn (mut r SMB2Resource) release_mapping('] {
		adapter += function(source, signature)
	}
	os.write_file(work + '/fs/adapter.v', adapter)!
	os.mkdir_all(work + '/resource')!
	os.write_file(work + '/resource/resource.v', 'module resource\npub struct Resource {}\n')!
	checked(v, ['-nocache', '-cc', 'clang', '-enable-globals', 'test', work + '/fs'])
	checked(v, ['-nocache', '-cc', 'clang', '-enable-globals', '-o', work + '/smb2-check', work + '/fs/adapter_test.v'])
	checked(work + '/smb2-check', [])
	checked(v, ['-nocache', '-cc', 'clang', '-enable-globals', '-gc', 'none', '-manualfree', '-o', work + '/adapter.c', work + '/fs/adapter_test.v'])
	generated := os.read_file(work + '/adapter.c')!
	mut checked_bodies := 0
	for name in ['SMB2Resource_mmap', 'SMB2Resource_read_locked', 'SMB2Resource_release_mapping', 'network_mmap_page', 'NetworkMmapPage_complete'] {
		mut found := false
		for line in generated.split_into_lines() {
			if line.starts_with('\t') || !line.ends_with(') {') || !line.replace('__', '_').contains(name + '(') { continue }
			body := generated.all_after(line + '\n').all_before('\n}\n')
			for alloc in ['memdup(', 'new_array', '_v_malloc(', 'HEAP(', 'heap('] {
				assert !body.contains(alloc), name + ': ' + alloc
			}
			found = true
			checked_bodies++
			break
		}
		assert found, name
	}
	println('NETWORK-MMAP-ALLOC-PASS ${checked_bodies} SMB2/page-fill generated C bodies contain no hidden allocations')
}
