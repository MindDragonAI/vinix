// SPDX-License-Identifier: GPL-2.0-or-later
// Host checks compile the actual production parsers/client and queue policy.
module main

import os
import crypto.rand

fn run(compiler string, args []string) {
	mut child := os.new_process(compiler)
	child.set_args(args)
	child.run()
	child.wait()
	code := child.code
	child.close()
	if code != 0 { exit(code) }
}

fn audit_no_allocations(path string, names []string) {
	generated := os.read_file(path) or { panic(err) }
	for name in names {
		mut found := false
		for line in generated.split_into_lines() {
			if !line.replace('__', '_').contains(name + '(') || !line.ends_with(') {') || line.starts_with('	') {
				continue
			}
			body := generated.all_after(line + '\n').all_before('\n}\n')
			for allocation in ['memdup(', 'new_array', 'string__substr(', '_v_malloc(', 'HEAP(',
				'heap('] {
				assert !body.contains(allocation), name + ' allocates: ' + allocation
			}
			found = true
			break
		}
		assert found, 'missing generated C definition: ' + name
	}
}

fn main() {
	root := os.real_path(os.join_path(os.dir(@FILE), '..', '..', '..'))
	scratch := os.getenv_opt('TMPDIR') or { os.temp_dir() }
	work := os.join_path(scratch, 'vinix-ninep-protocol-${os.getpid()}-' + rand.bytes(8)!.hex())
	os.mkdir(work)!
	os.mkdir_all(work + '/ninep')!
	os.mkdir_all(work + '/virtio_9p')!
	defer { os.rmdir_all(work) or {} }
	os.write_file(work + '/v.mod', "Module { name: 'ninep_host_checks' }")!
	for name in ['wire.v', 'options.v', 'client.v'] {
		os.cp(root + '/kernel/fs/ninep/' + name, work + '/ninep/' + name)!
	}
	os.cp(root + '/tests/ninep/protocol/wire_test.v', work + '/ninep/wire_test.v')!
	os.cp(root + '/tests/ninep/protocol/client_test.v', work + '/ninep/client_test.v')!
	os.cp(root + '/kernel/dev/virtio_9p/queue.v', work + '/virtio_9p/queue.v')!
	os.cp(root + '/tests/ninep/protocol/queue_test.v', work + '/virtio_9p/queue_test.v')!
	compiler := os.getenv_opt('V') or { @VEXE }
	os.setenv('VEXE', compiler, true)
	run(compiler, ['-nocache', '-cc', 'clang', '-enable-globals', 'test', work + '/ninep'])
	run(compiler, ['-nocache', '-cc', 'clang', 'test', work + '/virtio_9p'])
	os.mkdir_all(work + '/facade')!
	os.cp_all(root + '/tests/ninep/protocol/fixture', work + '/facade', false)!
	os.write_file(work + '/facade/v.mod', "Module { name: 'ninep_facade_fixture' }")!
	os.mkdir_all(work + '/facade/fs/ninep')!
	for name in ['wire.v', 'options.v', 'client.v'] {
		os.cp(root + '/kernel/fs/ninep/' + name, work + '/facade/fs/ninep/' + name)!
	}
	os.mkdir_all(work + '/facade/stat')!
	os.cp(root + '/kernel/stat/stat.v', work + '/facade/stat/stat.v')!
	os.cp(root + '/kernel/fs/ninep.v', work + '/facade/fs/ninep.v')!
	os.cp(root + '/kernel/fs/network_mmap.v', work + '/facade/fs/network_mmap.v')!
	os.cp(root + '/tests/ninep/protocol/facade_test.v', work + '/facade/fs/facade_test.v')!
	os.cp(root + '/tests/network-mmap/ninep_test.v', work + '/facade/fs/network_mmap_test.v')!
	cache := os.read_file(root + '/kernel/resource/cache.v')!
	release_interface := 'pub interface MappingReleaseResource {' + cache.all_after('pub interface MappingReleaseResource {').all_before('\n}') + '\n}\n'
	lifetime := 'pub interface MappingLifetimeResource {' + cache.all_after('pub interface MappingLifetimeResource {').all_before('\npub struct FileSystemStat')
	release_dispatch := 'pub fn release_mapping(' + cache.all_after('pub fn release_mapping(').all_before('\n// Mappings created directly')
	os.write_file(work + '/facade/resource/mapping.v', 'module resource\nimport errno\n' + release_interface + lifetime + release_dispatch)!
	run(compiler, ['-nocache', '-cc', 'clang', '-enable-globals', 'test', work + '/facade/fs'])
	run(compiler, ['-nocache', '-cc', 'clang', '-enable-globals', '-gc', 'none', '-manualfree',
		'-o', work + '/facade.c', work + '/facade/fs/facade_test.v'])
	audit_no_allocations(work + '/facade.c', ['ninep_resource', 'NinePResource_refresh_locked',
		'NinePResource_read', 'NinePResource_read_locked',
		'NinePResource_write_locked', 'NinePResource_write', 'NinePResource_grow',
		'NinePResource_persist_metadata', 'NinePResource_open', 'NinePResource_snapshot_permissions',
		'Client_read', 'Client_write', 'Client_call', 'Client_walk', 'Client_clunk', 'Client_getattr',
		'parse_attr', 'next_entry', 'parse_options'])
	run(compiler, ['-nocache', '-cc', 'clang', '-enable-globals', '-gc', 'none', '-manualfree',
		'-o', work + '/mmap.c', work + '/facade/fs/network_mmap_test.v'])
	audit_no_allocations(work + '/mmap.c', ['NinePResource_mmap', 'NinePResource_read_locked',
		'NinePResource_release_mapping', 'network_mmap_page', 'NetworkMmapPage_complete',
		'resource_release_mapping', 'resource_retain_mapping_range'])
	run(compiler, ['-nocache', '-cc', 'clang', '-enable-globals', '-o', work + '/mmap-check', work + '/facade/fs/network_mmap_test.v'])
	run(work + '/mmap-check', [])
	println('NETWORK-MMAP-ALLOC-PASS 7 9P/page-fill/Resource-dispatch generated C bodies contain no hidden allocations')
	os.mkdir_all(work + '/transport')!
	os.cp_all(root + '/tests/ninep/protocol/transport_fixture', work + '/transport', false)!
	// The host fixture owns real virtual memory, but its emulated device must
	// receive a representable legacy DMA bus address. Host malloc pointers can
	// exceed the production ring's page << 32 limit; they are not bus addresses.
	fixture_path := work + '/transport/transport.v'
	fixture := os.read_file(fixture_path)!
	needle := 'virt: aligned, bus: aligned, bytes: bytes'
	assert fixture.count(needle) == 1, 'transport DMA fixture contract changed'
	os.write_file(fixture_path, fixture.replace(needle,
		'virt: aligned, bus: if bytes == u64(buffer_bytes) * 2 { u64(0x200000) } else { u64(0x100000) }, bytes: bytes'))!
	os.write_file(work + '/transport/v.mod', "Module { name: 'ninep_transport_fixture' }")!
	os.mkdir_all(work + '/transport/klock')!
	os.cp(root + '/tests/ninep/protocol/fixture/klock/klock.v', work + '/transport/klock/klock.v')!
	for name in ['virtio_9p.v', 'queue.v'] {
		os.cp(root + '/kernel/dev/virtio_9p/' + name, work + '/transport/' + name)!
	}
	os.cp(root + '/tests/ninep/protocol/transport_test.v', work + '/transport/transport_test.v')!
	test_path := work + '/transport/transport_test.v'
	transport_test := os.read_file(test_path)!
	assert transport_test.count('assert ch.size == 128') == 1
	os.write_file(test_path, transport_test.replace('assert ch.size == 128',
		'assert ch.size == 128\n\tassert ch.ring.bus != ch.ring.virt\n\tassert valid_ring(ch.ring.bus, ch.ring.bytes, ch.page_size())\n\tassert ch.buffers.bus != ch.ring.bus'))!
	run(compiler, ['-nocache', '-cc', 'clang', '-enable-globals', 'test', work + '/transport'])
	// The numeric import failure is recorded in NOTES.md; the replacement
	// module path is proven here by compiling a real consumer.
	os.write_file(work + '/main.v', 'module main\nimport ninep\nfn main() { assert ninep.max_msize == 65536 }\n')!
	run(compiler, ['-nocache', '-cc', 'clang', 'run', work + '/main.v'])
	println('9P production protocol/client and split-ring policy host checks PASS')
}
