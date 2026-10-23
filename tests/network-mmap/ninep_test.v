// Compile the unchanged production facade, 9P client and mmap helper against
// the protocol fixture. Only the transport and physical allocator are fake.
module fs

import dev.virtio_9p
import errno
import fs.ninep
import memory
import memory.mmap
import resource
import stat

fn test_network_file_mmap_real_bytes_offsets_bounds_errors_and_ownership() {
	initial_mount_table = &MountTable{}
	mut backend := &NinePFS{}
	mut parent := create_node(backend.as_filesystem(), unsafe { nil }, '/', true)
	root := backend.mount_specifier(parent, 'qual', 'share', 0,
		'trans=virtio,version=9p2000.L,cache=none,msize=65536') or { panic('mount') }
	mut directory := ninep_resource(root)
	mut acl := []u8{}
	directory.snapshot_permissions(mut acl) or { panic('populate') }
	mut file := ninep_resource(lookup_child_synced(root, 'alpha'))
	assert file != unsafe { nil }
	assert file.can_mmap && !directory.can_mmap
	assert file.box.can_mmap && !directory.box.can_mmap
	// Exercise production attribute publication for every file type, even the
	// special types the namespace facade currently declines to expose.
	mut classification := NinePResource{filesystem: backend}
	for mode in [stat.ifreg, stat.ifdir, stat.iflnk, stat.ifchr, stat.ifblk, stat.ififo, stat.ifsock] {
		attr := ninep.Attr{mode: mode}
		classification.set_stat(unsafe { &attr })
		assert classification.can_mmap == stat.isreg(u32(mode))
	}
	mut data := [4096 + 29]u8{}
	for i in 0 .. data.len { data[i] = u8((i * 37 + i / 4096 * 19) % 251) }
	assert file.write(unsafe { nil }, &data[0], 0, u64(data.len)) or { i64(-1) } == data.len
	baseline := memory.live_pages()
	initial_fids := virtio_9p.live_fids()
	mut mapped_resource := file.box
	assert resource.retain_mapping_range(mut mapped_resource, unsafe { nil }, 0, 12288, mmap.map_private)
	for page in [u64(0), 1, 2] {
		virtio_9p.mmap_reads(257, 0, 0)
		physical := mapped_resource.mmap(unsafe { nil }, page, mmap.map_private)
		assert physical != unsafe { nil }
		assert memory.live_pages() == baseline + 1
		for i in 0 .. 4096 {
			at := int(page * 4096) + i
			assert unsafe { &u8(physical)[i] } == if at < data.len { data[at] } else { u8(0) }
		}
		if page == 0 { assert virtio_9p.read_count() == 16 }
		if page == 1 { assert virtio_9p.read_count() == 1 && virtio_9p.last_read_offset() == 4096 }
		if page == 2 { assert virtio_9p.read_count() == 0 }
		assert virtio_9p.live_fids() == initial_fids
		resource.release_mapping(mut mapped_resource, unsafe { nil }, page, physical, mmap.map_private)
		assert memory.live_pages() == baseline
	}
	resource.release_mapping_range(mut mapped_resource, unsafe { nil }, 0, 12288, mmap.map_private)
	virtio_9p.mmap_reads(257, 0, 0)
	virtio_9p.mmap_short_chunks(true)
	short_page := file.mmap(unsafe { nil }, 0, mmap.map_private)
	assert short_page != unsafe { nil }
	for i in 0 .. 4096 { assert unsafe { &u8(short_page)[i] } == data[i] }
	file.release_mapping(unsafe { nil }, 0, short_page, mmap.map_private)
	assert memory.live_pages() == baseline
	virtio_9p.mmap_short_chunks(false)
	// Existing read() permits partial results; a page fill must fail even if
	// the failing RPC follows an earlier successful chunk.
	for failure in [1, 2] {
		virtio_9p.mmap_reads(257, failure, 0)
		assert file.mmap(unsafe { nil }, 0, mmap.map_private) == unsafe { nil }
		assert errno.get() == errno.eio
		assert memory.live_pages() == baseline && virtio_9p.live_fids() == initial_fids
	}
	virtio_9p.mmap_reads(257, 0, 2)
	assert file.mmap(unsafe { nil }, 0, mmap.map_private) == unsafe { nil }
	assert errno.get() == errno.eio && memory.live_pages() == baseline
	virtio_9p.mmap_reads(0, 0, 0)
	memory.fail_next_page()
	assert file.mmap(unsafe { nil }, 0, mmap.map_private) == unsafe { nil }
	assert errno.get() == errno.enomem && memory.live_pages() == baseline
	assert file.mmap(unsafe { nil }, u64(-1), mmap.map_private) == unsafe { nil }
	assert errno.get() == errno.eoverflow
	assert !resource.retain_mapping_range(mut mapped_resource, unsafe { nil }, 0, 4096, mmap.map_shared)
	assert errno.get() == errno.enotsup
	assert file.mmap(unsafe { nil }, 0, mmap.map_shared) == unsafe { nil }
	assert directory.mmap(unsafe { nil }, 0, mmap.map_private) == unsafe { nil }
	assert errno.get() == errno.enodev && memory.live_pages() == baseline
	assert !file.filesystem.lock.held
	backend.channel.close()
	backend.closed = true
	assert file.mmap(unsafe { nil }, 0, mmap.map_private) == unsafe { nil }
	assert errno.get() == errno.eio && memory.live_pages() == baseline
	println('NETWORK-MMAP-PASS 9P real bytes; page offsets; EOF zero-fill; 257-byte RPCs; regular-only; error/OOM cleanup; shared refusal')
}
