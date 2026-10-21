module main

import compress.gzip
import json2
import os

fn work_dir() !string { return temporary(os.real_path(os.temp_dir()))! }

fn fixture_bundle(path string, id string) !Bundle {
	os.mkdir(path)!
	mut elf := []u8{len: 64}
	stamp(mut elf, 0, [u8(0x7f), `E`, `L`, `F`, 2, 1])
	put(mut elf, 16, 2, 2)
	put(mut elf, 18, 62, 2)
	os.write_file_array(path + '/vinix', elf)!
	mut pe := []u8{len: 512}
	stamp(mut pe, 0, 'MZ'.bytes())
	put(mut pe, 60, 128, 4)
	stamp(mut pe, 128, [u8(`P`), `E`, 0, 0])
	put(mut pe, 132, 0x8664, 2)
	put(mut pe, 152, 0x20b, 2)
	put(mut pe, 220, 10, 2)
	os.write_file_array(path + '/BOOTX64.EFI', pe)!
	mut tar := []u8{len: 2048}
	stamp(mut tar, 0, './.vinix-image-id'.bytes())
	stamp(mut tar, 100, '0000644\x00'.bytes())
	stamp(mut tar, 108, '0000000\x00'.bytes())
	stamp(mut tar, 116, '0000000\x00'.bytes())
	stamp(mut tar, 124, '00000000021\x00'.bytes())
	stamp(mut tar, 136, '00000000000\x00'.bytes())
	for i in 148 .. 156 { tar[i] = ` ` }
	tar[156] = `0`
	stamp(mut tar, 257, 'ustar\x0000'.bytes())
	mut sum := u64(0)
	for b in tar[..512] { sum += b }
	stamp(mut tar, 148, '${sum:06o}\x00 '.bytes())
	stamp(mut tar, 512, (id + '\n').bytes())
	mut gz := gzip.compress(tar)!
	gz[3] = 0x10
	mut commented := gz[..10].clone()
	commented << ('vinix-image-id=' + id + '\x00').bytes()
	commented << gz[10..]
	os.write_file_array(path + '/initramfs.tar.gz', commented)!
	os.write_file(path + '/limine.conf', template() + '    cmdline: vinix.disk=auto\n')!
	mut hashes := map[string]string{}
	for name in payloads { hashes[name] = digest(path + '/' + name)! }
	b := Bundle{ iso_sha256: '1'.repeat(64), image_id: id, files: hashes }
	os.write_file(path + '/manifest.json', json2.encode(b) + '\n')!
	return b
}

// A format fixture, never booted or presented as an installed userland image.
fn fixture_root(fd int, bytes i64) ! {
	at := bytes - 4 * mib
	mut sb := []u8{len: 1024}
	put(mut sb, 4, u64(at / 4096), 4)
	put(mut sb, 24, 2, 4)
	put(mut sb, 56, 0x4a56, 2)
	stamp(mut sb, 104, '0123456789abcdef'.bytes())
	write_at(fd, 1024, sb)!
	mut journal := []u8{len: 4096}
	// Bind this fixture to the on-disk constant, not the historically transposed
	// prose comment in kernel/fs/journal/journal.v.
	put(mut journal, 0, u64(0x314c4e4a58494e56), 8)
	put(mut journal, 8, 1, 4)
	put(mut journal, 12, 4096, 4)
	put(mut journal, 16, u64(at), 8)
	put(mut journal, 24, u64(at), 8)
	put(mut journal, 32, u64(4 * mib), 8)
	stamp(mut journal, 40, sb[104..120])
	put(mut journal, 56, crc(journal, 0x82f63b78), 4)
	write_at(fd, at, journal)!
}

fn test_geometry_gpt_primary_backup_and_crc() ! {
	assert crc32('123456789'.bytes()) == 0xcbf43926
	assert crc('123456789'.bytes(), 0x82f63b78) == 0xe3069283
	g := geometry(i64(4) * 1024 * mib)!
	assert g.disk_bytes == 5370806272
	for bad in [i64(0), 4096, g.root_bytes + 1, i64(1) << 51] {
		geometry(bad) or { continue }
		assert false, 'accepted invalid geometry'
	}
	e := gpt_entries(g, 'a'.repeat(32))!
	assert get(e, 32, 8) == 2048
	assert get(e, 160, 8) == u64(root_start / 512)
	assert get(e, 168, 8) - get(e, 160, 8) + 1 == u64(g.root_bytes / 512)
	for backup in [false, true] {
		mut h := gpt_header(g, 'a'.repeat(32), e, backup)
		recorded := get(h, 16, 4)
		put(mut h, 16, 0, 4)
		assert recorded == crc32(h[..92])
		assert get(h, 88, 4) == crc32(e)
	}
	work := work_dir()!
	defer { os.rmdir_all(work) or {} }
	fd := fresh_file(work + '/gpt', g.disk_bytes)!
	defer { C.close(fd) }
	write_gpt(fd, g, 'a'.repeat(32))!
	verify_gpt(fd, g, 'a'.repeat(32))!
	write_at(fd, g.disk_bytes - 1, [u8(1)])!
	verify_gpt(fd, g, 'a'.repeat(32)) or { return }
	assert false, 'accepted corrupt backup GPT'
}

fn test_marker_schema_and_literal_configuration() ! {
	token := 'a'.repeat(32)
	id := '0123456789abcdef'
	b := marker(token, i64(4) * 1024 * mib, id)!
	assert b.len == 512
	assert b[..16].bytestr() == 'VINIX-SYSDISK-1\n'
	assert b[15] == `\n`
	assert b[16..48].bytestr() == token
	assert b[48..64].bytestr() == '0000000100000000'
	assert b[64..80].bytestr() == id
	assert b[80..].all(it == 0)
	text := config('b'.repeat(64), token, id)!
	assert text.contains('kernel_path: boot():/boot/g-' + 'b'.repeat(64) + '/vinix\n')
	assert text.ends_with('cmdline: vinix.disk=auto vinix.sysroot=${token} vinix.disk_from=${id}\n')
	config('b'.repeat(64), token, id + '\ncmdline: evil') or { return }
	assert false, 'configuration injection accepted'
}

fn test_refusal_matrix_paths_links_identity_lock_and_blank() ! {
	work := work_dir()!
	defer { os.rmdir_all(work) or {} }
	path := work + '/disk'
	fd := fresh_file(path, 2 * mib + 7)!
	C.close(fd)
	for bad in ['relative', work + '/../disk', '/dev/null', work, work + '/missing'] {
		regular(bad) or { continue }
		assert false, 'accepted unsafe target ${bad}'
	}
	os.symlink(path, work + '/symlink')!
	mut refused := false
	regular(work + '/symlink') or {
		refused = true
		assert err.msg().contains('REFUSED')
	}
	assert refused
	os.link(path, work + '/hardlink')!
	refused = false
	regular(path) or {
		refused = true
		assert err.msg().contains('hardlinks')
	}
	assert refused
	os.rm(work + '/hardlink')!
	f := locked(path)!
	defer { f.close() }
	refused = false
	locked(path) or {
		refused = true
		assert err.msg().contains('lock')
	}
	assert refused
	blank(f)!
	mut mismatch := map[string]string{}
	mismatch['expect-dev'] = f.id.dev.str()
	mismatch['expect-inode'] = (f.id.ino + 1).str()
	mismatch['expect-bytes'] = f.id.bytes.str()
	refused = false
	confirm(f, mismatch) or {
		refused = true
		assert err.msg().contains('confirmation')
	}
	assert refused
	writer := C.open(path.str, C.O_RDWR)
	assert writer >= 0
	write_at(writer, 2 * mib + 6, [u8(1)])!
	C.close(writer)
	refused = false
	blank(f) or {
		refused = true
		assert err.msg().contains('zero')
	}
	assert refused
	os.rename(path, work + '/old')!
	os.write_file(path, 'replacement')!
	f.unchanged() or { return }
	assert false, 'path replacement accepted'
}

fn test_full_sparse_clone_and_zero_replacement() ! {
	work := work_dir()!
	defer { os.rmdir_all(work) or {} }
	src := fresh_file(work + '/source', 3 * mib + 17)!
	dst := fresh_file(work + '/clone', 3 * mib + 17)!
	defer {
		C.close(src)
		C.close(dst)
	}
	write_at(src, mib - 2, [u8(1), 2, 3, 4])!
	write_at(src, 3 * mib + 16, [u8(9)])!
	sum := clone_range(src, 0, dst, 0, 3 * mib + 17)!
	assert sum == hash_range(dst, 0, 3 * mib + 17)!
	assert read_at(dst, 3 * mib + 16, 1)! == [u8(9)]
}

fn test_vjfs_fixed_end_journal_refuses_corruption_foreign_and_pending() ! {
	work := work_dir()!
	defer { os.rmdir_all(work) or {} }
	bytes := i64(4) * 1024 * mib
	fd := fresh_file(work + '/root', bytes)!
	defer { C.close(fd) }
	fixture_root(fd, bytes)!
	validate_root(fd, 0, bytes)!
	write_at(fd, bytes - 4 * mib + 4096, [u8(1)])!
	mut refused := false
	validate_root(fd, 0, bytes) or {
		refused = true
		assert err.msg().contains('pending')
	}
	assert refused
	write_at(fd, bytes - 4 * mib + 4096, [u8(0)])!
	write_at(fd, bytes - 4 * mib + 60, [u8(1)])!
	refused = false
	validate_root(fd, 0, bytes) or {
		refused = true
		assert err.msg().contains('journal')
	}
	assert refused
	write_at(fd, 1080, [u8(0x53), 0xef])!
	validate_root(fd, 0, bytes) or { return }
	assert false, 'foreign ext2 accepted'
}

fn test_bundle_snapshot_trust_architecture_payload_and_archive_identity() ! {
	work := work_dir()!
	defer { os.rmdir_all(work) or {} }
	b := fixture_bundle(work + '/input', '0123456789abcdef')!
	trusted := digest(work + '/input/manifest.json')!
	snapshot := bundle_snapshot(work + '/input', trusted, work + '/snapshot')!
	assert snapshot == b
	assert check_payloads(work + '/snapshot')! == b.image_id
	mut refused := false
	bundle_snapshot(work + '/input', '0'.repeat(64), work + '/bad-trust') or {
		refused = true
		assert err.msg().contains('trusted')
	}
	assert refused
	os.write_file(work + '/input/vinix', 'corrupt')!
	refused = false
	bundle_snapshot(work + '/input', trusted, work + '/corrupt') or {
		refused = true
		assert err.msg().contains('payload')
	}
	assert refused
	bad := fixture_bundle(work + '/bad-archive', '0123456789abcdef')!
	assert bad.image_id == b.image_id
	mut gz := os.read_bytes(work + '/bad-archive/initramfs.tar.gz')!
	gz[25] = `f` // Change comment only; gzip CRC still matches the archive.
	os.write_file_array(work + '/bad-archive/initramfs.tar.gz', gz)!
	refused = false
	check_payloads(work + '/bad-archive') or {
		refused = true
		assert err.msg().contains('disagree')
	}
	assert refused
	os.write_file(work + '/snapshot/limine.conf', template() + '    cmdline: root=/dev/sda\n')!
	check_payloads(work + '/snapshot') or { return }
	assert false, 'arbitrary ISO configuration accepted'
}

fn test_native_exit_failure_and_bounded_output() ! {
	native(['true'])!
	mut refused := false
	native(['false']) or {
		refused = true
		assert err.msg().contains('exited')
	}
	assert refused
	refused = false
	native(['selfboot-test-no-such-native-executable']) or {
		refused = true
		assert err.msg().contains('unavailable')
	}
	assert refused
	assert native_output(['true'], 64)! == ''
	refused = false
	native_output(['false'], 64) or {
		refused = true
		assert err.msg().contains('exited')
	}
	assert refused
	native_output(['printf', '123456789'], 4) or { return }
	assert false, 'unbounded helper output accepted'
}

fn test_failpoints_never_activate_and_stale_policy() ! {
	for phase in ['validated', 'root-copied', 'payloads-staged', 'config-staged', 'verified',
		'before-activate'] {
		checkpoint({
			'interrupt-after': phase
		}, phase) or { continue }
		assert false, 'failpoint did not fail'
	}
	mut refused := false
	check_failpoints({
		'interrupt-after': 'after-activate'
	}) or {
		refused = true
		assert err.msg().contains('unknown')
	}
	assert refused
	refused = false
	check_failpoints({
		'pause-at': 'verified'
	}) or {
		refused = true
		assert err.msg().contains('together')
	}
	assert refused
	old := Ownership{
		generation:  'a'.repeat(64)
		generations: ['b'.repeat(64), 'a'.repeat(64)]
		image_ids:   ['1'.repeat(16), '2'.repeat(16)]
		bundle:      Bundle{ image_id: '2'.repeat(16) }
	}
	transition(old, old.generation, old.bundle)!
	transition(old, 'c'.repeat(64), Bundle{ image_id: '3'.repeat(16) })!
	refused = false
	transition(old, 'b'.repeat(64), Bundle{ image_id: '1'.repeat(16) }) or {
		refused = true
		assert err.msg().contains('downgrade')
	}
	assert refused
	transition(old, 'd'.repeat(64), Bundle{ image_id: '1'.repeat(16) }) or { return }
	assert false, 'repackaged stale image accepted'
}

fn test_cli_rejects_ambiguous_duplicate_and_unexpected_options() ! {
	for args in [['--target', '/tmp/a', '--target=/tmp/b'], ['--disk=/tmp/a'], ['positional']] {
		options(args, ['target']) or { continue }
		assert false, 'unsafe options accepted'
	}
	assert options(['--target=/tmp/a'], ['target'])!['target'] == '/tmp/a'
}

fn test_binary_header_and_mapping_refusals() ! {
	work := work_dir()!
	defer { os.rmdir_all(work) or {} }
	fixture_bundle(work + '/bundle', '0123456789abcdef')!
	mut elf := os.read_bytes(work + '/bundle/vinix')!
	elf[18] = 183
	mut refused := false
	kernel_header(elf) or { refused = true }
	assert refused
	mut pe := os.read_bytes(work + '/bundle/BOOTX64.EFI')!
	pe[132] = 0x64
	pe[133] = 0xaa
	refused = false
	efi_header(pe) or { refused = true }
	assert refused
	refused = false
	efi_header([u8(`M`), `Z`]) or { refused = true }
	assert refused
	mut gz := os.read_bytes(work + '/bundle/initramfs.tar.gz')!
	gz[3] = 0
	refused = false
	gzip_id(gz) or { refused = true }
	assert refused
	id := Identity{ dev: 0x801, ino: 12345 }
	assert mapped_identity('1000-2000 rw-s 00000000 08:01 12345 /tmp/root.img', id)
	assert !mapped_identity('1000-2000 rw-s 00000000 08:01 12346 /tmp/root.img', id)
	assert !mapped_identity('malformed', id)
}

fn test_ownership_encoding_and_foreign_target_refusal() ! {
	m := Ownership{ geometry: geometry(i64(4) * 1024 * mib)!, token: 'a'.repeat(32) }
	data := ownership_bytes(m)!
	assert data.len == meta_bytes
	assert data[..16].bytestr() == 'VINIX-HOST-1\n\x00\x00\x00'
	length := int(get(data, 16, 4))
	assert data[84 + length..].all(it == 0)
	assert json2.decode[Ownership](data[84..84 + length].bytestr())! == m
	work := work_dir()!
	defer { os.rmdir_all(work) or {} }
	fd := fresh_file(work + '/foreign', mib)!
	C.close(fd)
	f := locked(work + '/foreign')!
	defer { f.close() }
	read_ownership(f) or {
		assert err.msg().contains('foreign')
		return
	}
	assert false, 'foreign target accepted'
}

fn test_native_xorriso_bundle_and_pinned_kernel_override() ! {
	if os.getenv('SELFBOOT_BUNDLE_INTEGRATION') != '1' { return }
	work := work_dir()!
	defer { os.rmdir_all(work) or {} }
	fixture_bundle(work + '/fixture', '0123456789abcdef')!
	os.mkdir_all(work + '/iso/EFI/BOOT')!
	os.mkdir_all(work + '/iso/boot')!
	for i, name in payloads { os.cp(work + '/fixture/' + name, work + '/iso' + iso_paths[i])! }
	native(['xorriso', '-as', 'mkisofs', '-quiet', '-R', '-o', work + '/test.iso', work + '/iso'])!
	mut elf := os.read_bytes(work + '/fixture/vinix')!
	elf[63] = 1
	os.write_file_array(work + '/override', elf)!
	iso_hash := digest(work + '/test.iso')!
	kernel_hash := digest(work + '/override')!
	bundle_build({
		'iso':           work + '/test.iso'
		'iso-sha256':    iso_hash
		'output':        work + '/bundle'
		'kernel':        work + '/override'
		'kernel-sha256': kernel_hash
	})!
	trusted := digest(work + '/bundle/manifest.json')!
	b := bundle_snapshot(work + '/bundle', trusted, work + '/snapshot')!
	assert b.iso_sha256 == iso_hash
	assert b.kernel_override_sha256 == kernel_hash && b.files['vinix'] == kernel_hash
	assert os.read_bytes(work + '/snapshot/vinix')! == elf
	mut refused := false
	bundle_build({
		'iso':        work + '/test.iso'
		'iso-sha256': '0'.repeat(64)
		'output':     work + '/wrong'
	}) or {
		refused = true
		assert err.msg().contains('checksum')
	}
	assert refused && !os.exists(work + '/wrong')
}

// Optional real mtools transaction tests, enabled on a prepared Linux host.
// They operate only on private disposable sparse files. No QEMU or loop device.
fn test_linux_real_fat_transaction_order_interruption_and_root_preservation() ! {
	if os.getenv('SELFBOOT_INTEGRATION') != '1' { return }
	$if !linux {
		assert false, 'SELFBOOT_INTEGRATION requires Linux'
	}
	work := work_dir()!
	defer { os.rmdir_all(work) or {} }
	b := fixture_bundle(work + '/bundle', '0123456789abcdef')!
	assert b.schema == 1
	pin := digest(work + '/bundle/manifest.json')!
	esp := work + '/esp.img'
	// Interrupt after payload population: staged activation config must not exist.
	mut refused := false
	stage_esp(esp, work, work + '/bundle', pin, 'a'.repeat(32), '0'.repeat(16), true,
		{
			'interrupt-after': 'payloads-staged'
		}) or {
		refused = true
		assert err.msg().contains('interruption')
	}
	assert refused
	native(['mcopy', '-i', esp, '::/boot/limine.conf', work + '/unexpected.conf']) or { assert !os.exists(work + '/unexpected.conf') }
	assert !os.exists(work + '/unexpected.conf')
	os.rm(esp)!
	source := work + '/root.img'
	bytes := i64(4) * 1024 * mib
	sfd := fresh_file(source, bytes)!
	fixture_root(sfd, bytes)!
	write_at(sfd, 2 * mib, 'root-user-data'.bytes())!
	C.close(sfd)
	target := work + '/target.img'
	tfd := fresh_file(target, geometry(bytes)!.disk_bytes)!
	C.close(tfd)
	id := regular(target)!
	mut o := {
		'target':          target
		'source':          source
		'source-image-id': '0'.repeat(16)
		'expect-dev':      id.dev.str()
		'expect-inode':    id.ino.str()
		'expect-bytes':    id.bytes.str()
		'bundle':          work + '/bundle'
		'bundle-sha256':   pin
		'interrupt-after': 'before-activate'
	}
	refused = false
	install(o) or {
		refused = true
		assert err.msg().contains('interruption')
	}
	assert refused
	assert regular(target)!.ino == id.ino
	f := locked(target)!
	blank(f)!
	f.close()
	o.delete('interrupt-after')
	install(o)!
	installed := locked(target)!
	old := read_ownership(installed)!
	assert old.generation == pin
	installed.close()
	// Simulate an offline guest modification. Updater must carry these bytes,
	// rather than copying the initial source root again.
	writer := C.open(target.str, C.O_RDWR | C.O_CLOEXEC)
	assert writer >= 0
	write_at(writer, root_start + 2 * mib + 128, 'guest changed root'.bytes())!
	C.close(writer)
	changed := locked(target)!
	root_hash := hash_range(changed.fd, root_start, bytes)!
	changed.close()
	fixture_bundle(work + '/next', 'fedcba9876543210')!
	next_pin := digest(work + '/next/manifest.json')!
	new_id := regular(target)!
	mut u := {
		'target':          target
		'expect-dev':      new_id.dev.str()
		'expect-inode':    new_id.ino.str()
		'expect-bytes':    new_id.bytes.str()
		'bundle':          work + '/next'
		'bundle-sha256':   next_pin
		'interrupt-after': 'before-activate'
	}
	refused = false
	update(u) or {
		refused = true
		assert err.msg().contains('interruption')
	}
	assert refused
	unchanged := locked(target)!
	assert read_ownership(unchanged)!.generation == pin
	unchanged.close()
	u.delete('interrupt-after')
	update(u)!
	final := locked(target)!
	defer { final.close() }
	state := read_ownership(final)!
	assert state.prior_generation == pin && state.generation == next_pin
	assert state.token == old.token && state.predecessor == b.image_id
	assert hash_range(final.fd, root_start, bytes)! == root_hash
}
