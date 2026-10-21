module main

import crypto.sha256
import json2
import os
import time

struct Ownership {
	schema           int = 1
	geometry         Geometry
	token            string
	bootstrap_id     string
	generation       string
	prior_generation string
	generations      []string
	image_ids        []string
	predecessor      string
	bundle           Bundle
	config_sha256    string
	esp_sha256       string
}

fn ownership_bytes(m Ownership) ![]u8 {
	text := json2.encode(m)
	if text.len > meta_bytes - 84 { return error('ownership history exceeds metadata capacity') }
	mut data := []u8{len: meta_bytes}
	stamp(mut data, 0, 'VINIX-HOST-1\n\x00\x00\x00'.bytes())
	put(mut data, 16, u64(text.len), 4)
	stamp(mut data, 20, sha256.sum(text.bytes()).hex().bytes())
	stamp(mut data, 84, text.bytes())
	return data
}

fn read_ownership(f Locked) !Ownership {
	data := read_at(f.fd, meta_at, meta_bytes)!
	if data[..16].bytestr() != 'VINIX-HOST-1\n\x00\x00\x00' {
		return error('foreign target: no selfboot ownership metadata')
	}
	n := get(data, 16, 4)
	if n == 0 || n > u64(meta_bytes - 84) { return error('invalid ownership length') }
	text := data[84..84 + int(n)].bytestr()
	if sha256.sum(text.bytes()).hex() != data[20..84].bytestr() {
		return error('ownership checksum mismatch')
	}
	m := json2.decode[Ownership](text, strict: true)!
	if m.schema != 1 || !hex_text(m.token, 32) || !hex_text(m.bootstrap_id, 16)
		|| !hex_text(m.predecessor, 16) || !hex_text(m.generation, 64)
		|| !hex_text(m.config_sha256, 64) || !hex_text(m.esp_sha256, 64)
		|| (m.prior_generation != '' && !hex_text(m.prior_generation, 64))
		|| m.generations.len == 0 || m.generations.last() != m.generation
		|| m.generations.any(!hex_text(it, 64)) || m.image_ids.any(!hex_text(it, 16))
		|| m.geometry != geometry(m.geometry.root_bytes)! || m.geometry.disk_bytes != f.id.bytes {
		return error('invalid ownership/target geometry')
	}
	bundle_shape(m.bundle)!
	if sha256.sum((json2.encode(m.bundle) + '\n').bytes()).hex() != m.generation {
		return error('ownership bundle is not bound to active trusted generation')
	}
	if m.image_ids.len != m.generations.len || m.image_ids.last() != m.bundle.image_id
		|| (m.generations.len == 1 && m.prior_generation != '')
		|| (m.generations.len > 1 && m.prior_generation != m.generations[m.generations.len - 2]) {
		return error('invalid ownership generation history')
	}
	expected_predecessor := if m.image_ids.len > 1 {
		m.image_ids[m.image_ids.len - 2]
	} else {
		m.bootstrap_id
	}
	if m.predecessor != expected_predecessor { return error('ownership predecessor mismatch') }
	if ownership_bytes(m)! != data { return error('noncanonical or foreign ownership metadata') }
	expected := config(m.generation, m.token, m.predecessor)!
	if sha256.sum(expected.bytes()).hex() != m.config_sha256 {
		return error('ownership/config mismatch')
	}
	verify_gpt(f.fd, m.geometry, m.token)!
	if read_at(f.fd, root_start, 512)! != marker(m.token, m.geometry.root_bytes, m.bootstrap_id)! {
		return error('root marker/geometry/token mismatch')
	}
	validate_root(f.fd, root_start, m.geometry.root_bytes)!
	if hash_range(f.fd, mib, esp_bytes)! != m.esp_sha256 {
		return error('owned ESP checksum mismatch')
	}
	f.unchanged()!
	return m
}

fn transition(old Ownership, generation string, b Bundle) ! {
	if generation == old.generation { return }
	if generation in old.generations || (b.image_id != old.bundle.image_id
		&& (b.image_id in old.image_ids || b.image_id == old.bootstrap_id)) {
		return error('stale/downgrade generation REFUSED; full offline root backup is required for rollback')
	}
}

fn checkpoint(o map[string]string, phase string) ! {
	println('phase=${phase}')
	if o['interrupt-after'] == phase {
		return error('injected interruption after ${phase}; target was not activated')
	}
	if o['pause-at'] == phase {
		ready := required(o, 'ready-file')!
		absolute(ready)!
		fd := fresh_file(ready, 0)!
		write_at(fd, 0, '${os.getpid()} ${phase}\n'.bytes())!
		durable(fd)!
		C.close(fd)
		// Kill this process to exercise true interruption. Removing the ready file
		// resumes it; no shell controller or signal handler is involved.
		for os.exists(ready) { time.sleep(100 * time.millisecond) }
	}
}

fn check_failpoints(o map[string]string) ! {
	phases := ['validated', 'root-copied', 'payloads-staged', 'config-staged', 'verified',
		'before-activate']
	for key in ['interrupt-after', 'pause-at'] {
		if key in o && o[key] !in phases { return error('unknown ${key}: ${o[key]}') }
	}
	if ('pause-at' in o) != ('ready-file' in o) {
		return error('--pause-at and --ready-file must be supplied together')
	}
}

fn confirm(f Locked, o map[string]string) ! {
	println('target=${f.path}\ndev=${f.id.dev}\ninode=${f.id.ino}\nbytes=${f.id.bytes}\nsector-bytes=512\nesp-start=${mib}\nesp-bytes=${esp_bytes}\nroot-start=${root_start}')
	if required(o, 'expect-dev')! != f.id.dev.str() || required(o, 'expect-inode')! != f.id.ino.str()
		|| required(o, 'expect-bytes')! != f.id.bytes.str() {
		return error('explicit expected target dev/inode/bytes confirmation does not match')
	}
}

fn extract_esp(f Locked, path string) ! {
	fd := fresh_file(path, esp_bytes)!
	defer { C.close(fd) }
	clone_range(f.fd, mib, fd, 0, esp_bytes)!
	durable(fd)!
}

fn check_old_config(esp string, work string, old Ownership) ! {
	native(['mcopy', '-i', esp, '::/boot/limine.conf', work + '/old.conf'])!
	if digest(work + '/old.conf')! != old.config_sha256
		|| os.read_file(work + '/old.conf')! != config(old.generation, old.token, old.predecessor)! {
		return error('existing boot configuration ownership/hash mismatch')
	}
	// Check the active manifest/payloads too, rather than relying solely on the
	// whole-ESP hash recorded by the writer.
	for name in payloads {
		out := work + '/old-' + name
		native(['mcopy', '-i', esp, '::/boot/g-' + old.generation + '/' + name, out])!
		if digest(out)! != old.bundle.files[name] {
			return error('existing generation payload mismatch')
		}
	}
	native(['mcopy', '-i', esp, '::/boot/g-' + old.generation + '/manifest.json',
		work + '/old-manifest.json'])!
	if digest(work + '/old-manifest.json')! != old.generation {
		return error('existing generation manifest hash mismatch')
	}
	native(['mcopy', '-i', esp, '::/EFI/BOOT/BOOTX64.EFI', work + '/old-loader'])!
	if digest(work + '/old-loader')! != old.bundle.files['BOOTX64.EFI'] {
		return error('existing EFI loader mismatch')
	}
}

fn stage_esp(esp string, work string, bundle_dir string, generation string, token string, predecessor string, initial bool, o map[string]string) !string {
	if initial {
		fd := fresh_file(esp, esp_bytes)!
		C.close(fd)
		native(['mformat', '-i', esp, '-F', '-v', 'VINIXESP', '::'])!
		for dir in ['::/EFI', '::/EFI/BOOT', '::/boot'] { native(['mmd', '-i', esp, dir])! }
	}
	genpath := '::/boot/g-' + generation
	native(['mmd', '-i', esp, genpath])!
	for name in payloads {
		native(['mcopy', '-i', esp, bundle_dir + '/' + name, genpath + '/' + name])!
	}
	native(['mcopy', '-i', esp, bundle_dir + '/manifest.json', genpath + '/manifest.json'])!
	checkpoint(o, 'payloads-staged')!
	// All immutable content exists before replacing the staged activation files.
	text := config(generation, token, predecessor)!
	os.write_file(work + '/new.conf', text)!
	native(['mcopy', '-o', '-i', esp, bundle_dir + '/BOOTX64.EFI', '::/EFI/BOOT/BOOTX64.EFI'])!
	native(['mcopy', '-o', '-i', esp, work + '/new.conf', '::/boot/limine.conf'])!
	checkpoint(o, 'config-staged')!
	for name in payloads {
		out := work + '/verify-' + name
		native(['mcopy', '-i', esp, genpath + '/' + name, out])!
		if digest(out)! != digest(bundle_dir + '/' + name)! {
			return error('staged ESP payload mismatch')
		}
	}
	native(['mcopy', '-i', esp, genpath + '/manifest.json', work + '/verify-manifest.json'])!
	if digest(work + '/verify-manifest.json')! != generation {
		return error('staged manifest mismatch')
	}
	native(['mcopy', '-i', esp, '::/boot/limine.conf', work + '/verify.conf'])!
	if os.read_file(work + '/verify.conf')! != text { return error('staged config mismatch') }
	native(['mcopy', '-i', esp, '::/EFI/BOOT/BOOTX64.EFI', work + '/verify-loader'])!
	if digest(work + '/verify-loader')! != digest(bundle_dir + '/BOOTX64.EFI')! {
		return error('staged EFI mismatch')
	}
	return sha256.sum(text.bytes()).hex()
}

fn replace_esp(stage int, esp string) !string {
	f := locked(esp)!
	defer { f.close() }
	mut h := sha256.new()
	mut at := i64(0)
	for at < esp_bytes {
		b := read_at(f.fd, at, 1048576)!
		h.write(b)!
		// Write zeros too: this replaces an existing FAT, not a zero destination.
		write_at(stage, mib + at, b)!
		at += b.len
	}
	f.unchanged()!
	result := h.sum([]u8{}).hex()
	if hash_range(stage, mib, esp_bytes)! != result { return error('disk ESP copy mismatch') }
	return result
}

fn activate(stage string, fd int, target Locked, source ?Locked, o map[string]string) ! {
	durable(fd)!
	checkpoint(o, 'verified')!
	offline(target)!
	if f := source { offline(f)! }
	checkpoint(o, 'before-activate')!
	// Repeat after a pause so an opened VM/loop mapping cannot slip past it.
	offline(target)!
	if f := source { offline(f)! }
	parent := os.dir(target.path)
	dirfd := C.open(parent.str, C.O_RDONLY | C.O_DIRECTORY | C.O_CLOEXEC)
	if dirfd < 0 { return error('cannot open target parent directory') }
	defer { C.close(dirfd) }
	target.unchanged()!
	if C.rename(stage.str, target.path.str) != 0 {
		return error('atomic target activation rename failed')
	}
	mut published := C.selfboot_stat{}
	actual := regular(target.path) or { return error('ACTIVATED, but cannot verify published pathname: ${err}') }
	if C.selfboot_fstat(fd, &published) != 0 || actual.dev != published.st_dev
		|| actual.ino != published.st_ino || actual.bytes != published.st_size {
		return error('ACTIVATED, but published identity verification failed')
	}
	// A failure here means activation already happened; report that explicitly.
	durable(dirfd) or { return error('ACTIVATED, but parent directory fsync failed: ${err}') }
	println('ACTIVATED ${target.path}; inode changed: run inspect again before another operation')
}

fn install(o map[string]string) ! {
	check_failpoints(o)!
	target := locked(required(o, 'target')!)!
	defer { target.close() }
	confirm(target, o)!
	offline(target)!
	source := locked(required(o, 'source')!)!
	defer { source.close() }
	println('source=${source.path}\nsource-dev=${source.id.dev}\nsource-inode=${source.id.ino}\nsource-bytes=${source.id.bytes}')
	offline(source)!
	if source.id.dev == target.id.dev && source.id.ino == target.id.ino {
		return error('source equals target')
	}
	g := geometry(source.id.bytes)!
	println('root-bytes=${g.root_bytes}\nrequired-target-bytes=${g.disk_bytes}')
	if target.id.bytes != g.disk_bytes {
		return error('target geometry must exactly match the planned disk length')
	}
	source_id := required(o, 'source-image-id')!
	if !hex_text(source_id, 16) {
		return error('require --source-image-id=16lowerhex (operator assertion)')
	}
	println('source-image-id=${source_id} (OPERATOR ASSERTION; host does not read VJFS inodes)')
	validate_root(source.fd, 0, source.id.bytes)!
	if read_at(source.fd, 0, 512)!.any(it != 0) {
		return error('source pre-superblock marker area must be zero')
	}
	blank(target)!
	work := temporary(os.dir(target.path))!
	defer { os.rmdir_all(work) or {} }
	bundle_dir := work + '/bundle'
	trusted := required(o, 'bundle-sha256')!
	b := bundle_snapshot(required(o, 'bundle')!, trusted, bundle_dir)!
	token := random_token()!
	checkpoint(o, 'validated')!
	stage := work + '/disk.img'
	fd := fresh_file(stage, g.disk_bytes)!
	defer { C.close(fd) }
	write_gpt(fd, g, token)!
	root_hash := clone_range(source.fd, 0, fd, root_start, source.id.bytes)!
	if hash_range(fd, root_start, source.id.bytes)! != root_hash
		|| hash_range(source.fd, 0, source.id.bytes)! != root_hash {
		return error('source/clone mismatch')
	}
	source.unchanged()!
	write_at(fd, root_start, marker(token, source.id.bytes, source_id)!)!
	checkpoint(o, 'root-copied')!
	esp := work + '/esp.img'
	config_hash := stage_esp(esp, work, bundle_dir, trusted, token, source_id, true, o)!
	esp_hash := replace_esp(fd, esp)!
	m := Ownership{
		geometry:      g
		token:         token
		bootstrap_id:  source_id
		generation:    trusted
		generations:   [trusted]
		image_ids:     [b.image_id]
		predecessor:   source_id
		bundle:        b
		config_sha256: config_hash
		esp_sha256:    esp_hash
	}
	write_at(fd, meta_at, ownership_bytes(m)!)!
	verify_gpt(fd, g, token)!
	validate_root(fd, root_start, source.id.bytes)!
	if read_at(fd, root_start, 512)! != marker(token, source.id.bytes, source_id)! {
		return error('staged root marker mismatch')
	}
	activate(stage, fd, target, source, o)!
}

fn update(o map[string]string) ! {
	check_failpoints(o)!
	target := locked(required(o, 'target')!)!
	defer { target.close() }
	confirm(target, o)!
	offline(target)!
	old := read_ownership(target)!
	println('root-bytes=${old.geometry.root_bytes}\nactive=${old.generation}\nprior=${old.prior_generation}\nroot-token=${old.token}')
	work := temporary(os.dir(target.path))!
	defer { os.rmdir_all(work) or {} }
	bundle_dir := work + '/bundle'
	trusted := required(o, 'bundle-sha256')!
	b := bundle_snapshot(required(o, 'bundle')!, trusted, bundle_dir)!
	transition(old, trusted, b)!
	esp := work + '/esp.img'
	extract_esp(target, esp)!
	check_old_config(esp, work, old)!
	if trusted == old.generation {
		offline(target)!
		println('already active: verified no-op')
		return
	}
	checkpoint(o, 'validated')!
	stage := work + '/disk.img'
	fd := fresh_file(stage, target.id.bytes)!
	defer { C.close(fd) }
	disk_hash := clone_range(target.fd, 0, fd, 0, target.id.bytes)!
	if hash_range(fd, 0, target.id.bytes)! != disk_hash || hash_range(target.fd, 0, target.id.bytes)! != disk_hash {
		return error('target changed or full staged disk copy failed')
	}
	root_hash := hash_range(target.fd, root_start, old.geometry.root_bytes)!
	checkpoint(o, 'root-copied')!
	config_hash := stage_esp(esp, work, bundle_dir, trusted, old.token, old.bundle.image_id, false, o)!
	esp_hash := replace_esp(fd, esp)!
	mut generations := old.generations.clone()
	generations << trusted
	mut image_ids := old.image_ids.clone()
	image_ids << b.image_id
	m := Ownership{
		geometry:         old.geometry
		token:            old.token
		bootstrap_id:     old.bootstrap_id
		generation:       trusted
		prior_generation: old.generation
		generations:      generations
		image_ids:        image_ids
		predecessor:      old.bundle.image_id
		bundle:           b
		config_sha256:    config_hash
		esp_sha256:       esp_hash
	}
	write_at(fd, meta_at, ownership_bytes(m)!)!
	verify_gpt(fd, old.geometry, old.token)!
	if hash_range(fd, root_start, old.geometry.root_bytes)! != root_hash
		|| hash_range(target.fd, root_start, old.geometry.root_bytes)! != root_hash {
		return error('update changed root contents')
	}
	// Prior generation bytes remain in the copied FAT. Verify that ownership
	// again using a separate output directory, after the new FAT is complete.
	prior_work := work + '/prior-check'
	os.mkdir(prior_work)!
	for name in payloads {
		out := prior_work + '/' + name
		native(['mcopy', '-i', esp, '::/boot/g-' + old.generation + '/' + name, out])!
		if digest(out)! != old.bundle.files[name] {
			return error('prior generation was not preserved')
		}
	}
	native(['mcopy', '-i', esp, '::/boot/g-' + old.generation + '/manifest.json',
		prior_work + '/manifest.json'])!
	if digest(prior_work + '/manifest.json')! != old.generation {
		return error('prior manifest was not preserved')
	}
	activate(stage, fd, target, none, o)!
}
