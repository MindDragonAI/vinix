module main

import crypto.sha256
import json2
import os

const payloads = ['BOOTX64.EFI', 'vinix', 'initramfs.tar.gz', 'limine.conf']
const iso_paths = ['/EFI/BOOT/BOOTX64.EFI', '/boot/vinix', '/boot/initramfs.tar.gz', '/boot/limine.conf']

struct Bundle {
	schema                 int = 1
	iso_sha256             string
	kernel_override_sha256 string
	image_id               string
	files                  map[string]string
}

fn template() string {
	return 'timeout: 0\nverbose: yes\n\n/Vinix\n    protocol: limine\n    kernel_path: boot():/boot/vinix\n    module_path: boot():/boot/initramfs.tar.gz\n    resolution: 1024x768x32\n    kaslr: no\n'
}

fn config(generation string, token string, predecessor string) !string {
	if !hex_text(generation, 64) || !hex_text(token, 32) || !hex_text(predecessor, 16) {
		return error('invalid configuration fields')
	}
	return template().replace('/boot/vinix', '/boot/g-' + generation + '/vinix')
		.replace('/boot/initramfs.tar.gz', '/boot/g-' + generation + '/initramfs.tar.gz') +
		'    cmdline: vinix.disk=auto vinix.sysroot=${token} vinix.disk_from=${predecessor}\n'
}

fn kernel_header(b []u8) ! {
	if b.len < 64 || b[..4] != [u8(0x7f), `E`, `L`, `F`] || b[4] != 2 || b[5] != 1
		|| get(b, 18, 2) != 62 || get(b, 16, 2) !in [u64(2), 3] {
		return error('kernel must be a little-endian ELF64 amd64 executable')
	}
}

fn efi_header(b []u8) ! {
	if b.len < 64 || b[..2].bytestr() != 'MZ' { return error('EFI loader must be PE amd64') }
	at := get(b, 60, 4)
	if at > u64(b.len) || u64(b.len) - at < 94 { return error('truncated PE header') }
	p := int(at)
	if b[p..p + 4] != [u8(`P`), `E`, 0, 0] || get(b, p + 4, 2) != 0x8664
		|| get(b, p + 24, 2) != 0x20b || get(b, p + 24 + 68, 2) != 10 {
		return error('loader must be PE32+ amd64 EFI application')
	}
}

fn gzip_id(b []u8) !string {
	// Repository ISO builders use gzip -n plus exactly one FCOMMENT. Accept
	// only that header profile, with precisely sixteen lower-case hexadecimal digits.
	label := 'vinix-image-id='
	end := 10 + label.len + 16
	if b.len < end + 9 || b[..4] != [u8(0x1f), 0x8b, 8, 0x10]
		|| b[10..10 + label.len].bytestr() != label || b[end] != 0 {
		return error('gzip must carry the exact vinix-image-id=16lowerhex comment')
	}
	id := b[10 + label.len..end].bytestr()
	if !hex_text(id, 16) { return error('invalid gzip image id') }
	return id
}

fn prefix(path string, limit int) ![]u8 {
	f := locked(path)!
	defer { f.close() }
	return read_at(f.fd, 0, int(if f.id.bytes < limit { f.id.bytes } else { i64(limit) }))!
}

fn check_payloads(path string) !string {
	mut total := i64(0)
	for name in payloads {
		size := regular(path + '/' + name)!.bytes
		if size <= 0 || size >= 0xffffffff {
			return error('empty or FAT32-oversize payload: ${name}')
		}
		total += size
	}
	if total > esp_bytes - 16 * mib { return error('bundle too large for the 1 GiB ESP') }
	kernel_header(prefix(path + '/vinix', 64)!)!
	efi_header(prefix(path + '/BOOTX64.EFI', 65536)!)!
	id := gzip_id(prefix(path + '/initramfs.tar.gz', 4096)!)!
	text := os.read_file(path + '/limine.conf')!
	if text != template() && text != template() + '    cmdline: vinix.disk=auto\n' {
		return error('ISO configuration is not the vetted literal amd64 template (extra directives/cmdline refused)')
	}
	native(['gzip', '-t', '--', path + '/initramfs.tar.gz'])!
	archived_id := native_output(['tar', '-xOzf', path + '/initramfs.tar.gz', './.vinix-image-id'], 4096)!
	if archived_id != id + '\n' {
		return error('gzip comment and archived ./.vinix-image-id disagree (or duplicate/missing marker)')
	}
	return id
}

fn snapshot_file(source string, output string) !string {
	f := locked(source)!
	defer { f.close() }
	fd := fresh_file(output, f.id.bytes)!
	defer { C.close(fd) }
	hash := clone_range(f.fd, 0, fd, 0, f.id.bytes)!
	if hash_range(fd, 0, f.id.bytes)! != hash { return error('snapshot copy verification failed') }
	f.unchanged()!
	durable(fd)!
	return hash
}

fn bundle_build(o map[string]string) ! {
	iso := required(o, 'iso')!
	pin := required(o, 'iso-sha256')!
	output := required(o, 'output')!
	if !hex_text(pin, 64) { return error('require full lower-case ISO SHA-256') }
	absolute(output)!
	if os.exists(output) || os.is_link(output) { return error('bundle output must not exist') }
	input := locked(iso)!
	defer { input.close() }
	if hash_range(input.fd, 0, input.id.bytes)! != pin { return error('ISO checksum mismatch') }
	work := temporary(os.dir(output))!
	defer { os.rmdir_all(work) or {} }
	stage := work + '/bundle'
	os.mkdir(stage, mode: 0o700)!
	for i, name in payloads {
		native(['xorriso', '-osirrox', 'on', '-indev', iso, '-extract', iso_paths[i],
			stage + '/' + name])!
		regular(stage + '/' + name)!
	}
	mut override_hash := ''
	if 'kernel' in o || 'kernel-sha256' in o {
		kernel := required(o, 'kernel')!
		override_hash = required(o, 'kernel-sha256')!
		if !hex_text(override_hash, 64) { return error('invalid override SHA-256') }
		os.rm(stage + '/vinix')!
		if snapshot_file(kernel, stage + '/vinix')! != override_hash {
			return error('kernel override checksum mismatch')
		}
	}
	id := check_payloads(stage)!
	mut hashes := map[string]string{}
	for name in payloads { hashes[name] = digest(stage + '/' + name)! }
	manifest := Bundle{ iso_sha256: pin, kernel_override_sha256: override_hash, image_id: id, files: hashes }
	text := json2.encode(manifest) + '\n'
	os.write_file(stage + '/manifest.json', text)!
	input.unchanged()!
	if hash_range(input.fd, 0, input.id.bytes)! != pin {
		return error('ISO changed during extraction')
	}
	if os.exists(output) || os.is_link(output) {
		return error('bundle output appeared during extraction')
	}
	if C.rename(stage.str, output.str) != 0 { return error('cannot publish bundle') }
	println('bundle=${output}\nmanifest-sha256=${sha256.sum(text.bytes()).hex()}\nimage-id=${id}')
	println('Checksums identify content; obtain/trust the manifest hash independently. They do not authenticate this bundle.')
}

fn bundle_shape(b Bundle) ! {
	if b.schema != 1 || !hex_text(b.iso_sha256, 64) || !hex_text(b.image_id, 16)
		|| (b.kernel_override_sha256 != '' && !hex_text(b.kernel_override_sha256, 64))
		|| b.files.len != payloads.len {
		return error('invalid bundle manifest schema')
	}
	for name in payloads {
		if !hex_text(b.files[name], 64) { return error('missing/invalid payload hash: ${name}') }
	}
	if b.kernel_override_sha256 != '' && b.kernel_override_sha256 != b.files['vinix'] {
		return error('override hash not bound to kernel')
	}
}

// Copy to a private, closed input set before any helper reads it. The caller's
// trusted manifest digest binds every copied byte, including the override.
fn bundle_snapshot(source string, trusted string, destination string) !Bundle {
	absolute(source)!
	if os.real_path(source) != source || !os.is_dir(source) {
		return error('bundle must be a real directory')
	}
	if !hex_text(trusted, 64) {
		return error('require --bundle-sha256 with independently trusted manifest SHA-256')
	}
	entries := os.ls(source)!
	if entries.len != 5 || entries.any(it !in payloads && it != 'manifest.json') {
		return error('unexpected bundle files')
	}
	os.mkdir(destination, mode: 0o700)!
	if snapshot_file(source + '/manifest.json', destination + '/manifest.json')! != trusted {
		return error('trusted bundle manifest checksum mismatch')
	}
	if regular(destination + '/manifest.json')!.bytes > 16384 { return error('oversize manifest') }
	text := os.read_file(destination + '/manifest.json')!
	b := json2.decode[Bundle](text, strict: true)!
	bundle_shape(b)!
	if text != json2.encode(b) + '\n' {
		return error('bundle manifest must use canonical selfboot encoding')
	}
	for name in payloads {
		if snapshot_file(source + '/' + name, destination + '/' + name)! != b.files[name] {
			return error('corrupt bundle payload: ${name}')
		}
	}
	if check_payloads(destination)! != b.image_id {
		return error('manifest and gzip image id disagree')
	}
	return b
}
