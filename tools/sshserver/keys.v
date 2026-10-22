// SPDX-License-Identifier: GPL-2.0-or-later
module main

import encoding.base64
import os
import tools.packages.signing

const seed_header = 'Vinix SSH Ed25519 seed v1\n'

fn public_blob(key []u8) []u8 {
	mut blob := []u8{}
	put_string(mut blob, 'ssh-ed25519'.bytes())
	put_string(mut blob, key)
	return blob
}

fn parse_public(blob []u8) ![]u8 {
	mut r := Reader{ data: blob }
	if r.string_bytes(32)!.bytestr() != 'ssh-ed25519' { return error('unsupported public key') }
	key := r.string_bytes(32)!
	if key.len != 32 { return error('invalid public key size') }
	r.end()!
	return key
}

fn secure_regular(fd int, max_size i64) !C.stat {
	mut s := C.stat{}
	if C.fstat(fd, &s) != 0 || C.S_ISREG(s.st_mode) == 0 || s.st_mode & 0o077 != 0
		|| s.st_uid != C.getuid() || s.st_size < 0 || s.st_size > max_size {
		return error('unsafe file owner/mode/type/size')
	}
	return s
}

fn load_host_key(path string) !signing.PrivateKey {
	name := os.file_name(path)
	if name == '' || name in ['.', '..'] { return error('invalid host key path') }
	dir := open_directory(os.dir(path))!
	defer { C.close(dir) }
	mut directory_info := C.stat{}
	if C.fstat(dir, &directory_info) != 0 || directory_info.st_uid != C.getuid() || directory_info.st_mode & 0o022 != 0 {
		return error('unsafe host key directory owner/mode')
	}
	mut fd := C.openat(dir, name.str, C.O_RDONLY | C.O_NOFOLLOW | C.O_CLOEXEC | C.O_NONBLOCK)
	if fd < 0 {
		if C.errno != C.ENOENT { return error('cannot open host key') }
		mut data := seed_header.bytes()
		data << entropy(32)!
		temporary := '.vinix-sshd-${C.getpid()}-${entropy(8)!.hex()}'
		out := C.openat(dir, temporary.str, C.O_WRONLY | C.O_CREAT | C.O_EXCL | C.O_NOFOLLOW | C.O_CLOEXEC, u32(0o600))
		if out < 0 { return error('cannot create host seed') }
		defer {
			C.close(out)
			C.unlinkat(dir, temporary.str, 0)
		}
		write_fd(out, data)!
		if C.fchmod(out, 0o600) != 0 || C.fsync(out) != 0 { return error('host seed fsync/mode') }
		if C.linkat(dir, temporary.str, dir, name.str, 0) != 0 && C.errno != C.EEXIST {
			return error('publish host seed')
		}
		if C.fsync(dir) != 0 { return error('host directory fsync') }
		fd = C.openat(dir, name.str, C.O_RDONLY | C.O_NOFOLLOW | C.O_CLOEXEC | C.O_NONBLOCK)
	}
	if fd < 0 { return error('cannot reopen host seed') }
	defer { C.close(fd) }
	s := secure_regular(fd, 128)!
	if s.st_size != seed_header.len + 32 { return error('malformed host seed') }
	data := read_exact_fd(fd, int(s.st_size))!
	if data[..seed_header.len].bytestr() != seed_header { return error('unknown seed format') }
	return signing.new_key_from_seed(data[seed_header.len..])
}

fn authorized_keys(home string) ![][]u8 {
	homefd := open_directory(home)!
	defer { C.close(homefd) }
	mut st := C.stat{}
	if C.fstat(homefd, &st) != 0 || st.st_uid != C.getuid() || st.st_mode & 0o022 != 0 {
		return error('unsafe home')
	}
	dir := C.openat(homefd, c'.ssh', C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW | C.O_CLOEXEC)
	if dir < 0 { return error('missing .ssh') }
	defer { C.close(dir) }
	if C.fstat(dir, &st) != 0 || st.st_uid != C.getuid() || st.st_mode & 0o022 != 0 {
		return error('unsafe .ssh')
	}
	fd := C.openat(dir, c'authorized_keys', C.O_RDONLY | C.O_NOFOLLOW | C.O_CLOEXEC | C.O_NONBLOCK)
	if fd < 0 { return error('missing authorized_keys') }
	defer { C.close(fd) }
	s := secure_regular(fd, 65536)!
	return parse_authorized(read_exact_fd(fd, int(s.st_size))!.bytestr())!
}

fn parse_authorized(contents string) ![][]u8 {
	if contents.len > 65536 || contents.contains('\x00') { return error('invalid authorized_keys') }
	mut keys := [][]u8{}
	for line in contents.split_into_lines() {
		text := line.trim_space()
		if text == '' || text.starts_with('#') { continue }
		fields := text.fields()
		// Fail the entire file closed if restrictions or other key types occur.
		if fields.len < 2 || fields[0] != 'ssh-ed25519' || fields[1].len > 128 {
			return error('authorized_keys options/types unsupported')
		}
		blob := base64.decode(fields[1])
		_ := parse_public(blob)!
		if base64.encode(blob) != fields[1] { return error('noncanonical public key base64') }
		keys << blob
		if keys.len > 128 { return error('too many authorized keys') }
	}
	return keys
}
