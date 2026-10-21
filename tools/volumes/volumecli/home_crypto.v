// SPDX-License-Identifier: GPL-2.0-or-later
module volumecli

// Narrow in-memory API. Caller owns and erases credentials, random material
// and returned data keys. No path, CLI argument or diagnostic accepts a key.
pub fn home_wrap(disk_bytes u64, sector u64, identity &u8, key &u8,
	credential &u8, size int, random &u8, output &u8) bool {
	mut wrapping := [64]u8{}
	defer { erase_key(&wrapping[0], sizeof(wrapping)) }
	mut disk := unsafe { &DiskKey(C.alloca(sizeof(DiskKey))) }
	mut request := unsafe { &EncryptedRequest(C.alloca(sizeof(EncryptedRequest))) }
	unsafe { *disk = DiskKey{bytes: disk_bytes, sector: sector, kind: 2}
		*request = EncryptedRequest{data: Request{slot: 63, offset: home_data_offset, length: disk_bytes - home_data_offset}} }
	defer { erase_key(request, sizeof(EncryptedRequest)) }
	unsafe { C.memcpy(&disk.id[0], identity, 16); C.memcpy(&request.key[0], key, 64) }
	if disk_bytes <= home_data_offset || !sealed_derive(credential, size, random, &wrapping[0]) { return false }
	return encode_volume_seal(disk, request, &wrapping[0], random, output)
}

pub fn home_unwrap(envelope &u8, credential &u8, size int, output &u8) bool {
	mut wrapping := [64]u8{}
	mut disk := unsafe { &DiskKey(C.alloca(sizeof(DiskKey))) }
	mut request := unsafe { &EncryptedRequest(C.alloca(sizeof(EncryptedRequest))) }
	unsafe { *disk = DiskKey{}; *request = EncryptedRequest{} }
	defer { erase_key(&wrapping[0], sizeof(wrapping)); erase_key(request, sizeof(EncryptedRequest)) }
	if !volume_seal_header(envelope, 320)
		|| !sealed_derive(credential, size, unsafe { envelope + 40 }, &wrapping[0])
		|| !decode_volume_seal(envelope, 320, &wrapping[0], mut disk, mut request) { return false }
	unsafe { C.memcpy(output, &request.key[0], 64) }
	return true
}
