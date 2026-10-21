// SPDX-License-Identifier: GPL-2.0-or-later
module volumecli

#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <signal.h>
#include <time.h>
#include <stdlib.h>

fn C.socketpair(i32, i32, i32, &i32) i32
fn C.getsockopt(i32, i32, i32, voidptr, &u32) i32
fn C.getpeereid(i32, &u32, &u32) i32
fn C.fork() i32
fn C.waitpid(i32, &i32, i32) i32
fn C.execv(&char, &&char) i32
fn C._exit(i32)
fn C.kill(i32, i32) i32
fn C.fcntl(i32, i32, ...voidptr) i32
fn C.pwrite(i32, voidptr, usize, i64) i64
fn C.clock_gettime(i32, &C.timespec) i32
fn C.chdir(&char) i32
fn C.mkdir(&char, u32) i32
fn C.setenv(&char, &char, i32) i32
fn C.setrlimit(i32, &C.rlimit) i32
fn C.signal(i32, voidptr) voidptr
fn C.sleep(u32) u32

struct C.rlimit { rlim_cur u64 rlim_max u64 }
struct HomePeer { pid i32 uid u32 gid u32 }

struct HomeFrame {
mut:
	op u32
	size int
	bytes [1024]u8
}

struct HomeSupervisor {
mut:
	phase HomePhase = .locked
	budget HomeBudget
	header [4096]u8
	key [64]u8
	phrase [128]u8
	phrase_size int
	random [56]u8
	bytes u64
	sector u64
	fresh bool
}

fn home_entropy(output &u8, size int) bool {
	$if home_entropy_failure ? { return false }
	return key_random_bytes(output, size)
}

fn home_prepare(mut state HomeSupervisor, entropy fn (&u8, int) bool) bool {
	mut random := [24]u8{}
	defer { erase_key(&random[0], sizeof(random)) }
	if state.phase != .locked || !state.fresh
		|| !entropy(&state.key[0], 64) || !entropy(&random[0], 24)
		|| !entropy(&state.header[48], 16) || !entropy(&state.random[0], 56)
		|| recovery_equal(&state.key[0], &state.key[32], 32) {
		erase_key(&state.key[0], 64); state.phase = .failed; return false
	}
	state.phrase_size = home_phrase(&random, &state.phrase[0])
	state.phase = .enrollment
	return state.phrase_size > 0
}

fn home_enroll(mut state HomeSupervisor, confirmation &u8, size int, password &u8, password_size int, acknowledged bool) bool {
	if state.phase != .enrollment || !acknowledged || password_size < 0 || password_size > 128 { return false }
	mut normalized := [128]u8{}
	mut check := [64]u8{}
	defer { erase_key(&normalized[0], 128); erase_key(&check[0], 64) }
	n := home_normalize(confirmation, size, &normalized[0])
	if n != state.phrase_size || !recovery_equal(&normalized[0], &state.phrase[0], n) { return false }
	unsafe { C.memcpy(&state.header[0], c'VINIXHM1', 8) }
	put_le(&state.header[0], 8, 4, 1); state.header[12] = if password_size == 0 { u8(1) } else { u8(2) }
	put_le(&state.header[0], 16, 8, state.bytes); put_le(&state.header[0], 24, 8, state.sector)
	put_le(&state.header[0], 32, 8, home_data_offset); put_le(&state.header[0], 40, 8, state.bytes - home_data_offset)
	if !home_wrap(state.bytes, state.sector, &state.header[48], &state.key[0],
		&state.phrase[0], state.phrase_size, &state.random[0], &state.header[128]) { return false }
	if password_size > 0 {
		if !home_wrap(state.bytes, state.sector, &state.header[48], &state.key[0],
			password, password_size, &state.random[28], &state.header[448])
			|| !home_unwrap(&state.header[448], password, password_size, &check[0])
			|| !recovery_equal(&check[0], &state.key[0], 64) { return false }
	}
	if !home_header_valid(&state.header, state.bytes, state.sector) { return false }
	state.phase = .mounting
	return true
}

fn home_unlock(mut state HomeSupervisor, credential &u8, size int, password bool, now i64) bool {
	if state.phase != .locked || !state.budget.allowed(now) { return false }
	mut normalized := [128]u8{}
	defer { erase_key(&normalized[0], 128) }
	count := if password { size } else { home_normalize(credential, size, &normalized[0]) }
	input := if password { credential } else { unsafe { &normalized[0] } }
	slot := if password { 448 } else { 128 }
	valid := count > 0 && count <= 128 && (!password || state.header[12] == 2)
		&& home_header_valid(&state.header, state.bytes, state.sector)
		&& home_unwrap(unsafe { &state.header[slot] }, input, count, &state.key[0])
	if !valid { erase_key(&state.key[0], 64); state.budget.reject(now); return false }
	state.phase = .mounting
	return true
}

fn home_now() i64 {
	mut stamp := C.timespec{}
	if C.clock_gettime(C.CLOCK_MONOTONIC, &stamp) != 0 { return -1 }
	return stamp.tv_sec
}

fn home_transfer(fd i32, data &u8, size int, writing bool) bool {
	mut done := 0
	for done < size {
		n := if writing { C.write(fd, unsafe { data + done }, usize(size - done)) }
			else { C.read(fd, unsafe { data + done }, usize(size - done)) }
		if n < 0 && unsafe { C.errno == C.EINTR } { continue }
		if n <= 0 || n > size - done { return false }; done += int(n)
	}
	return true
}

fn home_receive(fd i32, mut frame HomeFrame) bool {
	mut header := [8]u8{}
	if !home_transfer(fd, &header[0], 8, false) { return false }
	frame.op = u32(get_le(&header[0], 0, 4)); frame.size = int(get_le(&header[0], 4, 4))
	return frame.size >= 0 && frame.size <= 1024 && home_transfer(fd, &frame.bytes[0], frame.size, false)
}

fn home_send(fd i32, op u32, bytes &u8, size int) bool {
	if size < 0 || size > 1024 { return false }
	mut header := [8]u8{}
	put_le(&header[0], 0, 4, op); put_le(&header[0], 4, 4, u64(size))
	return home_transfer(fd, &header[0], 8, true) && home_transfer(fd, bytes, size, true)
}

fn home_peer_root(fd i32) bool {
	$if macos {
		mut uid := u32(-1); mut gid := u32(-1)
		return C.getpeereid(fd, &uid, &gid) == 0 && uid == 0
	} $else {
		mut peer := HomePeer{}; mut size := u32(sizeof(HomePeer))
		return C.getsockopt(fd, C.SOL_SOCKET, 17, &peer, &size) == 0 && size == sizeof(HomePeer) && peer.uid == 0
	}
}

// No listener or rendezvous path exists. Only the explicitly inherited
// descriptor is accepted, and both endpoints require kernel root credentials.
fn home_serve(fd i32, mut state HomeSupervisor) bool {
	if !home_peer_root(fd) { return false }
	mut frame := unsafe { &HomeFrame(C.alloca(sizeof(HomeFrame))) }
	unsafe { *frame = HomeFrame{} }
	defer { erase_key(frame, sizeof(HomeFrame)) }
	for home_receive(fd, mut frame) {
		mut answer := u32(0)
		if frame.op == 1 && frame.size == 0 {
			answer = if state.phase == .enrollment { u32(2) } else if state.phase == .locked { u32(1) } else { u32(0) }
		} else if frame.op == 2 && frame.size == 0 && state.phase == .enrollment {
			if !home_send(fd, 2, &state.phrase[0], state.phrase_size) { return false }
			continue
		} else if frame.op == 3 && frame.size >= 5 {
			n := int(get_le(&frame.bytes[0], 0, 2)); p := int(get_le(&frame.bytes[0], 2, 2))
			if n <= 128 && p <= 128 && frame.size == n + p + 5
				&& home_enroll(mut state, &frame.bytes[5], n, unsafe { &frame.bytes[5 + n] }, p, frame.bytes[4] == 1) { answer = 3 }
		} else if frame.op == 4 || frame.op == 5 {
			if home_unlock(mut state, &frame.bytes[0], frame.size, frame.op == 5, home_now()) { answer = 3 }
		}
		erase_key(&frame.bytes[0], 1024)
		if !home_send(fd, answer, unsafe { nil }, 0) { return false }
		if answer == 3 { return true }
	}
	return false
}
