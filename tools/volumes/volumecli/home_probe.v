// SPDX-License-Identifier: GPL-2.0-or-later
module volumecli

// Compiled only into the explicit test build. It creates no socket pathname,
// disk file or environment credential and never emits a secret or key.
$if home_guest_probe ? {
@[direct_array_access]
fn home_probe_client(fd i32, phase int, phrase &u8, size int) bool {
	mut reply := unsafe { &HomeFrame(C.alloca(sizeof(HomeFrame))) }
	unsafe { *reply = HomeFrame{} }
	mut payload := [261]u8{}
	defer { erase_key(reply, sizeof(HomeFrame)); erase_key(&payload[0], sizeof(payload)) }
	if phase == 0 {
		if !home_send(fd, 2, unsafe { nil }, 0) || !home_receive(fd, mut reply) || reply.op != 2 || reply.size > 128 { return false }
		n := reply.size
		put_le(&payload[0], 0, 2, u64(n)); put_le(&payload[0], 2, 2, 14); payload[4] = 1
		unsafe { C.memcpy(&payload[5], &reply.bytes[0], n); C.memcpy(&payload[5 + n], c'Guest Password', 14) }
		return home_send(fd, 3, &payload[0], 5 + n + 14) && home_receive(fd, mut reply) && reply.op == 3
	}
	if phase == 1 {
		for mode in [u32(4), u32(5), u32(4)]! {
			if !home_send(fd, mode, unsafe { &u8(c'wrong') }, 5) || !home_receive(fd, mut reply) || reply.op != 0 { return false }
		}
		return true
	}
	if phase == 2 { return home_send(fd, 4, phrase, size) && home_receive(fd, mut reply) && reply.op == 0 }
	if phase == 3 { return home_send(fd, 5, unsafe { &u8(c'Guest Password') }, 14) && home_receive(fd, mut reply) && reply.op == 3 }
	return home_send(fd, 4, phrase, size) && home_receive(fd, mut reply) && reply.op == 3
}

fn home_probe_round(mut state HomeSupervisor, phase int) bool {
	mut pair := [2]i32{}
	if C.socketpair(C.AF_UNIX, C.SOCK_STREAM, 0, &pair[0]) != 0 { return false }
	child := C.fork()
	if child == 0 {
		C.close(pair[0])
		ok := home_probe_client(pair[1], phase, &state.phrase[0], state.phrase_size)
		C.close(pair[1]); erase_key(&state, sizeof(state)); C._exit(if ok { 0 } else { 1 })
	}
	C.close(pair[1]); if child < 0 { C.close(pair[0]); return false }
	passed := home_serve(pair[0], mut state)
	C.close(pair[0]); mut status := i32(0)
	if C.waitpid(child, &status, 0) != child { return false }
	return status == 0 && passed == (phase == 0 || phase >= 3)
}

fn home_probe() i32 {
	if C.geteuid() != 0 { return 1 }
	limit := C.rlimit{}
	if C.setrlimit(C.RLIMIT_CORE, &limit) != 0 { return 1 }
	mut state := unsafe { &HomeSupervisor(C.alloca(sizeof(HomeSupervisor))) }
	unsafe { *state = HomeSupervisor{fresh: true, bytes: 128 * 1024 * 1024, sector: 512} }
	defer { erase_key(state, sizeof(HomeSupervisor)) }
	if !home_prepare(mut state, home_entropy) { return 1 }
	if !home_probe_round(mut state, 0) || state.phase != .mounting { return 1 }
	mut expected := state.key
	defer { erase_key(&expected[0], 64) }
	state.phase = .locked; erase_key(&state.key[0], 64)
	if !home_probe_round(mut state, 1) || state.budget.failures != 3
		|| !home_probe_round(mut state, 2) || state.phase != .locked { return 1 }
	C.sleep(3)
	if !home_probe_round(mut state, 3) || state.key != expected { return 1 }
	state.phase = .locked; state.budget = HomeBudget{}; erase_key(&state.key[0], 64)
	if !home_probe_round(mut state, 4) || state.key != expected { return 1 }
	C.printf(c'HOME-PROBE: private protocol, dual-slot equality, shared rate and UI replacement PASS\n')
	return 0
}
}
