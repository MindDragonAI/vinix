// SPDX-License-Identifier: GPL-2.0-or-later
module volumecli

#include <sys/mount.h>
fn C.mount(&char, &char, &char, u64, voidptr) i32
fn C.chmod(&char, u32) i32
fn C.setpgid(i32, i32) i32

fn home_mount() bool {
	$if macos { return false } $else {
		return C.mount(c'/dev/mapper/vinix63', c'/root', c'ext2', 0, unsafe { nil }) == 0
	}
}

fn home_private_scratch() bool {
	$if macos { return false } $else {
		// Application temporary files must never spill onto the public boot
		// disk. The kernel's RAM pager already encrypts its disk backing.
		if C.mount(c'tmpfs', c'/tmp', c'tmpfs', 0, unsafe { nil }) != 0 { return false }
		return C.chmod(c'/tmp', u32(0o1777)) == 0
	}
}

fn home_disk_read(fd i32, output &u8, size int, offset u64) bool {
	mut done := 0
	for done < size {
		n := C.pread(fd, unsafe { output + done }, usize(size - done), i64(offset) + done)
		if n < 0 && unsafe { C.errno == C.EINTR } { continue }
		if n <= 0 || n > size - done { return false }; done += int(n)
	}
	return true
}

@[direct_array_access]
fn home_blank(fd i32, bytes u64) bool {
	mut buffer := [65536]u8{}
	mut at := u64(0)
	for at < bytes {
		n := int(if bytes - at < 65536 { bytes - at } else { u64(65536) })
		if !home_disk_read(fd, &buffer[0], n, at) { return false }
		for i in 0 .. n { if buffer[i] != 0 { return false } }
		at += u64(n)
	}
	return true
}

fn home_publish(fd i32, header &[4096]u8) bool {
	mut done := 0
	for done < 4096 {
		n := C.pwrite(fd, unsafe { &header[done] }, usize(4096 - done), done)
		if n < 0 && unsafe { C.errno == C.EINTR } { continue }
		if n <= 0 || n > 4096 - done { return false }; done += int(n)
	}
	return C.fsync(fd) == 0
}

fn home_activate(fd i32, mut state HomeSupervisor) bool {
	if state.phase != .mounting { return home_activation_failed('phase') }
	mut request := unsafe { &EncryptedRequest(C.alloca(sizeof(EncryptedRequest))) }
	unsafe { *request = EncryptedRequest{data: Request{slot: 63, offset: home_data_offset, length: state.bytes - home_data_offset}}
		C.memcpy(&request.key[0], &state.key[0], 64) }
	defer { erase_key(request, sizeof(EncryptedRequest)) }
	if C.ioctl(fd, u64(0x56560006), request) != 0 { return home_activation_failed('import') }
	mapper := C.open(c'/dev/mapper/vinix63', C.O_RDWR | C.O_CLOEXEC | C.O_NOFOLLOW)
	if mapper < 0 { return home_activation_failed('mapper-open') }
	defer { C.close(mapper) }
	if state.fresh && C.ioctl(mapper, u64(0x56560007), unsafe { nil }) != 0 { return home_activation_failed('format') }
	// Raw writes to a whole disk are forbidden after any overlapping mount.
	// Publish only after formatting/barriers, but before that first mount.
	// A power loss here leaves either an empty provisioned home or a rejected
	// incomplete enrollment, never pre-existing user data without a key slot.
	if state.fresh && C.fsync(mapper) != 0 { return home_activation_failed('mapper-sync') }
	if state.fresh && !home_publish(fd, &state.header) { return home_activation_failed('publish') }
	// /root must be covered before creating any profile or launching a session.
	if C.chdir(c'/') != 0 { return home_activation_failed('chdir') }
	if !home_mount() { return home_activation_failed('mount') }
	// Also completes a boot interrupted after header publication but before
	// the first profile marker was committed inside the encrypted volume.
	existing := C.open(c'/root/.vinix-encrypted-home', C.O_RDONLY | C.O_CLOEXEC | C.O_NOFOLLOW)
	if existing >= 0 { C.close(existing) }
	else {
		if unsafe { C.errno != C.ENOENT } { return home_activation_failed('marker-lookup') }
		marker := C.open(c'/root/.vinix-encrypted-home', C.O_WRONLY | C.O_CREAT | C.O_EXCL | C.O_CLOEXEC | C.O_NOFOLLOW, u32(0o600))
		if marker < 0 { return home_activation_failed('marker-open') }
		ok := home_transfer(marker, unsafe { &u8(c'Vinix encrypted home v1\n') }, 24, true) && C.fsync(marker) == 0
		C.close(marker)
		if !ok { return home_activation_failed('marker-write-sync') }
		if C.fsync(mapper) != 0 { return home_activation_failed('marker-mapper-sync') }
	}
	state.phase = .session
	erase_key(&state.phrase[0], 128); erase_key(&state.random[0], 56)
	return true
}

fn home_spawn_ui(mut state HomeSupervisor) i32 {
	home_session_note(c'HOME-UI: budget failures=%d\n', i32(state.budget.failures))
	mut pair := [2]i32{}
	if C.socketpair(C.AF_UNIX, C.SOCK_STREAM, 0, &pair[0]) != 0 { return -1 }
	child := C.fork()
	if child == 0 {
		// Never leave the supervisor's data key in the replacement UI image.
		home_erase_state(mut state); C.close(pair[0])
		mut descriptor := [24]char{}
		C.snprintf(&descriptor[0], 24, c'%d', pair[1])
		args := [&char(c'/usr/libexec/vinix-home-gate'), &char(c'--ui'), unsafe { &descriptor[0] }, unsafe { &char(nil) }]!
		C.execv(args[0], unsafe { &&char(&args[0]) }); C._exit(127)
	}
	C.close(pair[1])
	if child < 0 { C.close(pair[0]); return -1 }
	C.fcntl(pair[0], C.F_SETFD, C.FD_CLOEXEC)
	passed := home_serve(pair[0], mut state)
	C.close(pair[0]); if !passed { C.kill(child, C.SIGTERM) }
	mut status := i32(0)
	for C.waitpid(child, &status, 0) < 0 { if unsafe { C.errno != C.EINTR } { return -1 } }
	home_session_note(c'HOME-UI: child wait status=%d\n', status)
	return if passed && status == 0 { i32(1) } else { i32(0) }
}

fn home_session(mut state HomeSupervisor) i32 {
	if C.setenv(c'HOME', c'/root', 1) != 0 || C.chdir(c'/root') != 0 { return 1 }
	child := C.fork()
	if child == 0 {
		home_erase_state(mut state)
		args := [&char(c'/usr/bin/vinix-desktop'), unsafe { &char(nil) }]!
		home_session_note(c'HOME-SESSION: before desktop exec\n', 0)
		C.execv(args[0], unsafe { &&char(&args[0]) })
		home_session_note(c'HOME-SESSION: desktop exec failed errno=%d\n', unsafe { C.errno })
		C._exit(127)
	}
	if child < 0 { return 1 }
	if !home_test_event(12, unsafe { nil }, 0) { C.kill(child, C.SIGTERM); return 1 }
	mut status := i32(0)
	for C.waitpid(child, &status, 0) < 0 {
		if unsafe { C.errno != C.EINTR } {
			home_session_note(c'HOME-SESSION: wait failed errno=%d\n', unsafe { C.errno })
			return 1
		}
	}
	home_session_note(c'HOME-SESSION: child wait status=%d\n', status)
	// Session termination requires a cold boot. Do not paint a misleading
	// relock over live mappings/processes or enter any recovery shell.
	return 1
}

// Public root-owned configuration: one explicit raw device path, optionally
// followed by "enroll". No discovery, migration or implicit disk selection.
@[direct_array_access]
fn home_boot() i32 {
	if C.geteuid() != 0 { return 1 }
	if C.setpgid(0, 0) != 0 { return 1 }
	// A dead UI endpoint must not kill the rate-budget owner with SIGPIPE.
	if C.signal(C.SIGPIPE, unsafe { voidptr(C.SIG_IGN) }) == unsafe { voidptr(C.SIG_ERR) } { return 1 }
	limit := C.rlimit{}
	if C.setrlimit(C.RLIMIT_CORE, &limit) != 0 { return 1 }
	mut config := [256]u8{}
	n := read_private_key_file(c'/etc/vinix/encrypted-home', &config[0], 6, 255)
	if n == 0 { return plan_error(c'encrypted home requires explicit device configuration; locked') }
	mut end := 0
	for end < n && config[end] != 10 { end++ }
	if end < 6 || !recovery_equal(&config[0], unsafe { &u8(c'/dev/') }, 5) { return 1 }
	for i in 5 .. end { if !((config[i] >= `a` && config[i] <= `z`) || (config[i] >= `0` && config[i] <= `9`)) { return 1 } }
	enroll := end + 8 == n && recovery_equal(unsafe { &config[end + 1] }, unsafe { &u8(c'enroll\n') }, 7)
	if end != n && end + 1 != n && !enroll { return 1 }
	config[end] = 0
	fd := C.open(unsafe { &char(&config[0]) }, C.O_RDWR | C.O_NOFOLLOW | C.O_CLOEXEC | C.O_NONBLOCK)
	if fd < 0 { return 1 }; defer { C.close(fd) }
	mut status := Status{}
	if !query_status(fd, mut status) || status.start != 0 || status.flags & (1 | 2 | 8 | 16) != 0
		|| status.bytes < 64 * 1024 * 1024 || status.bytes >= u64(4) * 1024 * 1024 * 1024
		|| status.bytes % 4096 != 0 || (status.sector != 512 && status.sector != 4096) { return 1 }
	if C.ioctl(fd, u64(0x56560008), unsafe { nil }) != 0 { return 1 }
	mut state := unsafe { &HomeSupervisor(C.alloca(sizeof(HomeSupervisor))) }
	unsafe { *state = HomeSupervisor{bytes: status.bytes, sector: status.sector} }
	defer { erase_key(state, sizeof(HomeSupervisor)) }
	if !home_disk_read(fd, &state.header[0], 4096, 0) { return 1 }
	if !home_header_valid(&state.header, state.bytes, state.sector) {
		if !enroll || !home_blank(fd, state.bytes) { return plan_error(c'home header invalid or disk occupied; locked') }
		state.fresh = true
		if !home_prepare(mut state, home_entropy) {
			home_test_event(13, unsafe { nil }, 0)
			plan_error(c'secure entropy unavailable; enrollment stopped')
			return 2
		}
	}
	for {
		result := home_spawn_ui(mut state)
		if result < 0 { return 1 }
		if result == 1 { break }
		// State and the shared rate budget survive replacement of the UI.
		if state.phase != .locked && state.phase != .enrollment { return 1 }
		C.sleep(1)
	}
	if !home_activate(fd, mut state) { state.phase = .failed; return plan_error(c'encrypted home activation failed; locked') }
	if !home_private_scratch() { return plan_error(c'private temporary storage unavailable; session denied') }
	return home_session(mut state)
}

pub fn home_run(argc i32, argv &&char) i32 {
	$if home_guest_probe ? {
		if argc == 2 && unsafe { C.strcmp(argv[1], c'--protocol-probe') == 0 } { return home_probe() }
	}
	if argc == 3 && unsafe { C.strcmp(argv[1], c'--ui') == 0 } {
		fd := decimal(unsafe { argv[2] }) or { return 1 }
		if fd < 3 || fd > 1024 { return 1 }
		return home_ui(i32(fd))
	}
	if argc != 2 || unsafe { C.strcmp(argv[1], c'--boot') != 0 } { return 1 }
	result := home_boot()
	// A configuration, metadata, entropy or activation failure presents a
	// static error surface, with no path back to enrollment or a shell.
	mut failed := unsafe { &HomeSupervisor(C.alloca(sizeof(HomeSupervisor))) }
	unsafe { *failed = HomeSupervisor{phase: if result == 2 { .entropy_failed } else { .failed }} }
	home_spawn_ui(mut failed)
	return result
}
