// SPDX-License-Identifier: GPL-2.0-or-later
module sessiondaemon

import desktop.sessioncore

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

fn C.openat(int, &char, int, ...int) int
fn C.mkdirat(int, &char, u32) int

pub struct SshOptin {
pub:
	user string
	home string
}

// Exactly two newline-terminated lines; no whitespace normalization.
pub fn ssh_parse_optin(record string) !SshOptin {
	if record.len > 512 || !record.ends_with('\n') { return error('invalid SSH opt-in') }
	end := record.index('\n') or { return error('invalid SSH opt-in') }
	if end < 1 || end > 32 { return error('invalid SSH username') }
	if end + 1 >= record.len - 1 { return error('missing SSH home line') }
	user := record[..end]
	mut accepted := false
	defer { if !accepted { unsafe { user.free() } } }
	for i, ch in user {
		if !((ch >= `a` && ch <= `z`) || (ch >= `A` && ch <= `Z`)
			|| ch == `_` || (i > 0 && ((ch >= `0` && ch <= `9`) || ch == `-` || ch == `.`))) {
			return error('invalid SSH username')
		}
	}
	home := record[end + 1..record.len - 1]
	defer { if !accepted { unsafe { home.free() } } }
	expected := '/root/home/' + user
	defer { unsafe { expected.free() } }
	if home != expected { return error('invalid SSH physical home') }
	accepted = true
	return SshOptin{user, home}
}

// Bounded before allocation, including proc files whose stat size is zero.
fn ssh_read_fd(fd int, limit int) !string {
	mut buffer := [65537]u8{}
	if limit < 1 || limit > 65536 { return error('invalid read bound') }
	mut used := 0
	for used <= limit {
		n := unsafe { C.read(fd, &buffer[used], usize(limit + 1 - used)) }
		if n < 0 { return error('SSH guard read failed') }
		if n == 0 { return unsafe { tos(&buffer[0], used).clone() } }
		used += int(n)
	}
	return error('SSH guard input too large')
}

fn ssh_private_regular(fd int, exact_mode bool) bool {
	mut st := C.stat{}
	return fd >= 0 && C.fstat(fd, &st) == 0 && u32(st.st_mode) & C.S_IFMT == C.S_IFREG
		&& st.st_uid == 0 && (if exact_mode {
		u32(st.st_mode) & 0o7777 == 0o600
	} else {
		u32(st.st_mode) & 0o077 == 0
	})
}

// Shared with the disposable ISO seed launcher. Mirrors encrypted_home.v's
// mapper + ext2/rw + exact private marker contract, with bounded proc input.
pub fn ssh_encrypted_home_ready() bool {
	if C.getuid() != 0 { return false }
	root := C.open(c'/root', C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW | C.O_CLOEXEC)
	if root < 0 { return false }
	defer { C.close(root) }
	proc := C.open(c'/proc/self/mounts', C.O_RDONLY | C.O_NOFOLLOW | C.O_CLOEXEC)
	if proc < 0 { return false }
	defer { C.close(proc) }
	mounts := ssh_read_fd(proc, 65536) or { return false }
	defer { unsafe { mounts.free() } }
	lines := mounts.split_into_lines()
	defer { unsafe { lines.free() } }
	mut mounted := false
	for line in lines {
		fields := line.fields()
		if fields.len >= 4 && fields[0] == '/dev/mapper/vinix63' && fields[1] == '/root'
			&& fields[2] == 'ext2' && (fields[3] == 'rw' || fields[3].starts_with('rw,')) {
			mounted = true
		}
		unsafe { fields.free() }
	}
	if !mounted { return false }
	fd := C.openat(root, c'.vinix-encrypted-home', C.O_RDONLY | C.O_NONBLOCK | C.O_NOFOLLOW | C.O_CLOEXEC)
	if fd < 0 { return false }
	defer { C.close(fd) }
	if !ssh_private_regular(fd, false) { return false }
	marker := ssh_read_fd(fd, 24) or { return false }
	defer { unsafe { marker.free() } }
	return marker == 'Vinix encrypted home v1\n'
}

// Pin /etc and reject symlinks rather than chmod an existing target.
pub fn ssh_key_directory_ready() bool {
	if C.getuid() != 0 { return false }
	etc := C.open(c'/etc', C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW | C.O_CLOEXEC)
	if etc < 0 { return false }
	defer { C.close(etc) }
	C.mkdirat(etc, c'ssh', 0o700)
	fd := C.openat(etc, c'ssh', C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW | C.O_CLOEXEC)
	if fd < 0 { return false }
	defer { C.close(fd) }
	mut st := C.stat{}
	return C.fstat(fd, &st) == 0 && st.st_uid == 0 && u32(st.st_mode) & 0o7777 == 0o700
}

fn (mut daemon SessionDaemon) load_ssh_service() {
	// Settings can persist the supervisor. Recognize only our exact generated
	// shape, then gate that saved entry again before allowing it to start.
	mut slot := -1
	mut enabled := true
	for i in 0 .. daemon.supervisor.count {
		service := daemon.supervisor.services[i]
		if service.name.str() != 'ssh-server' && service.executable.str() != '/usr/libexec/vinix-sshd' {
			continue
		}
		if slot >= 0 || !ssh_managed_service(service) { return }
		slot = i
		enabled = service.enabled
		daemon.supervisor.services[i].enabled = false
	}
	if daemon.home != '/root' || !ssh_encrypted_home_ready() { return }
	if slot < 0 && daemon.supervisor.count >= sessioncore.max_services { return }
	root := C.open(c'/root', C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW | C.O_CLOEXEC)
	if root < 0 { return }
	defer { C.close(root) }
	fd := C.openat(root, c'.vinix-ssh', C.O_RDONLY | C.O_NONBLOCK | C.O_NOFOLLOW | C.O_CLOEXEC)
	if fd < 0 { return }
	defer { C.close(fd) }
	if !ssh_private_regular(fd, true) { return }
	record := ssh_read_fd(fd, 512) or { return }
	defer { unsafe { record.free() } }
	opt := ssh_parse_optin(record) or { return }
	defer {
		unsafe {
			opt.user.free()
			opt.home.free()
		}
	}
	// Every home component is physical; the daemon repeats these checks and
	// validates the key contents immediately before using them.
	mut homefd := C.openat(root, c'home', C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW | C.O_CLOEXEC)
	if homefd < 0 { return }
	userfd := C.openat(homefd, &char(opt.user.str), C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW | C.O_CLOEXEC)
	C.close(homefd)
	if userfd < 0 { return }
	defer { C.close(userfd) }
	sshfd := C.openat(userfd, c'.ssh', C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW | C.O_CLOEXEC)
	if sshfd < 0 { return }
	defer { C.close(sshfd) }
	keys := C.openat(sshfd, c'authorized_keys', C.O_RDONLY | C.O_NONBLOCK | C.O_NOFOLLOW | C.O_CLOEXEC)
	if keys < 0 { return }
	defer { C.close(keys) }
	if !ssh_private_regular(keys, false) { return }
	mut executable := C.stat{}
	if C.lstat(c'/usr/libexec/vinix-sshd', &executable) != 0
		|| u32(executable.st_mode) & C.S_IFMT != C.S_IFREG || executable.st_uid != 0
		|| u32(executable.st_mode) & 0o022 != 0 || u32(executable.st_mode) & 0o111 == 0 {
		return
	}
	if !ssh_key_directory_ready() { return }
	mut service := sessioncore.Service{
		name:       sessioncore.text('ssh-server') or { return }
		executable: sessioncore.text('/usr/libexec/vinix-sshd') or { return }
		system:     true
		restart:    .never
		enabled:    enabled
	}
	args := ['--user', opt.user, '--home', opt.home, '--host-key', '/etc/ssh/ssh_host_ed25519_key']!
	for i, arg in args { service.arguments[i] = sessioncore.text(arg) or { return } }
	service.argument_count = args.len
	i := if slot >= 0 { slot } else { daemon.supervisor.count }
	daemon.supervisor.services[i] = service
	if slot < 0 { daemon.supervisor.count++ }
	daemon.supervisor.validate() or {
		if slot < 0 {
			daemon.supervisor.count--
			daemon.supervisor.services[i] = sessioncore.Service{}
		} else {
			daemon.supervisor.services[i].enabled = false
		}
		return
	}
}

fn ssh_managed_service(service sessioncore.Service) bool {
	if !service.system || service.name.str() != 'ssh-server'
		|| service.executable.str() != '/usr/libexec/vinix-sshd'
		|| service.argument_count != 6 || service.restart != .never || service.dependencies != 0
		|| service.arguments[0].str() != '--user' || service.arguments[2].str() != '--home'
		|| service.arguments[4].str() != '--host-key'
		|| service.arguments[5].str() != '/etc/ssh/ssh_host_ed25519_key' {
		return false
	}
	expected := '/root/home/' + service.arguments[1].str()
	defer { unsafe { expected.free() } }
	return service.arguments[3].str() == expected
}
