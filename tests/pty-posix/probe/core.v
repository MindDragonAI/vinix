// SPDX-License-Identifier: GPL-2.0-or-later
// The same allocation/claim probe runs on Linux and in a native Vinix guest.
@[translated]
@[has_globals]
module probe

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

struct C.stat { mut: st_uid u32 st_gid u32 }
@[c_extern] __global C.errno i32
fn C.printf(&char, ...) i32
fn C.posix_openpt(i32) i32
fn C.grantpt(i32) i32
fn C.unlockpt(i32) i32
fn C.ptsname(i32) &char
fn C.open(&char, i32, ...) i32
fn C.close(i32) i32
fn C.ioctl(i32, u64, ...voidptr) i32
fn C.stat(&char, &C.stat) i32
fn C.snprintf(&char, usize, &char, ...) i32
fn C.strcmp(&char, &char) i32
fn C.fork() i32
fn C.setsid() i32
fn C.getsid(i32) i32
fn C.getpgrp() i32
fn C.geteuid() u32
fn C.getegid() u32
fn C.setuid(u32) i32
fn C.setgid(u32) i32
fn C.waitpid(i32, &i32, i32) i32
fn C._exit(i32)
fn C.fflush(voidptr) i32
fn C.signal(i32, voidptr) voidptr

fn check(ok bool, step &char) bool {
	if !ok { C.printf(c'PTY-POSIX FAIL step=%s errno=%d\n', step, C.errno); C.fflush(unsafe { nil }) }
	return ok
}

fn allocation() i32 {
	// Closing our master hangs up the controlling session during cleanup.
	unsafe { C.signal(C.SIGHUP, C.SIG_IGN) }
	master := C.posix_openpt(C.O_RDWR | C.O_NOCTTY | C.O_CLOEXEC)
	if !check(master >= 0, c'posix_openpt') { return 1 }
	defer { C.close(master) }
	mut number := u32(-1)
	if !check(C.ioctl(master, u64(0x80045430), &number) == 0, c'TIOCGPTN on ptmx') { return 1 }
	C.printf(c'PTY-POSIX TIOCGPTN number=%u\n', number)
	mut locked := i32(-1)
	if !check(C.ioctl(master, u64(0x80045439), &locked) == 0 && locked == 1, c'TIOCGPTLCK initially locked') { return 1 }
	if !check(C.grantpt(master) == 0, c'grantpt') { return 1 }
	if !check(C.unlockpt(master) == 0, c'unlockpt/TIOCSPTLCK') { return 1 }
	if !check(C.ioctl(master, u64(0x80045439), &locked) == 0 && locked == 0, c'TIOCGPTLCK unlocked') { return 1 }
	name := C.ptsname(master)
	if !check(name != unsafe { nil }, c'ptsname') { return 1 }
	mut expected := [64]char{}
	C.snprintf(&expected[0], 64, c'/dev/pts/%u', number)
	if !check(C.strcmp(name, &expected[0]) == 0, c'ptsname matches TIOCGPTN') { return 1 }
	mut st := C.stat{}
	if !check(C.stat(name, &st) == 0, c'slave node reachable') { return 1 }
	C.printf(c'PTY-POSIX slave=%s owner=%u:%u caller=%u:%u\n', name, st.st_uid, st.st_gid, C.geteuid(), C.getegid())
	slave := C.open(name, C.O_RDWR | C.O_NOCTTY | C.O_CLOEXEC)
	if !check(slave >= 0, c'open slave as unprivileged owner') { return 1 }
	defer { C.close(slave) }
	if !check(st.st_uid == C.geteuid(), c'slave belongs to allocating user') { return 1 }
	if !check(C.setsid() >= 0, c'setsid') { return 1 }
	if !check(C.ioctl(slave, u64(0x540e), unsafe { nil }) == 0, c'TIOCSCTTY fresh session') { return 1 }
	mut sid := i32(-1)
	if !check(C.ioctl(slave, u64(0x5429), &sid) == 0 && sid == C.getsid(0), c'TIOCGSID matches session') { return 1 }
	mut group := i32(-1)
	if !check(C.ioctl(slave, u64(0x540f), &group) == 0 && group == C.getpgrp(), c'TIOCGPGRP matches foreground') { return 1 }
	tty := C.open(c'/dev/tty', C.O_RDWR | C.O_NOCTTY | C.O_CLOEXEC)
	if !check(tty >= 0, c'open controlling /dev/tty') { return 1 }
	C.close(tty)
	C.printf(c'PTY-POSIX TIOCSCTTY session=%d foreground=%d PASS\n', sid, group)
	return 0
}

@[export: 'main']
pub fn entry() i32 {
	pid := C.fork()
	if !check(pid >= 0, c'fork isolated probe') { return 1 }
	if pid == 0 {
		// The guest init is root. Exercise the production unprivileged path.
		if C.geteuid() == 0 {
			if !check(C.setgid(1000) == 0 && C.setuid(1000) == 0, c'drop credentials') { C._exit(1) }
		}
		result := allocation()
		C.fflush(unsafe { nil })
		C._exit(result)
	}
	mut status := i32(-1)
	waited := C.waitpid(pid, &status, 0)
	C.printf(c'PTY-POSIX child_status=%d\n', status)
	if !check(waited == pid && status == 0, c'probe child exit') { return 1 }
	C.printf(c'PTY-POSIX PASS\n')
	C.fflush(unsafe { nil })
	return 0
}
