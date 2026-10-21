// SPDX-License-Identifier: GPL-2.0-or-later
module volumecli

#include <termios.h>
fn C.tcgetattr(i32, &C.termios) i32
fn C.tcsetattr(i32, i32, &C.termios) i32
struct C.termios {
mut:
	c_iflag u64
	c_oflag u64
	c_cflag u64
	c_lflag u64
	c_cc [32]u8
}

// fbdev ABI, matching the desktop's existing 32-bit framebuffer path.
struct HomeBitfield { offset u32 length u32 msb_right u32 }
struct HomeFBVar {
	xres u32 yres u32 xres_virtual u32 yres_virtual u32 xoffset u32 yoffset u32
	bits_per_pixel u32 grayscale u32 red HomeBitfield green HomeBitfield blue HomeBitfield transp HomeBitfield
	nonstd u32 activate u32 height u32 width u32 accel_flags u32 pixclock u32
	left_margin u32 right_margin u32 upper_margin u32 lower_margin u32 hsync_len u32 vsync_len u32
	sync u32 vmode u32 rotate u32 colorspace u32 reserved [4]u32
}
struct HomeFBFix {
	id [16]u8 smem_start u64 smem_len u32 typ u32 type_aux u32 visual u32
	xpanstep u16 ypanstep u16 ywrapstep u16 line_length u32 mmio_start u64 mmio_len u32
	accel u32 capabilities u16 reserved [2]u16
}
struct HomeScreen {
mut:
	fd i32 = -1
	pixels &u32 = unsafe { nil }
	width int height int stride int size usize
	red u32 green u32 blue u32
}

// Five columns, seven rows; deliberately tiny, with no compositor, preferences,
// application broker, font loader or user-home dependency before unlock.
const home_glyphs = [u64(0x7e1111117e), 0x7f49494936, 0x3e41414122, 0x7f4141221c,
	0x7f49494941, 0x7f09090901, 0x3e41495172, 0x7f0808087f, 0x00417f4100,
	0x204040403f, 0x7f08142241, 0x7f40404040, 0x7f020c027f, 0x7f0408107f,
	0x3e4141413e, 0x7f09090906, 0x3e4151215e, 0x7f09192946, 0x2649494932,
	0x01017f0101, 0x3f4040403f, 0x1f2040201f, 0x7f2018207f, 0x6314081463,
	0x0304780403, 0x6151494543, 0x3e4549513e, 0x00427f4000, 0x4261514946,
	0x2141494533, 0x1814127f10, 0x2745454539, 0x3c4a494930, 0x0171090503,
	0x3649494936, 0x064949291e, 0x08083e0808, 0x0808080808, 0x0000606000]!

fn home_screen() ?HomeScreen {
	fd := C.open(c'/dev/fb0', C.O_RDWR | C.O_CLOEXEC | C.O_NOFOLLOW)
	if fd < 0 { return none }
	mut var := HomeFBVar{}; mut fix := HomeFBFix{}
	if C.ioctl(fd, u64(0x4600), &var) != 0 || C.ioctl(fd, u64(0x4602), &fix) != 0
		|| var.bits_per_pixel != 32 || var.xres < 640 || var.yres < 480
		|| var.xres > 8192 || var.yres > 8192 || fix.line_length % 4 != 0
		|| fix.line_length < var.xres * 4 || var.red.length != 8 || var.green.length != 8 || var.blue.length != 8
		|| var.red.offset > 24 || var.green.offset > 24 || var.blue.offset > 24 {
		C.close(fd); return none
	}
	size := usize(fix.line_length) * var.yres
	if size > fix.smem_len || size > 256 * 1024 * 1024 { C.close(fd); return none }
	address := C.mmap(unsafe { nil }, size, C.PROT_READ | C.PROT_WRITE, C.MAP_SHARED, fd, 0)
	if address == unsafe { voidptr(C.MAP_FAILED) } { C.close(fd); return none }
	return HomeScreen{fd: fd, pixels: unsafe { &u32(address) }, width: int(var.xres), height: int(var.yres),
		stride: int(fix.line_length / 4), size: size, red: var.red.offset, green: var.green.offset, blue: var.blue.offset}
}

fn (screen &HomeScreen) clear() {
	color := u32(18) << screen.red | u32(27) << screen.green | u32(42) << screen.blue
	unsafe { for y in 0 .. screen.height { for x in 0 .. screen.width { screen.pixels[y * screen.stride + x] = color } } }
}

fn (screen &HomeScreen) text(bytes &u8, size int, line int, secret bool) {
	mut x := 24; mut y := 24 + line * 24
	color := u32(230) << screen.red | u32(235) << screen.green | u32(245) << screen.blue
	unsafe {
		for i in 0 .. size {
			mut ch := if secret { u8(`+`) } else { bytes[i] }
			if ch >= `a` && ch <= `z` { ch -= 32 }
			if x + 12 >= screen.width { x = 24; y += 20 }
			if y + 14 >= screen.height { break }
			index := if ch >= `A` && ch <= `Z` { int(ch - `A`) }
				else if ch >= `0` && ch <= `9` { 26 + int(ch - `0`) }
				else if ch == `+` { 36 } else if ch == `-` { 37 } else if ch == `.` { 38 } else { -1 }
			if index >= 0 {
				glyph := home_glyphs[index]
				for col in 0 .. 5 { for row in 0 .. 7 {
					if (glyph >> (8 * (4 - col))) & (u64(1) << row) == 0 { continue }
					for dy in 0 .. 2 { for dx in 0 .. 2 { screen.pixels[(y + row * 2 + dy) * screen.stride + x + col * 2 + dx] = color } }
				} }
			}
			x += 12
		}
	}
}

fn (screen &HomeScreen) label(text string, line int) { screen.text(unsafe { &u8(&text[0]) }, text.len, line, false) }

fn home_input(screen &HomeScreen, console i32, prompt string, output &u8, toggle bool) int {
	mut used := 0
	mut announced := false
	for {
		screen.clear(); screen.label('VINIX ENCRYPTED HOME', 0); screen.label(prompt, 2)
		screen.label('ENTER SUBMITS. ESC CLEARS.', 4)
		if toggle { screen.label('TAB SWITCHES WORDS OR PASSWORD.', 5) }
		screen.text(output, used, 7, true)
		if toggle && !announced {
			if !home_test_event(10, unsafe { nil }, 0) { return -1 }
			announced = true
		}
		mut ch := u8(0)
		if !home_transfer(console, &ch, 1, false) { return -1 }
		if ch == 13 || ch == 10 { return used }
		if ch == 9 && toggle { erase_key(output, 128); return -2 }
		if ch == 27 { erase_key(output, 128); used = 0 }
		else if ch == 127 || ch == 8 { if used > 0 { used--; unsafe { output[used] = 0 } } }
		else if ch >= 32 && ch <= 126 && used < 128 { unsafe { output[used] = ch }; used++ }
	}
	return -1
}

@[direct_array_access]
fn home_ui(fd i32) i32 {
	if C.geteuid() != 0 || !home_peer_root(fd) { return 1 }
	limit := C.rlimit{}
	if C.setrlimit(C.RLIMIT_CORE, &limit) != 0 { return 1 }
	mut screen := home_screen() or { return 1 }
	defer { screen.clear(); C.munmap(screen.pixels, screen.size); C.close(screen.fd) }
	console := C.open(c'/dev/console', C.O_RDONLY | C.O_CLOEXEC | C.O_NOFOLLOW)
	if console < 0 { return 1 }; defer { C.close(console) }
	mut saved := unsafe { &C.termios(C.alloca(sizeof(C.termios))) }
	mut raw := unsafe { &C.termios(C.alloca(sizeof(C.termios))) }
	if C.tcgetattr(console, saved) != 0 { return 1 }
	unsafe { C.memcpy(raw, saved, sizeof(C.termios)) }
	raw.c_lflag &= ~u64(C.ECHO | C.ICANON | C.ISIG | C.IEXTEN)
	raw.c_iflag &= ~u64(C.IXON | C.ICRNL)
	raw.c_cc[C.VMIN] = 1; raw.c_cc[C.VTIME] = 0
	if C.tcsetattr(console, C.TCSAFLUSH, raw) != 0 { return 1 }
	defer { C.tcsetattr(console, C.TCSAFLUSH, saved) }
	mut reply := unsafe { &HomeFrame(C.alloca(sizeof(HomeFrame))) }
	unsafe { *reply = HomeFrame{} }
	mut input := [128]u8{}; mut confirm := [128]u8{}; mut password := [128]u8{}; mut payload := [261]u8{}
	defer { erase_key(reply, sizeof(HomeFrame)); erase_key(&input[0], 128); erase_key(&confirm[0], 128); erase_key(&password[0], 128); erase_key(&payload[0], 261) }
	if !home_send(fd, 1, unsafe { nil }, 0) || !home_receive(fd, mut reply) { return 1 }
	if reply.op == 2 {
		if !home_send(fd, 2, unsafe { nil }, 0) || !home_receive(fd, mut reply) || reply.op != 2 { return 1 }
		screen.clear(); screen.label('SAVE YOUR TWELVE WORDS OFFLINE', 0)
		$if home_mask_enrollment_words ? {
			// Secret-safe diagnostic fixture only; production displays the words.
			screen.text(&reply.bytes[0], reply.size, 2, true)
		} $else { screen.text(&reply.bytes[0], reply.size, 2, false) }
		screen.label('THESE WORDS UNLOCK YOUR ENCRYPTED DATA.', 5)
		screen.label('IF THIS IS YOUR ONLY METHOD AND YOU LOSE IT', 6)
		screen.label('YOUR DATA CANNOT BE RECOVERED.', 7)
		screen.label('A PASSWORD IS OPTIONAL. EITHER SECRET WORKS.', 9)
		screen.label('LOSING BOTH SECRETS OR HEADER MEANS LOST DATA.', 10)
		screen.label('BOOT AND SYSTEM FILES REMAIN UNENCRYPTED.', 12)
		screen.label('ENTER ACKNOWLEDGES AN OFFLINE COPY AND RISK.', 14)
		if !home_test_event(2, &reply.bytes[0], reply.size) { return 1 }
		mut ch := u8(0)
		for ch != 13 && ch != 10 { if !home_transfer(console, &ch, 1, false) { return 1 } }
		erase_key(&reply.bytes[0], 1024)
		n := home_input(&screen, console, 'CONFIRM ALL TWELVE WORDS IN ORDER', &input[0], false)
		if n <= 0 { return 1 }
		p := home_input(&screen, console, 'OPTIONAL PASSWORD. ENTER EMPTY FOR WORDS ONLY', &password[0], false)
		if p < 0 { return 1 }
		if p > 0 {
			q := home_input(&screen, console, 'CONFIRM OPTIONAL PASSWORD EXACTLY', &confirm[0], false)
			if q != p || !recovery_equal(&password[0], &confirm[0], p) { return 1 }
		}
		put_le(&payload[0], 0, 2, u64(n)); put_le(&payload[0], 2, 2, u64(p)); payload[4] = 1
		unsafe { C.memcpy(&payload[5], &input[0], n); C.memcpy(&payload[5 + n], &password[0], p) }
		if !home_send(fd, 3, &payload[0], 5 + n + p) || !home_receive(fd, mut reply) || reply.op != 3 { return 1 }
		return 0
	}
	if reply.op != 1 {
		screen.clear(); screen.label('ENCRYPTED HOME UNAVAILABLE', 2)
		screen.label('CONFIGURATION OR STORAGE ERROR. REBOOT REQUIRED.', 4)
		mut ch := u8(0)
		for home_transfer(console, &ch, 1, false) { ch = 0 }
		return 1
	}
	mut password_mode := false
	for {
		n := home_input(&screen, console, if password_mode { 'ENTER PASSWORD EXACTLY' } else { 'ENTER TWELVE WORDS IN ORDER' }, &input[0], true)
		if n == -2 { password_mode = !password_mode; continue }
		if n < 0 { return 1 }
		if !home_send(fd, if password_mode { u32(5) } else { u32(4) }, &input[0], n) { return 1 }
		erase_key(&input[0], 128)
		if !home_receive(fd, mut reply) { return 1 }
		if reply.op == 3 { return 0 }
		screen.clear(); screen.label('DENIED OR RATE LIMITED. ENTER TO RETRY.', 2)
		if !home_test_event(11, unsafe { nil }, 0) { return 1 }
		mut ch := u8(0)
		for ch != 13 && ch != 10 { if !home_transfer(console, &ch, 1, false) { return 1 } }
	}
	return 1
}
