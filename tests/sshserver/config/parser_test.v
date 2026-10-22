module main

import desktop.sessiondaemon

fn test_exact_optin() {
	for user in ['m16b', 'User_42', '_svc', 'test-user.name'] {
		opt := sessiondaemon.ssh_parse_optin('${user}\n/root/home/${user}\n') or { panic(err) }
		assert opt.user == user
		assert opt.home == '/root/home/' + user
	}
}

fn test_optin_rejects_ambiguous_or_unphysical_input() {
	for record in ['', 'm16b\n', 'm16b\n\n', '\n\n', 'm16b\n/root/home/m16b', 'm16b\n/home/m16b\n',
		'm16b\n/root/home/other\n', 'm16b\n/root/home/m16b\nextra\n', 'm16b\r\n/root/home/m16b\n',
		'-bad\n/root/home/-bad\n', 'bad user\n/root/home/bad user\n', 'é\n/root/home/é\n',
		'm16b\n/root/home/m16b/../m16b\n', 'm16b\n/root/home/m16b\x00\n', 'x'.repeat(513)] {
		if _ := sessiondaemon.ssh_parse_optin(record) {
			assert false, 'invalid opt-in accepted'
		}
	}
}
