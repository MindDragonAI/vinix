module main

fn test_scp_bounds_and_recursive_records() {
	for line in ['C0600 -1 file', 'C0600 1073741825 file', 'C0600 18446744073709551615 file',
		'C0600 0 ../x', 'C0600 0 /x', 'C0600 0 a/b', 'C0600 0 a\\b', 'D0755 1 dir', 'C0999 0 bad'] {
		if _ := scp_record(line) {
			assert false
		}
	}
	for line in ['D0755 0 dir', 'D0700 0 nested', 'C0600 52428801 big file'] {
		record := scp_record(line) or { panic(err) }
		assert safe_name(record.name)
	}
	args := parse_scp_command("scp -r -t -- '/home/test/a b'") or { panic(err) }
	o := scp_options(args) or { panic(err) }
	assert o.receive && o.recursive && o.target == '/home/test/a b'
	for cmd in ['scp -t a;id', 'scp -S bad -t a', 'scp -t a b', 'scp -t $(id)', 'scp -t `id`'] {
		if _ := parse_scp_command(cmd) {
			assert false
		}
	}
}
