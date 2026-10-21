module main

import os

const usage = 'selfboot: offline amd64 regular-image installer/updater (Linux mutations only)
  inspect --target ABS [--source ABS]
  plan --source ABS
  bundle --iso ABS --iso-sha256 HASH64 --output ABS
         [--kernel ABS --kernel-sha256 HASH64]
  install --target ABS --expect-dev DEC --expect-inode DEC --expect-bytes DEC
          --source ABS --source-image-id HEX16 --bundle ABS --bundle-sha256 HASH64
  update  --target ABS --expect-dev DEC --expect-inode DEC --expect-bytes DEC
          --bundle ABS --bundle-sha256 HASH64
  install/update: [--interrupt-after PHASE] or [--pause-at PHASE --ready-file ABS]
  PHASE: validated, root-copied, payloads-staged, config-staged, verified, before-activate
  Operations and safety manifest: docs/selfboot.md.
  No raw/block devices, mounts, VM control or installed-root formatting/updates.'

fn required(o map[string]string, key string) !string {
	if o[key] == '' { return error('missing --${key}') }
	return o[key]
}

fn options(args []string, allowed []string) !map[string]string {
	mut result := map[string]string{}
	mut i := 0
	for i < args.len {
		arg := args[i]
		if !arg.starts_with('--') { return error('expected named option: ${arg}') }
		key := arg[2..].all_before('=')
		if key !in allowed || key in result {
			return error('unknown or duplicate option: --${key}')
		}
		mut value := ''
		if arg.contains('=') {
			value = arg.all_after('=')
		} else {
			i++
			if i >= args.len { return error('missing value for --${key}') }
			value = args[i]
		}
		if value == '' || value.starts_with('--') || value.contains('\x00') {
			return error('invalid value for --${key}')
		}
		result[key] = value
		i++
	}
	return result
}

fn dispatch(args []string) ! {
	if args.len == 0 || args[0] in ['--help', 'help'] {
		println(usage)
		return
	}
	mut allowed := []string{}
	match args[0] {
		'inspect' { allowed = ['target', 'source'] }
		'plan' { allowed = ['source'] }
		'bundle' { allowed = ['iso', 'iso-sha256', 'output', 'kernel', 'kernel-sha256'] }
		'install', 'update' {
			allowed = ['target', 'expect-dev', 'expect-inode', 'expect-bytes', 'bundle', 'bundle-sha256',
				'interrupt-after', 'pause-at', 'ready-file']
			if args[0] == 'install' { allowed << ['source', 'source-image-id'] }
		}
		else { return error('unknown command: ${args[0]}') }
	}
	o := options(args[1..], allowed)!
	match args[0] {
		'bundle' { bundle_build(o)! }
		'install' { install(o)! }
		'update' { update(o)! }
		'plan' {
			s := locked(required(o, 'source')!)!
			defer { s.close() }
			g := geometry(s.id.bytes)!
			validate_root(s.fd, 0, s.id.bytes)!
			println('source=${s.path}\nsource-dev=${s.id.dev}\nsource-inode=${s.id.ino}\nroot-bytes=${g.root_bytes}\nrequired-target-bytes=${g.disk_bytes}\nesp-start=${mib}\nesp-bytes=${esp_bytes}\nroot-start=${root_start}')
		}
		'inspect' {
			f := locked(required(o, 'target')!)!
			defer { f.close() }
			println('target=${f.path}\ndev=${f.id.dev}\ninode=${f.id.ino}\nbytes=${f.id.bytes}\nsector-bytes=512\nesp-start=${mib}\nesp-bytes=${esp_bytes}\nroot-start=${root_start}')
			if 'source' in o {
				s := locked(o['source'])!
				defer { s.close() }
				g := geometry(s.id.bytes)!
				println('source=${s.path}\nsource-dev=${s.id.dev}\nsource-inode=${s.id.ino}\nroot-bytes=${g.root_bytes}\nrequired-target-bytes=${g.disk_bytes}')
			}
		}
		else {}
	}
}

fn main() {
	dispatch(os.args[1..]) or {
		eprintln('selfboot: ${err.msg()}')
		exit(1)
	}
}
