# POSIX PTY allocation and SSH regression

`probe/core.v` is a V native fixture with no V runtime. The same probe runs on
Linux and Vinix. It allocates `/dev/ptmx`, checks TIOCGPTN against `ptsname`,
checks both lock ioctls, opens the slave as an ordinary user, creates a fresh
session, claims TIOCSCTTY, and checks TIOCGSID, TIOCGPGRP and `/dev/tty`.
When started as guest init it drops to UID/GID 1000 before allocating.

On fecv3, after preparing the private build tree described in the task report:

```sh
/home/agent/code/v/v -cc clang run tests/pty-posix/verify.v /home/agent/build/vinix-m17c-pty build
/home/agent/code/v/v -cc clang run tests/pty-posix/verify.v /home/agent/build/vinix-m17c-pty host
```

The host lane also tests the production SSH sources with OpenSSH, both without
TERM (the exact acceptance environment) and with TERM=xterm. Disposable keys
and the host seed stay in private directories and are never printed.

The native guest probe uses the existing V guest controller:

```sh
cd /home/agent/build/vinix-m17c-mmap
env PATH=/home/agent/toolshim:/usr/bin:/bin:/usr/local/bin V=/home/agent/code/v/v CC=clang \
  VINIX_OVMF_CODE=/usr/share/edk2/x64/OVMF_CODE.4m.fd \
  tests/kernel-gaps/run-native --arch x86_64 \
  --kernel-dir /home/agent/build/vinix-m17c-pty/kernel \
  --state-dir /home/agent/build/vinix-m17c-pty/guest-rerun-NEW \
  --source /home/agent/build/vinix-m17c-pty/tests/pty-posix/probe/core.v \
  --expect 'PTY-POSIX PASS' --fail 'PTY-POSIX FAIL' --no-network --timeout 60
```

This direct kernel test is separate from the literal production ISO gate.
`guest-proof.v package|run ROOT PARENT-QUAL-DIR FRESH-PACKAGE-DIR` packages an
isolated production ISO and invokes the parent's unchanged provision, offline
installation and smoke qualification. Run it in an ordinary fecv3 shell with
KVM available. It needs the parent's prepared tools, keys, dedicated SMB/NFS
containers and noninteractive permission for its regular-file-only offline
installer. It preserves the parent's original ISO, system disk and sources.
The unchanged acceptance worker retains all of its SSH, SCP and filesystem
checks, including the literal `ssh -tt ... 'echo M17C-PTY'` command.

If installation succeeded but a test fixture stopped before acceptance, the
`smoke` mode uses that installed disk with a new run directory and fresh HOME.
It retains the failed run and executes all of the unchanged smoke checks.

All receipts go into the private build/package directories. A failed attempt
must be retained; use a fresh package directory for another qualification.
