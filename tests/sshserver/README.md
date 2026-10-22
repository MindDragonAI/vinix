# Mission16B SSH guest qualification lane

This directory contains V sources, not a guest acceptance receipt. See the
appended integration section in `docs/ssh-server.md` for the security contract,
disposable ISO layout, strict refusal gate and required callback checks.

Build from a working V checkout (the local copied V has a stale baked-in root):

```sh
./v -new-compiler -o /OUTPUT/m16b-controller /REPO/tests/sshserver/controller
./v -new-compiler -enable-globals -gc none -manualfree \
  -path '/REPO|@vlib|@vmodules' -o /OUTPUT/m16b-seed /REPO/tests/sshserver/guest
./v -new-compiler -enable-globals -path '/REPO|@vlib|@vmodules' \
  test /REPO/tests/sshserver/config
```

The parent owns musl/static cross-compilation and ISO generation. The guest
helper imports the production guard from `desktop.sessiondaemon`; use the same
compiler/runtime flags and include path as the existing service build tool.
It is installed as `/usr/bin/vinix-desktop` only in a disposable ISO, alongside
`/usr/bin/vinix-desktop.real`, the actual modified broker and the SSH daemon.

On the Linux KVM host:

```text
/OUTPUT/m16b-controller /ABS/NEW_RUN_DIR /ABS/DIAGNOSTIC.iso /ABS/ACCEPTANCE_CALLBACK
```

The callback is an executable argument, not a shell command string. It receives
SSH_HOST, SSH_PORT, SSH_USER, SSH_KEY (a path only), and SSH_RUN_DIR. Use
`scp -O` and `setsid ssh -tt`; preserve individual criterion receipts. The
controller prints all child exits and writes fixed, nonsecret stage receipts.
Never attach COM2, credential memory or QMP input logs. RUN_DIR and HOME are
exclusive/new, so failed or completed runs cannot silently repeat finished steps.

NO-GO until actual encrypted-home guest boot, refusal, enrollment, session-broker
startup, OpenSSH exec/status/PTY/auth/session and 50 MiB/recursive SCP criteria
have all passed and their receipts have been reviewed by the parent.

`acceptance/main.v` contains the parent's actual OpenSSH callback. Its 180-second
per-command limit did not complete the guest 50 MiB upload in run gq5. This is
a failed qualification receipt, not proof of file corruption or protocol failure.
Do not rerun the successful shell/auth/session checks as a substitute for the
remaining transfer checks. Preserve and reverify their existing receipts.

The controller retains NO-GO if the strict pre-unlock refusal check fails, even
when it continues through real enrollment to collect transport diagnostics.

Stage 2 uses a 900-second per-command limit and a 2100-second outer callback
budget. Set `SSH_STAGE2_ONLY=1` on the controller to skip the already-qualified
shell/auth/session suite, not to waive either remaining gate. The callback
checks the fixed 50 MiB source SHA256, the guest hash, the downloaded hash,
and guest/host hashes for three recursive-tree files. Elapsed nanoseconds and
decimal MB/s are retained separately for both large transfer directions.

With the Stage 2 guest helper installed, set `SSH_STAGE2_LOOPBACK=1` as well.
Before unlock the helper requires ECONNREFUSED and no readable banner bytes.
After service start the callback invokes its bounded loopback-connect probe.
The pre-unlock check and post-unlock check both target guest 127.0.0.1:22;
the host-forward listener is not substituted for either check. A failed upload
also attempts a bounded collection of the daemon log, partial size and memory
status before the controller destroys its disposable guest.

Optional Stage 2 diagnostics are not acceptance substitutes:
`SSH_STAGE2_DIAGNOSTICS=1` starts the bounded V process-accounting sampler on
nonsecret COM1; `SSH_STAGE2_PCAP=1` records guest packets in the run directory.
`SSH_STAGE2_BENCH=1` also requires the separately built fixed-path AES benchmark
on the host. Never collect COM2 or HOME raw disks with these receipts.

Stage 2 guest-r4 passed strict refusal and post-unlock loopback success, but
the 50 MiB upload closed remotely after 151.188 seconds despite the 900-second
command limit. The bounded-memory repair passed target tests and reduced the
observed growth; it did not fix that closure. Full guest hash/download and
recursive qualification remain unverified. The Stage 2 operator gate is NO-GO.
