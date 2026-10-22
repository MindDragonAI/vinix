# V-native SSH server (Mission 16-B implementation lane)

## Status and integration

This is an experimental sandbox interface, not a hardened public SSH service.
Linux interoperability and static musl builds have receipts. Vinix guest
qualification and the operator gate are recorded separately in the mission
report. No deployment or public-release approval follows from these sources.

The entry point is the `main` module directory `tools/sshserver`:

```sh
v run tools/sshserver-build.v --arch=native --output=build/sshserver
v -path "$PWD|@vlib|@vmodules" test tools/sshserver
./build/sshserver/vinix-sshd --self-test
./build/sshserver/vinix-sshd --help
/usr/libexec/vinix-sshd --user USER --home /root/home/USER
```

Run in the foreground, after home unlock, as the owner of that home and key
files. The daemon does not switch UID/GID; the launcher owns privilege setup,
permission to bind port 22 and lifecycle. It does not create `/etc/ssh` or user
directories. Defaults: `--listen 0.0.0.0:22` and
`--host-key /etc/ssh/ssh_host_ed25519_key`. IPv6 listeners may be passed using
bracketed address/port notation accepted by V's `net.listen_tcp`.

## Identity and authentication

The custom host-key format is the exact ASCII header
`Vinix SSH Ed25519 seed v1\n`, followed by 32 raw seed bytes. This is **not** an
OpenSSH private-key file. Creation reads `/dev/urandom` fully, writes a 0600
exclusive temporary file, fsyncs it, publishes via exclusive `linkat`, and
fsyncs the containing directory. Existing key files must be regular, owned by
the daemon UID, have no group/other permissions, and match the exact format.
The key directory must be owned by the daemon UID and not group/other writable.
Every directory component and final file is opened without following symlinks.
Failures stop service; no ephemeral fallback identity is used.

```sh
./vinix-sshd --host-key /etc/ssh/ssh_host_ed25519_key --public-key
```

This prints only an authorized-keys-format public key. No private seed is
printed. Host fingerprints can be computed by the host's `ssh-keygen` from this
public output.

Only Ed25519 public-key authentication for the exact configured username is
accepted. `HOME/.ssh/authorized_keys` is reloaded per connection, capped at
64 KiB / 128 keys. It must be owned by the daemon UID with no group/other
permissions (0600 recommended); home and `.ssh` must be owned by that UID and
not group/other writable. Blank lines, comments and trailing key comments are
accepted. Any options, unsupported key types, malformed key blobs or
noncanonical base64 reject the entire file. Restrictions are never silently
ignored. Unsigned queries receive PK_OK only for a matching key; signed requests
are verified over the original request prefixed by the initial session ID.

Sessions are serialized. The production builder uses `-gc none` and
`-d ssh_session_workers`: a supervisor forks one worker per connection. All
session allocations disappear at worker exit, including failed handshakes.
An anonymous shared mapping retains the global failure budget across workers.
Use the supplied builder; do not combine this fork mode with a threaded GC.
An ordinary developer V build without this define retains the original
single-process, GC-managed execution path.

The daemon retains a global budget of 12 failed auth attempts per 60-second
epoch across connections, with
16 auth requests per connection. This is an in-memory rate limit, reset by a
daemon restart, not an external persistent lockout. Handshake/auth have an
absolute 30-second deadline; individual network operations have 15-second
timeouts. One connection can occupy the serialized service until its limits.
The normal `none` method-discovery request for the configured user does not
consume the shared failed-key budget; it still consumes a connection request.

## Protocol and channels

Identification is `SSH-2.0-Vinix`. Advertisements contain only
`curve25519-sha256`, `ssh-ed25519`, `aes128-ctr`, `hmac-sha2-256`, and compression
`none`. Client `ext-info-c` is treated as a KEX-list token; the server does not
advertise or send extension info. RFC 4253 packet alignment, random padding,
sequence-number MAC input, NEWKEYS and A..F SHA256 derivation are implemented.
The X25519 secret is encoded as an unsigned SSH mpint per RFC 8731. Zero shared
secrets and non-32-byte client points fail. There is no rekey implementation:
incoming rekey is rejected, and limits force reconnection before 1 GiB in either
direction, 1,000,000 packets in either direction, or one hour.

Only one `session` channel is accepted. Additional channels, global forwarding,
subsystems (including SFTP), and unknown channel requests are rejected. Local
receive window is 256 KiB, data packets at most 32 KiB; credit is returned after
bytes are delivered to child stdin. Output reads obey the peer's window and
packet limit. Stderr uses extended-data type 1 for pipe-based exec. EOF closes
only child input after queued input drains; stdout/stderr drain before exit
status, EOF and channel close. Socket, stdin, stdout and stderr are polled in one
thread. Disconnect cleanup closes descriptors and terminates/reaps the child
with bounded TERM-to-KILL escalation, including its process group.
Closing child stdin early does not abort stdout/stderr draining. POSIX pipe
pairs and wait status use explicit `i32` storage: V `int` is 64-bit in the
pinned compiler and cannot be used for a C `int *` output parameter.

Shell sessions use `/bin/sh` through `desktop.ptycore` when a PTY was requested;
exec otherwise uses `/bin/sh -c` and separate stdin/stdout/stderr pipes. PTY
geometry and `window-change` are handled. **Client terminal modes are framing
validated but are not applied; platform PTY defaults are used.** PTY EOF is an
EOT byte, which is not a universal half-close for raw terminal programs. The
environment allowlist is LANG, LC_ALL and LC_CTYPE (16 entries, 1024 bytes each);
TERM is set through a validated PTY request. Commands are capped at 8 KiB.
Authenticated shell/exec is arbitrary shell access as the daemon UID, not a
filesystem jail. Processes inherit only explicit environment entries.

## Legacy SCP

Modern clients use SFTP by default. Use `scp -O` for this implementation:

```sh
scp -O -P 22 file USER@host:/root/home/USER/file
scp -O -r USER@host:/root/home/USER/directory ./directory
```

Literal `scp ...` exec requests are decoded into arguments and intercepted to
`/usr/libexec/vinix-sshd --scp ...` using the daemon's own executable path;
no external scp binary or guest crypto subprocess is used. Only `-t`, `-f`,
`-r`, `-d`, `-p`, and `--` are parsed. Shell expansion/control operators and
extra targets are rejected. C/D/E/T receive records, regular-file sends,
recursive sends, acknowledgements and error responses are implemented. Incoming
timestamps are bounded and applied with `futimens`; outgoing `-p` timestamps are
not yet emitted. Modes exclude special bits. Existing directory and named-file
destinations are supported. File data streams in at most 32 KiB chunks, with a
1 GiB file limit, nesting depth 32, and 100,000 entries per outgoing directory.
Incoming names cannot contain separators, control bytes, `.` or `..`. Opens
are relative to pinned directory descriptors with NOFOLLOW; symlinks and
nonregular files are rejected. User-selected target paths may be absolute:
this is shell access, not a chroot. Partial failed uploads may remain and
existing regular files are truncated after checking their descriptor type.

## Reused cryptography and evidence

No cryptographic primitive is reimplemented here. Ed25519 uses the existing
`tools.packages.signing` vendored module at repository base
`9aba281162aa44c2c5752d756e95afc1e75a799a` (including its existing licensing).
X25519 uses V's `x.crypto.curve25519`; AES, CTR, HMAC and SHA256 use V's
`crypto.aes`, `crypto.cipher`, `crypto.hmac`, `crypto.sha256`. The inspected local
V checkout reports `0.5.2`, commit
`6af2727d4220773312f0953e5d1c8e3fd97b93a6`. V's crypto source notices specify MIT
licensing; Ed25519's internal field arithmetic is also used by X25519. These
are source provenance statements, not constant-time or security audit claims.

SHA256 of inspected entry sources:

| Source | SHA256 |
|---|---|
| tools/packages/signing/signing.v | 917cbf36479fbde6e593d16940f738b3977cf47df2cea8cb0c0071293bb85a86 |
| x/crypto/curve25519/curve25519.v | b74ec1c30b1c90fefe67ff99582a48c47755edbc9c97dab0059bbbe5ea46b57a |
| crypto/aes/aes.v | 474fc2bb1f9afd1192e41f3a3ea6095ad4eacc99e393015f5ef86545a0bb05f9 |
| crypto/cipher/ctr.v | 422e1bf6c37e854e2548e606d699640b556ed872d8a9a747e665d9c67edec1d2 |
| crypto/hmac/hmac.v | 4e1d5d842a21aba55b209686da2f81f40e39e5b66c2910b331377bd5192664d8 |
| crypto/sha256/sha256.v | f505514a25560d51172e0bbed5d63e4b1cfd470ee7dec75214ae7da739a4e516 |

The self-test includes RFC 7748 Alice/Bob X25519, RFC 8032 Ed25519 test 1,
SHA256 `abc`, NIST SP800-38A F.5.1 AES128-CTR, and RFC 4231 HMAC-SHA256 test 1.
The test sources add truncated/oversized codec cases, mpint boundaries, MAC
sequence binding, auth session/username/key binding, authorized-key option
rejection and SCP traversal/recursive record parsing. These tests do not replace
end-to-end recursive filesystem fixtures, 50 MiB transfers, hostile network
testing, or actual Vinix PTY/process qualification.

Before integration, the parent must establish: clean compilation with its
compiler; passing test suite and self-test; ordinary OpenSSH connection with no
weak-algorithm flags; host identity persistence and permission rejection;
wrong/no-key rejection and shared failure budget; real PTY shell/resize;
exec stdin half-close, separate stderr and exit status; disconnect reap;
50 MiB transfer each way; recursive SCP named-file/existing-directory fixtures;
and malformed packet/padding/MAC disconnects. No such runtime acceptance is
implied merely by the presence of these source files.

## Recovery verification (2026-10-22)

Local macOS checks used the supplied V 0.5.2 / `6af2727` executable. Source
checking, a complete daemon build, `--self-test`, and `--help` passed. The build
retains notices about the transport's initially unused cipher interfaces.
All five V test files passed (25.703 seconds total): codec bounds, crypto
vectors, authentication binding/discovery, SCP parsing, and the pipe-exec
regression. The latter launches a real host child, closes stdin after input,
checks separate stdout/stderr, verifies exit status 7, and reaps the child.
These checks establish host compilation and primitive vectors, not Vinix or
OpenSSH session qualification.

The copied compiler has a stale baked-in root, so local commands were invoked
from its actual checkout with the workspace's absolute path as the first
`-path` entry. `TMPDIR` remained the supplied profile scratch directory; the
sandbox permits compiler intermediates only inside the workspace, so `VTMP`
was set to `tools/sshserver/.local-check` and `-cflags '-save-temps=obj'` avoided
Clang's otherwise-denied temporary object creation. These are local verification
workarounds, not daemon dependencies or target build requirements.

## Optional desktop-session integration (Mission16B lane 2)

`desktop/sessiondaemon/ssh.v` adds `ssh-server` to the existing supervisor after
`load_services()`. The desktop broker already runs after home unlock. Startup is
opt-in through `/root/.vinix-ssh`, an exact two-line, newline-terminated record:

```text
m16b
/root/home/m16b
```

The file must be a root-owned 0600 regular file, at most 512 bytes, opened
without following symlinks. The username is 1–32 ASCII characters, starts with a
letter or underscore, and thereafter permits letters, digits, underscore, dot
and hyphen. The second line must be exactly `/root/home/` plus that username.
The guard first checks a bounded (64 KiB) `/proc/self/mounts` for the real
`/dev/mapper/vinix63` ext2 rw mount at `/root`, then the private root-owned regular
marker with exact `Vinix encrypted home v1\n` contents. This follows
`desktop/encrypted_home.v`; a public-volume marker cannot authorize startup.

The physical home components and `.ssh/authorized_keys` are opened without
following symlinks. The authorized-key file must be root-owned and private;
the daemon performs its full key and directory validation. The root-owned,
executable regular `/usr/libexec/vinix-sshd` must exist. `/etc/ssh` is created
0700 if missing. An existing root-owned directory such as the standard 0755
`/etc/ssh` is accepted if group/other cannot write it; symlinks are rejected.
A host private key is **not** required in advance: the daemon creates its
persistent key using its existing safe creation path. The service arguments are
`--user USER --home /root/home/USER --host-key /etc/ssh/ssh_host_ed25519_key`.
The current root desktop session runs this daemon as root; this integration does
not add UID switching or confinement.

The service uses the existing guardian, process-group cleanup and
`/root/.vinix-service-logs/ssh-server.log`. Restart is `never`, so supervisor
retries cannot reset the daemon's in-memory failed-auth budget after failure.
An explicit user restart or broker restart still creates a new process/budget.
Existing conflicting service names/executables are preserved, and a full
32-service registry prevents insertion. Settings can persist service records;
the exact generated service shape is revalidated on broker startup and remains
disabled if the guard or opt-in fails. A persisted disabled setting is preserved.
The original optional-service change did not alter the kernel or general build tools.

### Disposable ISO qualification sources

`tests/sshserver/guest/main.v` is a **test-only** desktop replacement. In a new
disposable ISO only, move the actual desktop to `/usr/bin/vinix-desktop.real`,
install the statically compiled helper at `/usr/bin/vinix-desktop`, and install
only the host client's **public** Ed25519 key at
`/usr/share/vinix/m16b-client.pub`. Include the modified actual `vinix-session`
and daemon in their normal paths. The helper shares the encrypted-home guard,
creates private `/root/home/m16b/.ssh`, exclusively creates `authorized_keys`
0600 and the exact opt-in 0600, prepares `/etc/ssh`, and execs the real desktop
with libc argv. It never launches SSH directly and never seeds a private key.
Exclusive seed creation deliberately rejects reused/partially seeded HOME disks.

`tests/sshserver/controller/main.v` adapts the secure Wire/QMP/Secrets utilities
and exact enrollment keystroke flow from `tests/fullstack/controller.v`. Build
it as a host V executable and invoke with three absolute, nonsecret paths:

```text
CONTROLLER RUN_DIR ISO POST_UNLOCK_CALLBACK
```

The Linux host requires KVM, `qemu-system-x86_64`, OpenSSH, and the matching
`/usr/share/edk2/x64/OVMF_CODE.4m.fd` / `OVMF_VARS.4m.fd` pair. RUN_DIR must not
exist. The controller makes it private/exclusive, creates a new 128 MiB HOME
raw disk on ide.0 (`/dev/sd0`), boots the ISO on ide.2 with q35/OVMF/4 vCPU/4 GiB,
and uses virtio-net user networking with
`hostfwd=tcp:127.0.0.1:22289-:22`. It records actual QEMU argv and nonsecret block
metadata. COM1 is a nonsecret log; COM2 is a private unix socket whose contents
are never logged. The ISO must enable the diagnostic `/dev/sd0` enrollment gate,
`home_test_bridge` and `home_mask_enrollment_words`.

The 12-word bridge frame and generated optional password stay in locked memory,
are entered one key at a time through the existing verified QMP sequence, and
are wiped on every exit (and immediately after op12). Core dumps and Linux
process dumps are disabled. The test init first runs the seed executable with
`--preunlock-probe`, before launching the HOME gate. That probe requires the
HOME guard to deny access and an actual guest-loopback TCP connect to port 22
to fail with `ECONNREFUSED`. It writes the fixed receipt
`M16B-PREUNLOCK: CONNECT_REFUSED locked_HOME=true` to COM1.
The controller requires both that guest receipt and a failed pre-enrollment
OpenSSH attempt. Slirp owns the host listening socket throughout the boot, so
the outer attempt may report reset or closed instead of refused. A host reset
alone, an auth rejection, or a timeout cannot satisfy this gate.
After op12 the controller allows at most 180 seconds for an SSH banner, then
runs the parent-supplied executable callback once, bounded to 2100 seconds.
It exports only nonsecret connection/path settings:
`SSH_HOST=127.0.0.1`, `SSH_PORT=22289`, `SSH_USER=m16b`, `SSH_RUN_DIR`, and
`SSH_KEY=/home/agent/build/m16b-receipts/host-interop-r1/client` (path only; the
controller never reads the private key). The callback must return nonzero on
any failed check and must perform actual OpenSSH exec/status, a real shell PTY
using `setsid ssh -tt` with pipe input, wrong/no-key rejection, 20 sessions,
`scp -O` 50 MiB each way with remote `sha256sum`, and recursive SCP roundtrip.
A callback exit zero alone is not evidence of those individual criteria;
preserve its individual receipts for parent review. Existing Linux receipts
should not be repeated as substitutes for this guest qualification.

QEMU is quit through QMP, then killed if needed within bounded cleanup; real
child exits are printed. `status.txt` contains fixed stage receipts plus model
and elapsed time. The controller never resumes a completed run or reuses a HOME
disk. The parent owns ISO generation, musl/service builds, remote execution and
final qualification. Source checks and parser tests do not establish guest
acceptance: the final gate remains **NO-GO until every guest criterion passes**.

### Parent operator gate

The original Mission 16-B gate was NO-GO. In encrypted-HOME guest gq5, the actual
broker started SSH after unlock. Exec, status, PTY shell, 20 sessions and wrong/no
key rejection passed. The pre-unlock closed port returned errno 104 (reset), not
the strict refusal receipt. The 50 MiB guest upload exceeded the test timeout;
download, guest hashes and recursive guest SCP therefore remain unqualified.
Linux large-file/recursive receipts do not substitute for these guest checks.
The final report carries artifact hashes, raw receipt paths and cleanup proof.

### Stage 2 streaming ownership and refusal semantics

Stage 2 keeps the 256 KiB channel window and returns only consumed/discarded
input credit. It reuses bounded pending/SCP/output buffers, releases owned
packet temporaries, and copies borrowed input before releasing its packet.
MAC verification still precedes channel delivery. Separate directional states
use the existing V library's streaming HMAC API, avoiding the one-shot API's
payload-sized retained allocations in a `-gc none` worker. No cipher, protocol
algorithm, key format, or authentication policy is replaced.

The small kernel fix maps lwIP ERR_RST to ECONNREFUSED only while an active
connect is pending. Established resets retain ECONNRESET. RFC 9293 section
3.10.7.3 describes a reset but does not assign a numeric errno; Linux's
connect(2) ABI specifies ECONNREFUSED when nobody listens. The regression tests
the production error callback and SO_ERROR read/clear path separately from
the real guest-loopback refusal and post-unlock-success probes.

The callback's per-command budget is 900 seconds. `SSH_STAGE2_ONLY=1` avoids
repeating the prior accepted shell/auth/session suite, without waiving transfer
or refusal gates. Optional test-only `SSH_STAGE2_DIAGNOSTICS=1` samples process
accounting to nonsecret COM1, and `SSH_STAGE2_PCAP=1` enables a QEMU packet dump.
These are diagnostics, not production service settings or qualification passes.
The Stage 2 report owns the final verdict and measured before/after results.
