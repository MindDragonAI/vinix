# Fresh encrypted home

Mission 14-A adds `/usr/libexec/vinix-home-gate`, built from the volume module
with `-d vinix_home_gate`. Both desktop init paths invoke it before any desktop
or session helper. It supervises a separate framebuffer greeter and launches
the native desktop only after mounting the encrypted mapper at `/root`.
Supervisor or desktop termination requires reboot. There is no shell fallback,
automatic supervisor restart, migration, or in-place relock claim.
Init stops the supervisor's process group if it exits, including orphaned
greeter or desktop children.

## Explicit provisioning

The operator must stage `/etc/vinix/encrypted-home` as a root-owned, private
regular file (0600). Its contents are a single whole-device path, for example
`/dev/ata1`, terminated by a newline. Add a second line `enroll` to explicitly
authorize fresh enrollment. Do not stage a credential or data key.

Only a whole writable physical device of at least 64 MiB and strictly less than
4 GiB is accepted. Size must be divisible by 4096, with 512- or 4096-byte sectors.
That size ceiling keeps the fresh disk below sysdisk's automatic adoption limit.
Enrollment checks every byte for zero and refuses occupied disks. A malformed
or incomplete header never authorizes reformatting. A valid header always takes
the unlock path, including when the configuration still contains `enroll`.

The first MiB is public reserved space. The 4096-byte v1 header at offset zero
contains magic/version, slot count, complete device/mapper geometry, a generated
stable disk UUID, and one or two existing 320-byte authenticated volume
envelopes at offsets 128 and 448. Each envelope authenticates that same UUID
and geometry. The entire remaining extent, including VJFS's full journal, is
inside AES-256-XTS mapper slot 63. The UUID is an on-disk identity, not hardware
attestation or clone detection.

A random 64-byte data key is generated once per enrollment. Twelve independently
uniform 11-bit indices select from the reviewed 2048-word English vocabulary.
This is not a checksum-bearing wallet mnemonic. The supervisor normalizes only
phrases: ASCII case folding and whitespace collapsing, twelve full known words,
preserving order and repetition. Optional passwords retain exact bytes. Slots
use independently generated salts/nonces and the existing scrypt profile
(N=32768, r=8, p=3), ChaCha20 and HMAC-SHA256 envelope implementation. A password
slot is unwrapped and compared against the original key before publication.

The greeter displays the phrase locally, requires full confirmation, and asks
for acknowledgment of offline backup and lost-secret risk. Either enrolled
secret unlocks the same volume. Loss of all secrets or wrapping metadata can
lose the data. Boot and system files remain readable. XTS supplies no offline
tamper, rollback, or malicious-boot protection.

Formatting completes and flushes before the public header is published, and
publication precedes mounting: mounted-disk protection rejects whole-device raw
writes after mount. An interrupted initial publication can leave a rejected,
occupied disk; no applications or existing user data have been admitted then.
A successfully published header can unlock on the next boot and finish creating
the profile marker. Header backup/recovery management and slot/password changes
are not exposed in this first fresh-enrollment interface.

## Boundaries and APIs

`home_crypto.v` exposes only in-memory `home_wrap` and `home_unwrap`. Fixed buffer
contracts are identity 16, XTS key 64, entropy 28, envelope 320 bytes. Callers
retain and erase their credentials and returned keys. No credential-file path
is used by either API. The boot configuration reader reuses the private-file
reader only for the public device-selection configuration.

The supervisor owns phase, data key and one rate budget shared by both secret
modes. Three failures cause two seconds of delay; subsequent failures double
to a 300-second cap. It uses monotonic time, denies clock rollback, serializes
clients, and retains the budget across UI replacement. Cold boot resets the
budget; this is not offline-attack throttling or durable reboot throttling.

The private inherited Unix socketpair has no listener/path. Both endpoints
require kernel root peer credentials. Wire frames are little-endian u32 opcode,
u32 payload length, then at most 1024 bytes. Requests: 1 state, 2 enrollment
phrase, 3 confirmation (`u16 phrase length`, `u16 password length`, `u8 ack`,
phrase bytes, password bytes), 4 phrase unlock, 5 password unlock. Replies are
0 denied/unavailable, 1 locked, 2 enrollment, 3 accepted for activation. UI
acceptance never grants a session until mapper import and mount also succeed.
Credentials and the data key are absent from arguments, environment, persistent
temporary files, and diagnostics. Core dumps are disabled. Secret workspaces
are erased stack storage; scrypt uses its existing erased anonymous mapping.

Kernel ioctl `0x56560007` formats only a writable encrypted logical mapper.
It requires initial-namespace trusted CAP_SYS_ADMIN, securelevel below two,
and a destructive-extent reservation that excludes mounts, retained caches,
swap and competing raw writes. `fs.register_block_formatter` registers
`ext2.format` without an import cycle. No new kernel allocation is retained.
Ioctl `0x56560008` marks the boot sensitive before credentials exist, prohibiting
unencrypted hibernation even before a mapper is imported. Existing mapper import
is unchanged. The initial amd64 seed now uses the carry-checked hardware helper;
any failed draw erases the entire partial seed and leaves strict reads unavailable.

The desktop independently requires the expected `/root` mount and private
encrypted profile marker before any app/service/greeter dispatch. HOME or a
mode argument cannot authorize startup. The marker supplies profile metadata
only; no `.vinix-user` verifier is used as a key. `/tmp` is mounted as RAM-backed
tmpfs before desktop launch; the existing pager encrypts disk backing.

## Host qualification

Run the new self-contained V runner:

```
V run tests/encrypted-home/run.v /absolute/path/to/V
```

It compiles and runs the production home policy/crypto tests in normal and
`home_entropy_failure` builds, then extracts the actual production amd64 seed
function with its real erasure implementation. Seed tests fail every hardware
draw in turn and check complete erasure, then check success. Tests cover phrase
normalization/order/changed/unknown words, phrase-only and dual-slot unlock,
wrong exact-byte passwords, shared throttle and clock rollback, enrollment
entropy failure, malformed header/geometry, state denial and absence of plaintext
phrase/password/key in serialized metadata. A regular-file fixture tests the
complete blank-device scan, middle occupancy and short-read rejection.
`-nocache` isolates V's builtin cache from
kernel host fixtures.

The same runner stages the unchanged kernel mapper/formatter sources with
the repository's existing storage host fixtures and runs the production
volume tests, including the new formatter and early-sensitive-state cases.

The existing `volume-host` runner additionally copies `storage_format.v` and
tests formatter physical/plain-mapper rejection, writable/admin/securelevel
checks, mount exclusion and reservation lifetime. Its full AES oracle suite
requires the repository-compatible V library API.

## Guest qualification handoff

The existing volume staging path builds and installs the production gate for
both architectures. For a separate disposable probe binary, generate the same
module with `-d vinix_home_gate -d home_guest_probe`, then compile its generated
artifact using the existing volume tool flags and headers. Add
`-Wno-unused-const-variable` for V's duplicate string literals. Invoke that
explicit test binary with `--protocol-probe` as root. It uses real socketpairs,
forked clients, peer credentials and production `home_serve`, exercises both
slots and UI replacement across a real rate delay, and prints only a PASS line.
The production binary has no probe mode. `-d home_entropy_failure` is a separate
compile-time-only entropy-denial fixture; there is no environment fallback.

Remaining release evidence belongs to the parent: Linux static binaries and
kernels on both architectures, disposable fecv3 boots, graphical enrollment,
wrong-secret/crash/mount-failure tests, both-secret cold-boot data readback,
complete raw-disk marker/control scans including journal/unallocated space,
crash consistency and kernel allocation/desktop performance regression checks.
No guest, remote host, PVE VM or protected worktree was accessed by this lane.

## Changed files

```
build-support/init-aarch64/initcore/core.v
build-support/init-amd64/desktop-init
build-support/native-compat-tools/compathost/stage.v
build-support/native-compat-tools/compathost/volume_host.v
desktop/encrypted_home.v
desktop/main.v
desktop/registration_store.v
docs/encrypted-home.md
kernel/fs/ext2/ext2.v
kernel/fs/storage_control.v
kernel/fs/storage_format.v
kernel/krandom/random_amd64.v
tests/encrypted-home/run.v
tests/encrypted-home/seed_test.v
tests/storage-volumes/hostfixtures/fs/stubs.v
tests/storage-volumes/volume_test.v
tools/volumes/volumecli/core.v
tools/volumes/volumecli/HOME-WORDLIST-LICENSE
tools/volumes/volumecli/home_boot.v
tools/volumes/volumecli/home_crypto.v
tools/volumes/volumecli/home_policy.v
tools/volumes/volumecli/home_probe.v
tools/volumes/volumecli/home_supervisor.v
tools/volumes/volumecli/home_test.v
tools/volumes/volumecli/home_ui.v
tools/volumes/volumecli/home_words.v
```
