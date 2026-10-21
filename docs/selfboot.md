# Mission14-B offline host installer/updater

`tools/selfboot/` builds a real native V executable. Its v1 writable surface is
**explicitly named, precreated, blank regular sparse image files on Linux**.
Raw/block devices are refused before opening; live raw-device support is absent.
There are no mount, loop setup, VM management, PVE, kernel build, or installed-root
formatting operations. This tool does not install an OS from an initramfs: it clones
an existing, offline, installed VJFS root image. The parent must provision that
source and qualify the resulting disk with disposable QEMU.

Build and test with the supplied compilers:

```text
/Users/jefferson/.hermes/profiles/vinix/cache/scratch/v-ui2-qualification/v -o /private/tmp/selfboot tools/selfboot
/Users/jefferson/.hermes/profiles/vinix/cache/scratch/v-ui2-qualification/v test tools/selfboot
SELFBOOT_BUNDLE_INTEGRATION=1 /Users/jefferson/.hermes/profiles/vinix/cache/scratch/v-ui2-qualification/v -stats test tools/selfboot
```

On Linux use compiler `6af2727` (set its actual absolute path below):

```text
/ABS/v -prod -o /ABS/selfboot /ABS/vinix-selfboot/tools/selfboot
/ABS/v test /ABS/vinix-selfboot/tools/selfboot
SELFBOOT_INTEGRATION=1 /ABS/v test /ABS/vinix-selfboot/tools/selfboot
```

Use `-prod` when building the executable for multi-gigabyte images. Unoptimized
V SHA-256 makes the deliberately repeated whole-image verification very slow.

## Firmware requirement

Keep firmware variable storage separate from the ESP. For QEMU/OVMF, copy the
matching `OVMF_VARS.4m.fd` template to a private writable file and attach it as
the second pflash unit, alongside read-only `OVMF_CODE.4m.fd`. A code-only OVMF
boot can create or modify `/EFI/NvVars` on the ESP. That changes the recorded
whole-ESP hash, and the updater correctly refuses it as an unowned modification.
Do not bypass that refusal or rewrite the ownership checksum to accept changes.
Use proper firmware variable storage from the first boot. Real firmware that
writes unrelated files to the ESP is outside this v1 updater's supported surface.

macOS supports building, bundle creation, planning, inspection and portable tests;
install/update fail closed there. Linux operations need visibility into every
host process's `/proc/PID/fd` and `/proc/PID/maps`, the host mount namespace and
`/sys/block`. Run on the actual host, normally as root, outside restricted PID or
mount namespaces. Inaccessible process/loop evidence is an error. A container's
partial `/proc` cannot establish that an image is offline on its host.

## Operations manifest

| Command | Reads | Creates/writes | Activation |
| --- | --- | --- | --- |
| `plan` | locked source signature, journal, geometry | stdout | none |
| `inspect` | locked target identity; optional source geometry | stdout | none |
| `bundle` | pinned ISO; optional independently pinned kernel | private sibling directory, four payloads and `manifest.json` | directory rename to previously absent output |
| `install` | fully zero-scanned target; locked installed source; trusted bundle | private sibling full disk and 1 GiB FAT32 image | atomic rename over the blank target |
| `update` | owned target GPT/metadata/ESP, unchanged marker and valid VJFS journal; trusted bundle | private sibling full disk copy and updated whole ESP | atomic rename over the owned target |

Only direct argv calls to native `xorriso`, `gzip`, `tar`, `mformat`, `mmd`, and
`mcopy` are used. No shell or interpreter is started by this implementation.
GPT, protective MBR, CRC32/CRC32C, hashing, sparse copying, markers, ownership,
locking, offline checks and transactions are V. Helpers' nonzero exits abort.
The native helper search path is the operator's `PATH`; use trusted installed
binaries. mtools runs with `MTOOLSRC=/dev/null` and a nonexistent home.

## Bundle and trust

```text
/ABS/selfboot bundle --iso /ABS/vinix.iso --iso-sha256 HASH64 --output /ABS/bundle-a
/ABS/selfboot bundle --iso /ABS/vinix.iso --iso-sha256 HASH64 --output /ABS/bundle-patched --kernel /ABS/patched-vinix --kernel-sha256 KERNEL_HASH64
```

All hashes are exactly 64 lowercase hexadecimal digits. Output must not exist.
Only `/EFI/BOOT/BOOTX64.EFI`, `/boot/vinix`, `/boot/initramfs.tar.gz`, and
`/boot/limine.conf` are extracted. The flat output contains `BOOTX64.EFI`, `vinix`,
`initramfs.tar.gz`, `limine.conf`, and a canonical `manifest.json`. Its SHA-256 is
printed as `manifest-sha256`. The manifest records ISO provenance, per-file hashes,
the optional override hash explicitly bound to the actual kernel, and image ID.

Install/update require `--bundle-sha256` containing an **independently trusted
manifest hash**. Self-generated checksums alone provide no authenticity. This
is not Secure Boot signing or verification. No signature enrollment is performed.
Inputs must be regular single-link files, without symlink path components, and
the bundle must contain exactly those five files. Every file is snapshotted to
private staging, checked against the trusted manifest and validated before use.
The manifest must retain the canonical encoding emitted by `bundle`.

Kernel validation requires little-endian ELF64 amd64 ET_EXEC/ET_DYN; EFI requires
PE32+ amd64 EFI application headers. These are format checks, not proof of kernel
policy compatibility. The gzip must have the repository's exact FCOMMENT profile
`vinix-image-id=16lowerhex`, pass `gzip -t`, and contain exactly that ID followed by
one newline in archive member `./.vinix-image-id` (`tar -xOzf`, bounded
output). Mismatches, duplicate archive markers and extra config directives fail.
Only the literal `build-support/limine.conf` profile with `.tar.gz` and optional
exact `cmdline: vinix.disk=auto` is accepted; arbitrary ISO command lines are
refused. Each payload must fit FAT32 and their total must fit the 1 GiB ESP.

## Source and disk geometry

```text
/ABS/selfboot plan --source /ABS/installed-root.img
```

The source must be an already installed **offline private VJFS** image, at least
4 GiB, length divisible by 4096, with signature `0x4a56` at byte 1080. The host
validates the fixed-end 4 MiB journal's magic/version/page size, CRC32C, volume
geometry and UUID against the superblock. A nonzero pending commit page is refused;
recover in a guest and shut down cleanly first. The first 512 source bytes must
be zero. Source is opened read-only, exclusively locked and never stamped.

`--source-image-id HEX16` is a required **operator assertion of the installed
source's actual `/.vinix-image-id`**. The host does not walk VJFS inodes or prove
source userland provenance. Inspect that file in the provisioning guest before
shutdown. Bundle gzip/archive identity is verified separately; it can legitimately
differ from this predecessor ID. The kernel must enforce actual installed ID,
marker, token, geometry, pending-target and predecessor agreement at boot.

Geometry uses 512-byte sectors, a protective MBR, 128-entry primary and backup GPT
tables and CRC32 headers. ESP type is standard EFI System; root type is Linux
filesystem. Partition starts are aligned to 1 MiB:

| Region | Byte offset | Byte length |
| --- | ---: | ---: |
| Primary GPT | 512 | header plus 16 KiB entries |
| Selfboot ownership metadata | 32768 | 65536 |
| FAT32 ESP | 1048576 | 1073741824 (1 GiB) |
| VJFS root clone | 1074790400 | exactly source length |
| Tail/gap and backup GPT | after root | disk rounded up to 1 MiB plus 1 MiB |

For a 4294967296-byte root, exact disk length is **5370806272** bytes. `plan`
prints `required-target-bytes` for other sizes. Precreate a new, private regular
file using native `truncate` with the printed length, then inspect it. Do not
reuse a path containing valuable data. The installer scans **every byte**, including
sparse holes; even one nonzero byte is refused. Extra disk capacity is refused.

```text
truncate -s 5370806272 /ABS/new-disk.img
/ABS/selfboot inspect --target /ABS/new-disk.img --source /ABS/installed-root.img
/ABS/selfboot install --target /ABS/new-disk.img --expect-dev DEC --expect-inode DEC --expect-bytes 5370806272 --source /ABS/installed-root.img --source-image-id HEX16 --bundle /ABS/bundle-a --bundle-sha256 MANIFEST_HASH64
```

Copy the decimal `dev`, `inode`, and `bytes` from `inspect`; all three exact
confirmation fields are mandatory. They are displayed again before writes.
Paths must be normalized absolute paths with real parents and no control bytes. Symlinks, hardlinks,
foreign/nonblank targets, geometry mismatches, open descriptors, memory mappings,
mount sources and loop backing identities are refused. Source has the same
offline/live checks. All existing files use opened descriptors, nonblocking
exclusive `flock`, and path/fd pre/post stat identity checks including nanoseconds.
Advisory locks cannot stop an uncooperative process from opening a file later:
the operator must keep both images offline for the entire command. Namespace
isolation and hostile changes to parent directories are outside this v1 surface.

The root is copied and hash-verified byte-for-byte, then only the clone's first
512 bytes are stamped. All root bytes after byte 511 remain source-identical.
No filesystem is resized or formatted. Root marker schema:

| Root-relative bytes | Value |
| --- | --- |
| 0..15 | exactly ASCII `VINIX-SYSDISK-1\n` (16 bytes, no NUL) |
| 16..47 | 32 lowercase hex digits, crypto-random token |
| 48..63 | 16 lowercase hex digits, **root partition byte length** |
| 64..79 | 16 lowercase hex digits, asserted source/bootstrap image ID |
| 80..511 | all zero |

## Boot configuration and update

Immutable generation directories are `/boot/g-MANIFEST_SHA256/` on the ESP. They
contain the four payloads and exact trusted manifest. `/EFI/BOOT/BOOTX64.EFI` and
`/boot/limine.conf` select the active generation. Config is generated literally:

```text
timeout: 0
verbose: yes

/Vinix
    protocol: limine
    kernel_path: boot():/boot/g-GENERATION_HASH64/vinix
    module_path: boot():/boot/g-GENERATION_HASH64/initramfs.tar.gz
    resolution: 1024x768x32
    kaslr: no
    cmdline: vinix.disk=auto vinix.sysroot=TOKEN32 vinix.disk_from=PREDECESSOR16
```

Initial predecessor is the asserted source ID. On update it is the active
bundle image ID. The root token and bootstrap marker remain constant. Host
staging does not modify installed userland; the compatible kernel must perform
the permitted transition after boot and keep a durable pending target so an old
boot generation cannot consume a newer pending update. It must never format the
selected root. This host tool alone does not prove those kernel properties.

```text
/ABS/selfboot inspect --target /ABS/new-disk.img
/ABS/selfboot update --target /ABS/new-disk.img --expect-dev DEC --expect-inode NEW_DEC --expect-bytes 5370806272 --bundle /ABS/bundle-b --bundle-sha256 NEW_MANIFEST_HASH64
```

Activation changes the target inode, so inspect again after every success. The
updater requires owned canonical metadata bound to GPT geometry, token, bootstrap,
active/prior generation, complete generation/image-ID history, active trusted
manifest, generated config hash and whole-ESP hash. It verifies existing config,
EFI loader and active generation files. Guest changes to root contents are
accepted when marker, VJFS and geometry stay valid. It copies the entire current
disk (including that changed root), updates a separate whole ESP, verifies new
files/config and retained prior payloads, and rechecks root equality before rename.
Prior directories remain; no pruning is implemented. Space/history exhaustion
fails before activation. The same verified generation is a no-op; previously
seen generations or older image IDs are refused, including repackaged old IDs.
A new patched kernel for the current image ID is permitted.

Keeping an old boot directory is **not userland rollback**. After a guest userland
transition, actual rollback requires restoring a complete offline root/disk backup;
the predecessor policy should refuse the old config as a downgrade.

## Recovery and interruption testing

Both install and update stage a complete sibling disk on the same filesystem.
FAT changes happen only in a private 1 GiB ESP image: immutable payloads first,
then staged loader/config, readback verification, ownership, full disk verification,
file `fsync`, final offline/stat checks, atomic rename, published identity check,
and parent directory `fsync`. Before rename, the original target is untouched:
interrupted install leaves the blank target retryable; interrupted update retains
the entire old config, generation and root. After rename, the target is a complete
new generation. An error explicitly beginning `ACTIVATED` means rename succeeded
but a post-activation check/fsync failed; inspect before retrying. Power-loss
durability relies on local filesystem atomic rename/fsync semantics. Network
filesystems and storage that lies about flushes are not qualified.

Every install/update accepts these exact pre-activation phases:

```text
validated
root-copied
payloads-staged
config-staged
verified
before-activate
```

`--interrupt-after=PHASE` returns nonzero at that phase and cleans its stage.
`--pause-at=PHASE --ready-file=/ABS/nonexistent.ready` creates the ready file
containing PID and phase, fsyncs it, and waits in native V. Send SIGKILL to that
PID for real process-interruption proof; alternatively remove the ready file to
resume. Final offline checks repeat after the pause. There is deliberately no
post-activation interrupt failpoint. Example (append to a complete install/update):

```text
--pause-at=before-activate --ready-file=/ABS/selfboot.ready
```

After SIGKILL, only the private `.selfboot-*` sibling directory and ready file
may remain. Confirm the process is gone, inspect the original target, then remove
that exact abandoned directory/file manually. They are never auto-resumed or used
by retries. Sparse staging still needs room for the full allocated disk plus a
1 GiB ESP and payload snapshots; verify free capacity first.

Portable host tests cover helper exit failures/bounded output, bundle trust and
corruption, archive/comment agreement, ELF/PE/profile checks, GPT geometry/CRCs,
marker schema, VJFS journal corruption/pending records, file refusal/locking/stat
checks, sparse copying, confirmation, stale updates and all failpoint names.
`SELFBOOT_BUNDLE_INTEGRATION=1` also creates a tiny native xorriso ISO and exercises
real bundle extraction, pinned kernel override and trusted manifest readback.
`SELFBOOT_INTEGRATION=1` adds actual mtools FAT ordering, interrupted install/retry,
interrupted update/activation, prior-generation retention and changed-root
preservation with disposable synthetic sparse fixtures. Those fixtures are not
bootable OS roots. Parent validation must separately use compiler `6af2727`, real
installed source/ISO, real SIGKILL pauses and disposable fecv3 QEMU boots. Host tests
are not evidence that the kernel boots, transitions userland or handles power loss.
