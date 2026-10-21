# Combined disk-only and encrypted-home qualification

This procedure is for disposable file-backed QEMU on fecv3 only. It does not
create or modify a PVE VM. Deployment remains a separate operator decision.

## Storage contract

The merged stack retains two distinct disks:

- A GPT system disk with an ESP and a marked VJFS root. `tools/selfboot` prepares
  it from a stopped, installed root of the new ISO. The root partition keeps the
  source's exact byte geometry. OVMF boots this disk with no ISO attached.
- A separate blank whole-device HOME disk, at least 64 MiB and less than 4 GiB.
  The fresh-home supervisor does not support a HOME partition or encrypt the
  boot/system disk. Do not describe this as full-disk encryption or one-disk
  provisioning.

The disposable rig puts the system disk at `/dev/sd0` and HOME at `/dev/sd1`.
The ISO must contain a private root-owned 0600 `/etc/vinix/encrypted-home` with
these two lines:

```text
/dev/sd1
enroll
```

`enroll` permits only a completely blank HOME disk. A valid existing header
still requires unlock. Device numbering is an explicit provisioning contract,
not stable-UUID discovery. Never reuse this configuration against arbitrary
attached storage.

## Build and provenance

Use the existing `scripts/build-amd64.sh`, `scripts/build-aarch64.sh`, and
`scripts/build-desktop-amd64.sh --with-firefox --no-iso` paths. Build both
production kernels in private architecture-specific directories. On fecv3 use
its working V compiler and `LD_LLD=/usr/bin/ld.lld`. Existing package layers can
be read from the builder, but keep writable userland and desktop output private.

The desktop staging root is `build-amd64-desktop/initramfs-root`, not `staging`.
Add the explicit HOME configuration before creating the final ustar archive.
Package that archive with `build-support/build-amd64-iso.sh`; this preserves the
image-ID and gzip-comment protocol validated by the offline installer. Record
SHA256 for both kernels, ISO, trusted installer bundle, and final raw images.

The production gate has no secret UART bridge. For automated qualification,
create a separately named diagnostic ISO from the same staged production root:
replace only the gate with a build enabling `home_test_bridge`,
`home_guest_probe`, and `home_mask_enrollment_words`, and add the unchanged
`tests/encrypted-home/disk_probe` executable. Retain an exact root-tree
comparison. The diagnostic gate does not bypass enrollment or authentication.
Do not deploy this diagnostic ISO or present it as a byte-identical production
boot receipt. Never save the normal production phrase display or the COM2 stream.

## Qualification and receipts

See `tests/fullstack/README.md` for the Linux controller. Prepare a stopped
source root from the diagnostic ISO, then use the merged `tools/selfboot`
executable to create a new regular GPT disk image. Keep the bundle's image ID
as an explicit source-ID assertion; verify the actual installed image ID in
the disk-only guest. The installer itself does not inspect VJFS inodes.

Use a matching private writable OVMF VARS file from the first boot. Do not let
firmware store variables on the ESP. The controller records actual process
arguments and validates the block list. It requires no optical device, real
12-word enrollment, wrong/reordered phrase denial, phrase unlock after two cold
power-offs, and identical fsynced marker readback. Each cold boot is a new QEMU
process, not a reset or saved RAM state. QMP quit is not a physical storage
power-cut qualification.

After the controller exits successfully, run:

```text
v -prod -o /absolute/offline_scan tests/fullstack/offline_scan.v
/absolute/offline_scan /absolute/run /absolute/system.img /absolute/run/home.raw
```

The scanner requires all three readbacks and successful stopped-guest receipts.
It checks the plaintext positive control, rejects open images, and scans every
logical byte of BOTH raw images, including the unencrypted system disk. An I/O
error is not a zero-match result. Preserve raw serial, masked enrollment and
gate screendumps, the exact scanner output, artifact checksums, failures, fixes,
and a complete receipt manifest in the mission report.

Also run `tests/kernel-allocs/run.sh` without changing `allowed.txt`. An unchanged
failure relative to freemick is evidence of no allocation regression, not a green
absolute allocation gate. Do not hide it or turn it into an automatic deployment
approval.
