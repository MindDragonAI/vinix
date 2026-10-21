# Mission15 controller

Linux/KVM on fecv3 only. The parent provisions the prepared selfboot GPT system
image and fixture; this controller performs no build, installer, remote, or ISO
operations. Compile on the Linux host with the current V compiler:

```sh
v -o /absolute/controller tests/fullstack/controller.v
/absolute/controller /absolute/new-run /absolute/prepared-boot.img /absolute/kernel /absolute/new-home.img
```

RUN_DIR and HOME_DISK must not exist. HOME_DISK is created as a blank 128 MiB
file. The fixture must enable `home_test_bridge`, `home_guest_probe`, and
`home_mask_enrollment_words`, and install the existing
`tests/encrypted-home/disk_probe` unchanged as
`/usr/libexec/vinix-home-qualify`. Its historical `M14A-MARKER.TXT` filename is
intentional; the content is the Mission15 marker. Masking is a provisioning
requirement: the bridge protocol does not attest the fixture's build flags.

The controller copies the matching `/usr/share/edk2/x64/OVMF_CODE.4m.fd` and
`OVMF_VARS.4m.fd` into the private run directory once, preserving VARS through
three separate QEMU processes. It attaches system/home at ide.0/ide.1 with no
default devices or optical drive, and gives the system disk `bootindex=1`.
Boot 1 enrolls and writes/fsyncs the marker;
boot 2 denies three wrong phrases and a wrong password, switches back to phrase
mode, and reads the existing marker; boot 3 unlocks by phrase and reads it again.
No later boot writes or renews the marker. The existing probe verifies exact
bytes, EOF, and the encrypted ext2 mount. Each boot also requires the installed
`/dev/sd0-1` serial receipt and a framed, nonempty 16-lowercase-hex
`/.vinix-image-id`, identical across boots.

Each boot retains raw COM1 serial, actual `/proc/PID/cmdline` argv as JSON,
validated `query-block` JSON, and screenshots at the masked enrollment, denial,
locked, unlocked, and desktop marker gates as applicable. COM2 and the QMP
stream are private and never logged. Credentials remain in locked memory and
are erased on exit. Every successful stop requires QEMU dead, successful exit,
and fsync of both images and private VARS. A failed check exits nonzero;
deferred cleanup stops only the controller-owned QEMU process. Offline image
scanning and screenshot review remain with the parent.
Startup and enrollment-timeout frames are also captured under the mandatory
masked-fixture contract. The terminal image-ID command adds its own delimiter
newline because sysdisk's committed ID is not newline-terminated. Keep every
failed run directory; a fresh retry must not erase or relabel the old attempt.

Transport selftests use only synthetic data and local socket pairs:

```sh
v -d m15_selftest -o /absolute/controller-selftest tests/fullstack/controller.v
/absolute/controller-selftest
```

Guest execution and Linux compilation must be performed by the parent. Local
macOS validation can check V types and run the transport-only selftests.

Source-root preparation is a separate, diagnostic-ISO-only controller:

```sh
v -prod -o /absolute/source_provision tests/fullstack/source_provision.v
/absolute/source_provision /absolute/receipts /absolute/diagnostic.iso
# Only for this controller's existing, stopped disposable source:
/absolute/source_provision /absolute/receipts /absolute/diagnostic.iso --resume
```

It creates a new 4 GiB regular source image and private firmware variables in
the existing receipt directory. It attaches that source and the diagnostic ISO,
but no HOME disk. Source installation/recovery is complete only when the kernel
root receipt and the real auth-supervisor receipt both occur in this attempt's
unique UART log. The old plaintext-init desktop banner is intentionally absent
from the merged auth stack. A 600-second hard bound and 120-second no-progress
bound distinguish a large active install from a stalled one. Resume refuses an
open source. Successful completion captures the source gate, stops its owned
QEMU process, fsyncs the raw image, and hashes it. The source screenshot is the
expected no-HOME error surface, not an unlock or desktop-qualification receipt.
Use the offline installer on the stopped source before running the disk-only
controller. Source provisioning with an ISO is not the no-ISO boot proof.
