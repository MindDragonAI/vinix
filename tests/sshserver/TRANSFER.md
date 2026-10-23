# SCP and encrypted-HOME transfer proof

Use the production V compiler on fecv3. These programs use V and real OpenSSH
clients; no acceptance source, assertion or allocation allowlist is changed.

`transfer/main.v SERVER FRESH-DIR` creates an exclusive loopback fixture on
port 22396 with a correctly framed private host seed and pinned public key.
It times 50 MiB `scp -O` upload and download, computes the source and readback
SHA256 on the host, checks the remote digest within 30 seconds, then checks
20 sequential sessions, separate stderr and exit status 7, a PTY with the
acceptance client's stripped environment, wrong/no-key denial, and a 210-second
session. The daemon writes to a file, so unread diagnostic pipes cannot block
it. The fixture contains private test keys: retain those locally on the builder,
and copy only the explicitly selected nonsecret receipts.

Build the daemon exactly as follows in a private source root:

```sh
/home/agent/code/v/v -prod -gc none -d no_backtrace -d no_segfault_handler \
  -d ssh_session_workers -path "$PWD|@vlib|@vmodules" \
  -o sshd.c tools/sshserver
clang -O2 -D_GNU_SOURCE -w sshd.c -pthread -lm -o sshd
/home/agent/code/v/v -cc clang -gc none -d no_backtrace -d no_segfault_handler \
  -o transfer tests/sshserver/transfer
./transfer "$PWD/sshd" "$PWD/host-fresh"
```

`xts-throughput/main.v` isolates the production kernel cipher from SSH and
disk. Compile with `-prod` and the search path
`@vlib|@vmodules|/ABS/PRIVATE-ROOT/kernel` (vlib must precede kernel's `time`
module), then clang `-O2`. It prints both directions and verifies a round trip.
It is a microbenchmark, not guest transfer proof.

`xts-scalar/main.v` removes the V userspace runtime and floating-point rate
formatting so the cipher can be compiled with SIMD disabled, as in the kernel:

```sh
/home/agent/code/v/v -prod -shared -no-builtin -no-closures -os vinix \
  -arch amd64 -target-libc-headers -nofloat -gc none -manualfree \
  -path "@vlib|@vmodules|$PWD/kernel" -o xts-scalar.c tests/sshserver/xts-scalar
clang -O2 -D_GNU_SOURCE -w -mno-sse -mno-sse2 -mno-mmx xts-scalar.c -o xts-scalar
./xts-scalar
```

It records integer nanoseconds for 1 MiB per direction and checks its round
trip. This isolates the primitive; guest disk I/O must still be measured.

`tests/storage-volumes/aesxts_test.v` runs with a copy of `kernel/aesxts/core.v`
and `aesxts_vectors.rsp` in a scratch module. Generate its C **without `-prod`**
to keep assertions enabled, then compile with clang `-O2`. It checks all S-box
inputs in all four parallel blocks, polynomial squares against
general multiplication, FIPS AES, 60 NIST XTS vectors, an independent library
oracle, sector sizes, offsets, chunking, canaries and rejected arguments.

`transfer-verify/main.v PRIVATE-ROOT build|build-aarch64|verify-builds|host|xts|observer` saves commands, outputs and
exit statuses. `build` expects separate, already prepared `kernel` and
`kernel-aarch64` trees with their architecture-matching dependencies; it never
copies an x86 runtime into ARM. It copies the changed cipher and encrypted I/O source to ARM, touches
both changed sources, discards stale generated blob C/object files, generates
the x86 heap sampler first, and runs the required production make commands.
Use a private root; this runner intentionally regenerates build products.
`verify-builds` checks both actual make exits, both current source hashes,
generated C/object/ELF freshness and the new generated symbols.

`transfer-guest/main.v` is an optional diagnostic callback for the unchanged
M17-C controller, using its existing `M17C_RUN` and `M17C_KEY` environment.
It compares identical 50 MiB tmpfs and encrypted-HOME transfers, records a
separate digest's actual duration with a diagnostic 900-second bound, and
collects nonsecret daemon counters and memory statistics. It writes only
`scp-proof.receipt`, **never `acceptance.receipt`**: the controller's combined
acceptance verdict remains a failure even when this diagnostic proof passes.
This distinguishes measuring an existing timeout from qualifying unchanged
acceptance assertions. Run the original acceptance worker for qualification.
With `M17C_ORIGINAL_ACCEPTANCE` set to that original binary, this same callback
instead observes the unmodified worker, forwards its exact exit status, saves
the last observed timing for each command, and collects daemon counters only
after it exits. It neither supplies nor substitutes any acceptance receipt.
The `observer` verification mode prepares a private parent environment for
this mode and records the original worker's SHA256. Progress timing samples
are lower bounds within the worker's 50 ms polling interval and observer's
25 ms polling interval; the daemon's completed-session timings provide a
separate measurement.

The existing V `tests/pty-posix/guest-proof.v` packages a private production ISO,
checks extracted kernel/daemon identities and preserves the production home
gate, then provisions/installs a disposable GPT disk and runs the unchanged
literal-ISO controller. Use its `package` and `run` modes in an ordinary fecv3
shell, with the new private root and a new package directory. Its inputs and
the exact invocation used for this repair are recorded in the transfer report.
No deployment or Proxmox operation is involved.
The final combined candidate uses the original parent environment and acceptance
binary directly. A separate read-only progress observer records command timing;
it supplies no receipts or acceptance inputs. The report records any expired
external test fixture and the exact fresh smoke retry, preserving failed runs.

`encrypted-io/verify.v REPO KERNEL-SOURCE FRESH-PROJECT` copies
`KERNEL-SOURCE/fs/storage_crypt.v` verbatim into a host module. Its adapters
count backend calls, enforce locking, simulate removal/errors/short I/O and
allocation failure, and check full workspace erasure and balanced budget
release. It uses the real current AES-XTS implementation and checks data-unit
numbering/ciphertext, caller plaintext, bounds and both native sector sizes.
Run against the pre-fix source for an expected failing command-count control,
then the patched source for a passing regression. Build/run the V verifier
with `/home/agent/code/v/v -cc clang`; it records generation/link/test exits.
The control and patched runs must use distinct fresh project directories.
