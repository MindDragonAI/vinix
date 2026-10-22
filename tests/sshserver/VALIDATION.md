# Lane 2 source validation — 2026-10-22

Requested model/lane: gpt-6.1-sol, Mission16B implementation lane 2.
Started: 2026-10-22 21:05:35 UTC. Validation complete: 21:14:37 UTC.
Elapsed to validation: 542 seconds (9m02s), within the 15-minute lane.
Workspace: /Users/jefferson/vinix-ssh-server, branch services/ssh-server.
Compiler used: /private/tmp/vinix-ext4-v/v, V 0.5.2 6af2727.

Verified locally:

- Final opt-in parser tests: PASS, one test file / two test functions;
  compiler/test runner exit 0. Latest run: 2385 ms total, 176.499 ms runtime.
- Actual desktop session service module: source check PASS with
  `-new-compiler -enable-globals -gc none -manualfree` and repo include path.
- Diagnostic seed launcher: source check PASS including Linux target and the
  production manual-memory flags.
- ISO host controller: source check PASS including Linux target.
- Both helper sources also compiled as local host executables during development;
  these temporary outputs were removed. They were not installed or deployed.
- `git diff --check`: PASS. Existing broker diff is exactly one added call
  immediately after `load_services()`. Documentation changes are append-only.

Not executed: KVM/ISO boot, encrypted HOME enrollment, strict pre-enrollment
refusal, actual guest broker startup, post-unlock SSH, callback acceptance,
50 MiB transfers, recursive SCP, or target musl/static builds. No ISO or callback
was supplied to this lane. Existing parent Linux interop receipts were not rerun.
The parent owns target builds, remote execution and the final acceptance gate.

Review points: the guard uses pinned NOFOLLOW descriptors, fixed bounded read
storage, root/private metadata checks and the existing encrypted-home contract.
Generated persisted service records are re-gated at broker startup; conflicting
user records are preserved. Restart is never. The controller rejects reset/EOF
instead of treating them as proof of refusal; some QEMU user-network stacks may
therefore fail that strict gate. Its callback exit-zero receipt does not replace
individual exec/PTY/auth/session/SCP receipts.

NO-GO pending real guest qualification. No daemon source edits, commits, pushes,
deployments, fleet calls, or SOUL/HEARTBEAT/mission-log changes were performed.

## Parent runtime follow-up

The earlier section is the lane's source-check receipt, not the final verdict.
The parent built both production kernels and a static musl daemon on fecv3.
Five final daemon host test files passed. Linux 50 MiB bidirectional and
recursive SCP passed with matching hashes. The final TCP close regression and
shared-worker failure-budget regression passed separately.

Disposable Vinix run `gq5` used real encrypted HOME enrollment and the actual
desktop broker. Exec, status 7, PTY shell, 20 sequential sessions, and wrong/no
key rejection passed. The guest returned reset/errno 104 before unlock, not
the strict ECONNREFUSED receipt. The guest 50 MiB upload reached its timeout
and exited 137. Guest download/hash/recursive checks did not run.

The callback failed, QEMU exited 0, and no forwarded test listener remained.
Final mission gate: NO-GO. See the parent report and preserved raw receipts.
