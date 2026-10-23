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

## Stage 3 parent qualification — 2026-10-22

GO for the requested SSH qualification. The Stage 1/2 NO-GO results above are
retained as historical evidence. The first error was traced to the compositor's
300 ms control-reply deadline, not an SSH channel arithmetic failure. Commit
`ae6fa9ec` retains an idle outstanding reply without reconnecting, replaying a
request, or accepting a partial frame. Seven focused regression functions,
eight daemon test files, the final static daemon self-test, the opt-in parser
and the unchanged TCP errno regression passed on fecv3. A separate static
review found no concrete security or correctness blocker.

Final `gate-r2` passed actual encrypted-HOME 50 MiB upload, guest hash, download,
host hash, recursive copies and three guest/host tree comparisons. It then
kept a fresh SSH session open for 210.302 seconds with before/after markers.
Upload took 393.311 seconds (0.133 MB/s); download took 101.300 seconds
(0.518 MB/s). Callback, controller and QEMU cleanup exited zero. The ISO and
guest binaries were unchanged between the first fixed run and this rerun;
only a stdout/stderr capture-order bug in the callback was corrected. The
first fixed run's independently verified matching hashes are also retained.

Both fresh production kernel builds exited zero. No kernel source changed
in Stage 3. The allocation scan still fails its absolute allowlist with the
same 175 baseline groups; the exact sorted NEW findings match, and
`allowed.txt` is untouched. No clean-allocation or 1 MB/s upload claim is made.

All owned QEMU processes and forwarded test listeners were gone at cleanup.
Full report and checksummed receipts use the `m16b3-*` prefix in the active
`vinix-b` profile. No push, PR, PVE change or deployment occurred.
