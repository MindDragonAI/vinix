Mission 15-B production smoke qualification

Status: IN PROGRESS. No GO and no deployment permission.
Tested product code: integration/m15-fullstack at 43ab7a61192bbb45757476e0ebc9f7ce583bb2c0.
Receipts: fecv3:/home/agent/build/m15b-receipts.

Step 1: artifact freeze and source boundary — PASS

The unchanged production ISO SHA256 was freshly checked on fecv3:
2dc7df1e3143962f2ddc28abcc80cd8f0b828585241816ebdaf4bb513ed348c2.
The gate extracted from that ISO and the staged production gate both hash to
80a57b1fa23b54cae0c02ae67a65057d1fdf0b200146221bb228eac377c3804b.
The extracted production root has no /usr/libexec/vinix-home-qualify.
Receipts: m15b-iso-freeze.sha256, m15b-production-gate.sha256,
m15b-production-payload.log, m15b-iso-extract.log.

Production compilation uses only vinix_home_gate:
build-support/native-compat-tools/compathost/stage.v:90-106.
The retained diagnostic build recipe is m15-evidence/sources/m15-fixture-build.v:18-23.
It adds home_guest_probe, home_test_bridge and home_mask_enrollment_words.
Both variants use the same V source. A fresh production C translation was compared
against the retained diagnostic C input. Full diff: m15b-gate-source.diff.
The executable checker is tests/fullstack/production_equivalence.v.
Its successful receipt, m15b-equivalence-v2.log, identifies 74 identical generated
functions, five changed functions, and three diagnostic-only probe functions.
The initial checker misclassified a struct declaration as a function; that failed
attempt is preserved in m15b-equivalence.log. The parser was fixed before PASS.

Identical security/storage paths (also required by the generated-C checker):
  Credential entropy and generation: tools/volumes/volumecli/home_supervisor.v:59-75.
  Enrollment validation and wrapped-key creation: home_supervisor.v:78-100.
  Unlock validation and shared failure budget: home_supervisor.v:102-115.
  Protocol dispatch: home_supervisor.v:160-184.
  Phrase generation/normalization/header validation: home_policy.v:64-123.
  Key derivation and envelope operations: home_crypto.v:6-30.
  Disk validation and supervisor startup: home_boot.v:148-195.
  Mapper import, format, fsync, header publication, mount: home_boot.v:47-92.
  Private temporary filesystem: home_boot.v:15-21.
The latter paths are identical generated functions, not just matching root filenames.

All generated differences were reviewed:
  home_ui: home_ui.v:153-157 changes only the enrollment text secret/masking flag.
  home_test_event: home_bridge.v:37-54 adds private COM2 frames plus nonsecret COM1
    event notices. Diagnostic transport failure can stop the UI/session; production
    returns true. This is fail-closed instrumentation, not equivalent availability.
  home_session_note and home_activation_failed: home_bridge.v:5-31 add nonsecret
    COM1 status notes and preserve errno. Their production bodies are no-ops/false.
  home_run: home_boot.v:198-201 adds an explicit --protocol-probe selftest entry.
    home_probe.v:8-67 uses private in-memory supervisor state, has no disk/mount
    operation, and is not selected by normal --boot or --ui arguments. The three
    additional generated functions are home_probe, home_probe_client and
    home_probe_round. This is test instrumentation; it must not be hidden behind
    an inaccurate claim that only one rendering boolean differs.
There is no unexplained normal-path authentication, derivation or storage change.
The separate marker probe is absent from production. Broader diagnostic test
results may be reused only within this stated boundary, not as production execution.

Step 2: allocation-policy exception — recorded; focused review pending

Jefferson explicitly accepted the existing allocation baseline for deployment to
VM 9104 on 2026-10-21. This is a deployment-scoped exception, not a passing gate.
Existing m15-alloc-compare.log states:
  BASELINE_NEW_GROUPS:175
  M15_NEW_GROUPS:175
  EXACT_SORTED_FINDINGS_EQUAL:true
The absolute allowlist check still exits 1. No allowlist or gate is changed.
allowed.txt SHA256 remains
0ae5baa578fa92d3ee82c16d834fc3ea414db344529d2fef4bbc264d2409cc12.
Any concrete unsafe behavior identified by focused review remains a blocker.
