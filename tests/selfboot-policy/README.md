The host tests import only `kernel/sysdiskpolicy`, with no hardware imports.
Run from the repository root:

```
V=/Users/jefferson/.hermes/profiles/vinix/cache/scratch/v-ui2-qualification/v /Users/jefferson/.hermes/profiles/vinix/cache/scratch/v-ui2-qualification/v run tests/selfboot-policy/run.v
```

The V runner stages only this policy module and its tests in a temporary
project so kernel module names cannot shadow host standard-library imports.

The ownership sector has exactly 512 bytes: the 16-byte ASCII header
`VINIX-SYSDISK-1\n`, 32 lowercase hex root-token bytes, 16 lowercase hex
partition-length bytes, 16 lowercase hex bootstrap-image-id bytes, then zero
padding. Its byte length must equal the block resource's exact size. The raw
VJFS signature at partition byte 1080 must be `56 4a` before filesystem init.

Partition updates persist and sync `/.vinix-update-target` before setting
`/.vinix-image-id` to `pending`. A pending root can resume only under that
target image with a valid, different explicit predecessor. The target remains
after commit and is overwritten and synced before the next pending update;
the ownership marker's original source id never authorizes pending recovery.

The existing no-selector whole-disk installer retains its legacy policy.
Partition failures panic and cannot fall back to it. Kernel builds and the
full allocation audit remain the parent task's validation responsibilities.
