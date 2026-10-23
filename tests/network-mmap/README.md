# Network file mapping checks

Run with the repository's qualified V compiler:

```sh
V=/path/to/v /path/to/v run tests/ninep/protocol/run.v
V=/path/to/v /path/to/v run tests/nfs/protocol .
V=/path/to/v /path/to/v run tests/network-mmap/run.v
V=/path/to/v /path/to/v run tests/smb2/protocol/run.v
```

The 9P and NFS suites compile the production resource facade and protocol
client against simulated wire services. The 9P test also copies the actual
Resource mapping-lifetime/release dispatch functions. The SMB2 handler test
extracts its production resource type and method bodies verbatim and replaces
the wire client; the separate SMB2 protocol suite exercises that actual client.
Physical memory allocation is emulated in all host tests.

Checks cover bytes on pages zero and one, a partial final page, zero-fill
beyond EOF, negotiated 257-byte request limits, successful positive short
reads, failures after an earlier successful chunk, and balanced physical page
ownership. They reject shared mappings and nonregular types, including SMB2
reparse points. The 9P suite additionally covers OOM, page-offset overflow,
zero-progress reads and a closed connection. Generated-C checks reject hidden
heap allocations in the new page fill paths.

These host checks do not execute a guest ELF. Both production architecture
builds, the full `tests/kernel-allocs/run.sh` comparison, and exec of
`/qual/bootstrap` from a real 9P mount remain required qualification gates.
