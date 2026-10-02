# PCIF — Page-Cache Integrity Fuzzer

A **differential fuzzer** for Linux zero-copy syscall paths, specifically
targeting page-cache / mmap coherence bugs across `splice(2)`,
`vmsplice(2)`, `sendmsg(2)`, `sendfile(2)`, `copy_file_range(2)`, `io_uring`,
and AF_ALG sockets.

## Idea

Random syscall fuzzing rarely finds subtle coherence bugs because the
observable state isn't checked precisely. PCIF uses a **snapshot-diff
oracle**:

1. Generate a small program of zero-copy ops over a mix of fds
   (memfd, pipe, AF_ALG, unix socket, regular file).
2. `mmap(MAP_SHARED)` the file-backed regions before running ops.
3. Take a byte-exact snapshot of every region + file *before* ops.
4. Execute ops, recording return values / errno.
5. Take a byte-exact snapshot *after* ops.
6. Apply oracle rules (read-only mutation, ghost write, msync divergence,
   silent no-op) to detect incoherence.

Any op sequence whose observed effect is inconsistent with what the kernel
should have done is a candidate finding.

## Why it's new

Syzkaller has AF_ALG descriptions but does not track page-cache state
across splice chains. PCIF generalizes the snapshot-diff primitive to all
zero-copy paths and uses **grammar-based generation** with a real
mmap-snapshot oracle.

## Build
