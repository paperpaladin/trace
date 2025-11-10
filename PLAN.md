# trace -- plan

## Contract

`trace [-c] CMD [ARGS...]`. Per-call output on stderr, or a summary with `-c`.
Exit status is the **traced program's** status, so `trace` is transparent in a
pipeline.

## Hard invariant

**Tracing does not change the traced program.** Identical exit status and
identical stdout, traced vs untraced, including when the program dies from a
signal or fails to exec. Checked first in `t/run.sh`, before anything about
output.

## Oracle

1. `strace -c` and `strace -f -c` -- an independently written tracer must agree on
   per-syscall counts, single-process and multi-process. Currently agrees on
   `write`, `openat`, `close` and `fsync`, and on `write`/`clone` across a
   4-process tree.
2. `t/workload.c` and `t/forker.c` -- ground truth with exactly known counts, both
   built `-static` so `ld.so` contributes nothing. That matters twice over in the
   forking case, since `ld.so` would otherwise run again in every child.
3. The transparency checks, which are their own oracle: the untraced run is the
   reference.

## Non-goals (for generation one)

Full struct decoding. Attaching to a running pid. Any architecture but x86-64. Those belong to a tracer people use; this one exists to
be the slow, complete baseline that generations two and three are measured
against.

## Commit sequence

- [x] 00 fork + PTRACE_TRACEME + the syscall-stop loop, with TRACESYSGOOD
      files: trace.c Makefile
      proves: `trace /bin/true` runs and reports calls
- [x] 01 sparse x86-64 syscall name table; `-c` summary sorted by call count
- [x] 02 path argument decoding via `process_vm_readv`, with output escaping
      why: a filename with a newline in it could otherwise forge a trace line
- [x] 03 `-errno` return decoding (the kernel returns -errno in rax; the libc
      wrapper is what turns that into -1 plus errno)
- [x] 04 transparency + ground-truth + strace differential harness
      files: t/run.sh t/workload.c
- [x] 05 fix: route signal delivery through the single restart point
      why: restarting from the signal branch left the tracee running, so the
           next PTRACE_SYSCALL got ESRCH and a SIGTERM death reported as exit 0
- [x] 06 fix: handle exec failure, where there is no stop to attach options to
- [x] 07 follow fork/vfork/clone with `-f`: per-pid state table, `waitpid(-1)`
      with `__WALL`, `PTRACE_GETEVENTMSG` to learn each child's pid
      why: single-process tracing is useless on anything that spawns, and this is
           where the state machine stops being trivial
      files: trace.c t/forker.c t/run.sh
      proves: `strace -f` agrees on write (4) and clone (3) across a known
              4-process tree; transparency holds with three children sharing stdout
- [x] 08 fix: route every restart through one place; propagate a signal death
      why: both were reintroductions of bugs 05 and 06, caught immediately by the
           transparency test that existed before any feature did

### Milestone 1 -- a tracer that is actually usable

- [ ] 09 `-e name,name` filtering, and `-p PID` to attach to a running process
- [ ] 10 decode the argument structs that matter: `struct stat`, `iovec`,
      `sockaddr`, open flags as symbolic names
- [ ] 11 `-T` per-call timing, which is the prerequisite for the overhead table
- [ ] 12 `PTRACE_O_TRACEEXEC`, so an exec inside a followed child is visible as an
      event rather than only as a syscall

### Milestone 2 -- generation two: seccomp user notification

- [ ] 12 the same tracer on `SECCOMP_USER_NOTIF`, with a filter that only
      notifies on the syscalls we care about
- [ ] 13 demonstrate the capability `ptrace` has and eBPF does not: intercept an
      `openat` and substitute a different return value
      why: this is the concrete difference that makes the comparison table worth
           publishing rather than obvious

### Milestone 3 -- generation three: eBPF

- [ ] 14 the same tracer on raw tracepoints with CO-RE, needs clang + libbpf
- [ ] 15 show what it *cannot* do: eBPF observes, it cannot block or modify
- [ ] 16 the overhead harness: a workload issuing N million syscalls, measured
      under all three tracers plus untraced, with variance reported
- [ ] 17 the write-up and the capability table, with real numbers

## Open questions

- Whether generation three belongs in this repo or its own. One repo makes the
  comparison table trivial to keep honest; three repos make each implementation
  readable on its own. Leaning toward one repo with three binaries.
- `ptrace` and seccomp-unotify can both modify syscalls, but only `ptrace` can
  see arguments *after* the call returns. Worth confirming before claiming it in
  the table.
