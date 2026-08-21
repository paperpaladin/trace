# trace: plan

## Contract

`trace [-c] [-f] [-e name,name] CMD [ARGS...]` or `trace [-c] -p PID`.
Per-call output on stderr, or a summary with `-c`; `-f` follows children and
`-e` filters by name. All four are shipped, this line listed only `-c`.
Exit status is the **traced program's** status, so `trace` is transparent in a
pipeline.

## Hard invariant

Tracing does not change the traced program. Identical exit status and
identical stdout, traced vs untraced, including when the program dies from a
signal or fails to exec. Checked first in `t/run.sh`, before anything about
output.

## Oracle

1. `strace -c` and `strace -f -c`: an independently written tracer must agree on
   per-syscall counts, single-process and multi-process. Currently agrees on
   `write`, `openat`, `close` and `fsync`, and on `write`/`clone` across a
   4-process tree.
2. `t/workload.c` and `t/forker.c`, ground truth with exactly known counts, both
   built `-static` so `ld.so` contributes nothing. That matters twice over in the
   forking case, since `ld.so` would otherwise run again in every child.
3. The transparency checks, which are their own oracle: the untraced run is the
   reference.

## Non-goals (for generation one)

Full struct decoding. Any architecture but x86-64. Those belong to a tracer
people use. This one exists to be the slow, complete baseline that generations
two and three are measured against.

Attaching to a running pid was on this list and then shipped as item 09b, so
it has been removed from it. The Non-goals section is for what the project
declines to do, not a record of what it once declined.

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

### Milestone 1: a tracer that is actually usable

- [x] 09 `-e name,name` filtering
      why: the first thing anyone reaches for on a tracer whose output is
      thousands of lines long, and the cheapest useful feature left.
      done: also accepts strace's `-e trace=name,name` spelling, the thing
      the harness passes to both programs so the differential compares the
      same request. Filtering applies to reporting, not counting, so a
      filtered count equals an unfiltered one and the summary then shows only
      what passed, matching `strace -c -e`. An unknown name exits 2 rather
      than matching nothing, because a typo that silently filters everything
      out reads exactly like a program making no calls. Ten assertions. The
      one worth having: a call is printed by two stops, name and arguments on
      entry and result on exit, so gating one half leaves orphan `) = 0`
      lines: asserted by requiring every line to be a complete call, which
      is the mutation that would otherwise have shipped.
      Split from `-p PID`, which is now item 09b: it turns on
      `kernel.yama.ptrace_scope`, so both the feature and its test change
      shape with a sysctl this repo does not control, and that deserves its
      own commit instead of riding along with a flag parser.
- [x] 09b `-p PID` to attach to a running process
      why: the other half of what people use a tracer for, something is
      already wedged and you want to see what it is doing, without restarting
      it. PTRACE_SEIZE, not PTRACE_ATTACH, because SEIZE does not stop
      the process and does not need the stop-signal dance. The test has to
      create its own target, attach, observe a known syscall and detach,
      leaving the target running and unchanged, transparency means something
      stricter here than it does for a child we started. Note that
      `ptrace_scope` is 0 on this machine and 1 on most distributions, where
      only descendants may be attached; the harness must detect that and skip
      loudly instead of failing.
      done: PTRACE_SEIZE plus PTRACE_INTERRUPT, and the detail the whole item
      turns on, EXITKILL is set for a command we started and deliberately
      not set when attaching, because killing a process that was running
      before we arrived, because we exited, is the worst thing this program
      could do. Ten assertions, with a new t/looper.c as the target. The two
      that matter read /proc/PID/stat after the tracer is gone: the target
      must still exist and must not be in state T, since a process stopped
      forever looks alive to kill -0. Adding EXITKILL to the attach options
      turns exactly those red.
- [ ] 10 decode the argument structs that matter: `struct stat`, `iovec`,
      `sockaddr`, open flags as symbolic names
- [ ] 11 `-T` per-call timing, the prerequisite for the overhead table
- [ ] 12 `PTRACE_O_TRACEEXEC`, so an exec inside a followed child is visible as an
      event, not only as a syscall

### Milestone 2: generation two: seccomp user notification

- [ ] 13 the same tracer on `SECCOMP_USER_NOTIF`, with a filter that only
      notifies on the syscalls we care about
- [ ] 14 demonstrate the capability `ptrace` has and eBPF does not: intercept an
      `openat` and substitute a different return value
      why: this is the concrete difference that makes the comparison table worth
           publishing, not obvious

### Milestone 3: generation three: eBPF

- [ ] 15 the same tracer on raw tracepoints with CO-RE, needs clang + libbpf
- [ ] 16 show what it *cannot* do: eBPF observes, it cannot block or modify
- [ ] 17 the overhead harness: a workload issuing N million syscalls, measured
      under all three tracers plus untraced, with variance reported
- [ ] 18 the write-up and the capability table, with real numbers

## Open questions

- Whether generation three belongs in this repo or its own. One repo makes the
  comparison table trivial to keep honest; three repos make each implementation
  readable on its own. Leaning toward one repo with three binaries.
- `ptrace` and seccomp-unotify can both modify syscalls, but only `ptrace` can
  see arguments *after* the call returns. Worth confirming before claiming it in
  the table.
