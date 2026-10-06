# trace

A syscall tracer on `ptrace(2)`. Generation one of three.

```
$ make test
ok   exit status unchanged by tracing (0)
ok   stdout unchanged by tracing
ok   propagates exit 42
ok   signal death reported as 143
ok   missing binary exits 127
ok   write count exact (13)
ok   openat count exact (4)
ok   openat error count exact (1)
ok   strace agrees on write (13)
ok   strace agrees on openat (4)
ok   strace agrees on close (3)
ok   strace agrees on fsync (1)
ok   decodes openat path argument
ok   decodes -errno into a name
ok   escapes newline in a path
ok   stdout unchanged under -f
ok   without -f sees only the parent's write
ok   with -f sees all 4 writes
ok   counts 3 clones
ok   strace -f agrees on write (4)
ok   strace -f agrees on clone (3)

23 passed, 0 failed
```

```
$ ./trace -c ls >/dev/null
   calls   errors syscall
      17        0 mmap
      10        1 openat
       8        0 newfstatat
       ...
```

## Why three generations

Linux has three different ways to watch a process make syscalls, built in three
different eras, with genuinely different capabilities:

| | sees args | can **modify** | can **block** | cost |
|---|---|---|---|---|
| `ptrace` | yes, before and after | yes | yes | 2 stops per syscall |
| `seccomp` user notification | yes, on entry | yes, the return value | yes | 1 notify per filtered call |
| eBPF tracepoints | yes | no | no | in-kernel, no context switch |

The end product of this project is that table filled in with measured numbers
rather than hand-waving, plus a write-up of which API you reach for when. This
repo is the `ptrace` column: works everywhere, sees the most, costs the most.

## The invariant

**Tracing must not change the traced program.** Same exit status, same stdout,
every time. A tracer that perturbs its subject is worse than no tracer, and this
is checked before anything about output format is checked.

The oracle for counts is `strace -c`, an independently written tracer. For
accuracy it is `t/workload.c`, a program that issues an exactly known number of
each syscall -- built `-static` on purpose, because a dynamically linked binary
has `ld.so` issuing a dozen `openat` and `mmap` calls before `main` and the
expected numbers stop being exact.

## Following children

`-f` follows `fork`, `vfork` and `clone`. This is where the state machine stops
being trivial: the entering/exiting phase and the outstanding syscall number are
**per process**, so the two globals holding them had to become a table keyed by
pid. The loop waits on `-1` with `__WALL`, because any tracee may stop next and
cloned threads must be reported too.

`PTRACE_O_TRACE{FORK,VFORK,CLONE}` makes the kernel attach the tracer to each new
child automatically and hand over its pid via `PTRACE_GETEVENTMSG`. That closes
the race you would otherwise have between a child being created and the tracer
learning it exists -- and a child that `waitpid` reports *before* its parent's
event stop is adopted on sight rather than dropped.

```
$ trace -cf ./forker        # parent plus three children
       4        0 write
       3        0 clone

$ trace -c ./forker         # parent only
       1        0 write
       3        0 clone
```

Only the root process's exit status is propagated, so `trace` stays transparent in
a pipeline. The `[pid]` prefix appears only under `-f`, so single-process output is
byte-identical to what it was before the flag existed.

## Writing this found four real bugs

All four in signal, exit and restart handling -- which is where every ptrace
tutorial stops caring:

1. After passing a signal through with `PTRACE_SYSCALL`, the tracee is already
   running. The loop then issued another `PTRACE_SYSCALL`, got `ESRCH`, broke out,
   and returned 0 -- so a program killed by `SIGTERM` was reported as a clean
   exit. Fixed by routing every restart, signal delivery included, through one
   place at the top of the loop.
2. When `execvp` fails there is never an exec, so there is no stop to attach
   options to and the child has already exited. `PTRACE_SETOPTIONS` returned
   `ESRCH` and the tracer reported its own error instead of the child's 127.

3. Restructuring for `-f` moved `waitpid` to the top of the loop, but the exec
   stop had already been consumed before the loop began -- so nothing ever
   restarted the tracee and it hung forever waiting for a stop that had already
   happened.
4. The rewritten exit path returned `WEXITSTATUS` unconditionally, which reports 0
   for a signal death. That is bug 1 again, reintroduced by the rewrite. The
   transparency test caught it on the first run, which is the whole argument for
   having written that test before any of the features.

Neither of the first two is visible if you only ever trace programs that succeed.

## Status

Works. Decodes syscall names from a sparse x86-64 table, path arguments for the
`open`/`stat`/`unlink` families, and `-errno` returns into names. Paths are escaped
on output, so a filename containing a newline cannot forge a line of trace output.
Follows children with `-f`.

Not implemented: full argument decoding for structs like `struct stat`, syscall
filtering by name, per-call timing, attaching to an already-running pid, or any
architecture but x86-64. The syscall table covers roughly 110 numbers; anything
else prints as `syscall_N`, which is honest rather than wrong.

## License

GPL-3.0-or-later.
