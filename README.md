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

15 passed, 0 failed
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

## Writing this found two real bugs

Both were in signal and exit handling, which is where every ptrace tutorial
stops caring:

1. After passing a signal through with `PTRACE_SYSCALL`, the tracee is already
   running. The loop then issued another `PTRACE_SYSCALL`, got `ESRCH`, broke out,
   and returned 0 -- so a program killed by `SIGTERM` was reported as a clean
   exit. Fixed by routing every restart, signal delivery included, through one
   place at the top of the loop.
2. When `execvp` fails there is never an exec, so there is no stop to attach
   options to and the child has already exited. `PTRACE_SETOPTIONS` returned
   `ESRCH` and the tracer reported its own error instead of the child's 127.

Neither is visible if you only ever trace programs that succeed.

## Status

Works. Decodes syscall names from a sparse x86-64 table, path arguments for the
`open`/`stat`/`unlink` families, and `-errno` returns into names. Paths are
escaped on output, so a filename containing a newline cannot forge a line of
trace output.

Not implemented: following `fork`/`clone` into children (single process only),
full argument decoding for structs like `struct stat`, syscall filtering by name,
attaching to an already-running pid, or any architecture but x86-64. The syscall
table covers roughly 110 numbers; anything else prints as `syscall_N`, which is
honest rather than wrong.

## License

GPL-3.0-or-later.
