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

33 passed, 0 failed
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
Follows children with `-f`. Filters by name with `-e`.

### `-e`

`trace -e write,close CMD` reports only those calls. `-e trace=write,close` is
accepted too, which is strace's spelling, and is the spelling the test harness
uses because it has to pass the same list to both programs.

Filtering decides what is *reported*, not what is counted, so `-c -e write`
shows the same number for `write` that an unfiltered run does. The summary then
shows only the calls that passed the filter, which is what `strace -c -e` does.

An unrecognised name is refused with `invalid system call 'name'` and exit 2,
rather than producing an empty filter. A typo that quietly matched nothing
would read exactly like a program that makes no syscalls, which is the kind of
silence this project tries not to produce. strace refuses too, though it exits
1 where this exits 2, because 2 is this program's own usage status.

### What does not work

- **Full argument decoding.** Structs like `struct stat`, `iovec` and
  `sockaddr` print as hex pointers. Open flags print as a number, not as
  `O_RDONLY|O_CLOEXEC`.
- **No per-call timing.** `-T` is absent, which is what blocks the
  three-generation overhead table this project exists to produce.
- **No attaching to a running process.** `-p PID` is the next item in
  `PLAN.md`; it was split out of the same plan item as `-e` because it is a
  different kind of problem -- it depends on `kernel.yama.ptrace_scope`, which
  on a machine set to 1 permits attaching only to descendants, so the feature
  and its test both change shape with a sysctl this repo does not control.
- **x86-64 only**, and the syscall table covers roughly 110 numbers. Anything
  outside it prints as `syscall_N`, which is honest rather than wrong.
- **`-e` filters by name only.** strace also takes classes (`-e trace=file`,
  `%net`), negation (`-e trace=!write`), and `-e` qualifiers other than
  `trace`. None of those are here.

## License

GPL-3.0-or-later.
