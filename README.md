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
ok   exit status unchanged under -f
ok   without -f sees only the parent's write
ok   with -f sees all 4 writes
ok   counts 3 clones
ok   announces 3 new processes
ok   strace -f agrees on write (4)
ok   strace -f agrees on clone (3)
ok   -e write: count unchanged by filtering (13)
ok   -e write: summary has only write and total
ok   -e trace=write is the same as -e write
ok   -e write: every line is a complete write call (13 of them)
ok   -e write,close: both appear and nothing else
ok   -e with an unknown name exits 2
ok   -e names the syscall it did not recognise
ok   -e does not change the traced program
ok   strace -e trace=write agrees on write (13)
ok   strace -e also reports a single syscall row
ok   -p rejects pid 0
ok   -p rejects a non-numeric pid
ok   -p with a command is refused
ok   -p on an unattachable pid fails and says so
ok   -p: traced 2137 write calls in an already-running process
ok   -p: reports which pid it attached to
ok   -p: the target is still alive after the tracer exits
ok   -p: the target was resumed, not left stopped (state S)
ok   strace -p also sees writes in it (2831)
ok   -p: the target exits with its own status after all that

43 passed, 0 failed
```

```
$ ./trace -c ls >/dev/null          # GNU coreutils 9.7 on this machine
   calls   errors syscall
      23        0 mmap
      11        0 close
      10        0 fstat
       9        0 openat
       ...
```

The exact rows depend on the `ls` and the libc in front of you, this one
reaches `fstat` where a different build reaches `newfstatat`, and the counts
move with the directory being listed. It is pasted as an illustration of the
format, not as a number to match.

## Why three generations

Linux has three different ways to watch a process make syscalls, built in three
different eras, with genuinely different capabilities:

| | sees args | can **modify** | can **block** | cost |
|---|---|---|---|---|
| `ptrace` | yes, before and after | yes | yes | 2 stops per syscall |
| `seccomp` user notification | yes, on entry | yes, the return value | yes | 1 notify per filtered call |
| eBPF tracepoints | yes | no | no | in-kernel, no context switch |

The end product of this project is that table filled in with measured numbers,
not hand-waving, plus a write-up of which API you reach for when. This
repo is the `ptrace` column: works everywhere, sees the most, costs the most.

## The invariant

Tracing must not change the traced program. Same exit status, same stdout,
every time. A tracer that perturbs its subject is worse than no tracer, and this
is checked before anything about output format is checked.

The oracle for counts is `strace -c`, an independently written tracer. For
accuracy it is `t/workload.c`, a program that issues an exactly known number of
each syscall, built `-static` on purpose, because a dynamically linked binary
has `ld.so` issuing a dozen `openat` and `mmap` calls before `main` and the
expected numbers stop being exact.

## Following children

`-f` follows `fork`, `vfork` and `clone`. This is where the state machine stops
being trivial: the entering/exiting phase and the outstanding syscall number are
per process, so the two globals holding them had to become a table keyed by
pid. The loop waits on `-1` with `__WALL`, because any tracee may stop next and
cloned threads must be reported too.

`PTRACE_O_TRACE{FORK,VFORK,CLONE}` makes the kernel attach the tracer to each new
child automatically and hand over its pid via `PTRACE_GETEVENTMSG`. That closes
the race you would otherwise have between a child being created and the tracer
learning it exists, and a child that `waitpid` reports *before* its parent's
event stop is adopted on sight, not dropped.

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

All four in signal, exit and restart handling, which is where every ptrace
tutorial stops caring:

1. After passing a signal through with `PTRACE_SYSCALL`, the tracee is already
   running. The loop then issued another `PTRACE_SYSCALL`, got `ESRCH`, broke out,
   and returned 0, so a program killed by `SIGTERM` was reported as a clean
   exit. Fixed by routing every restart, signal delivery included, through one
   place at the top of the loop.
2. When `execvp` fails there is never an exec, so there is no stop to attach
   options to and the child has already exited. `PTRACE_SETOPTIONS` returned
   `ESRCH` and the tracer reported its own error instead of the child's 127.

3. Restructuring for `-f` moved `waitpid` to the top of the loop, but the exec
   stop had already been consumed before the loop began, so nothing ever
   restarted the tracee and it hung forever waiting for a stop that had already
   happened.
4. The rewritten exit path returned `WEXITSTATUS` unconditionally, which reports 0
   for a signal death. That is bug 1 again, reintroduced by the rewrite. The
   transparency test caught it on the first run. That is the whole argument for having
   written that test before any of the features.

Neither of the first two is visible if you only ever trace programs that succeed.

## Status

Works. Decodes syscall names from a sparse x86-64 table, path arguments for the
`open`/`stat`/`unlink` families, and `-errno` returns into names. Paths are escaped
on output, so a filename containing a newline cannot forge a line of trace output.
Follows children with `-f`. Filters by name with `-e`. Attaches to a running
process with `-p`.

### `-e`

`trace -e write,close CMD` reports only those calls. `-e trace=write,close` is
accepted too, which is strace's spelling, and is the spelling the test harness
uses because it has to pass the same list to both programs.

Filtering decides what is *reported*, not what is counted, so `-c -e write`
shows the same number for `write` that an unfiltered run does. The summary then
shows only the calls that passed the filter, as `strace -c -e` does.

An unrecognised name is refused with `invalid system call 'name'` and exit 2,
not producing an empty filter. A typo that quietly matched nothing
would read exactly like a program that makes no syscalls, the kind of silence
this project tries not to produce. strace refuses too, though it exits
1 where this exits 2, because 2 is this program's own usage status.

### `-p`

`trace -p PID` takes over a process that is already running, the case a tracer is usually
wanted for: something is wedged and restarting it would
destroy the evidence.

`PTRACE_SEIZE`, not `PTRACE_ATTACH`. ATTACH sends `SIGSTOP` and leaves a stop
the tracer has to recognise and swallow. Getting that wrong is how an attached
process ends up stopped forever. SEIZE does not signal the target at all, and
it is the only form that attaches and sets options in one operation, between
a bare attach and a later `SETOPTIONS` the target runs untraced.

`PTRACE_O_EXITKILL` is set when tracing a command we started and deliberately
not set when attaching. For our own child it means "do not leave an orphan
stopped forever if the tracer dies". For a process that was running before we
arrived, it would mean killing someone else's program because we exited, which
is the worst thing this program could do. The suite asserts the difference by
reading `/proc/PID/stat` after the tracer is gone. A target must still exist
*and* must not be in state `T`, because a process stopped forever looks alive
to `kill -0`.

`EPERM` on attach is usually `kernel.yama.ptrace_scope`, not a
permission problem in the ordinary sense, so the error says so.

### What does not work

- Full argument decoding. Structs like `struct stat`, `iovec` and
  `sockaddr` print as hex pointers. Open flags print as a number, never as `O_RDONLY|O_CLOEXEC`.
- No per-call timing. `-T` is absent, and its absence blocks the
  three-generation overhead table this project exists to produce.
- `-p` cannot attach to a non-descendant where `ptrace_scope` is 1, which
  is the default on Ubuntu and several other distributions. It is 0 on this
  machine, so the suite exercises the real path here and prints a loud SKIP
  elsewhere instead of reporting a pass it did not earn. There is no
  workaround inside this program: the sysctl is the kernel's answer, not ours.
- `-p` does not detach on a signal. Interrupting the tracer relies on the
  kernel auto-detaching when the tracer dies, which does resume the target:
  asserted, but there is no handler that detaches cleanly on `SIGINT`, so
  there is a window during which the target is stopped.
- `-p` attaches to one thread and never a thread group. `strace -p` without
  `-f` behaves the same way, but a multi-threaded target traced this way shows
  only the thread whose pid was given.
- x86-64 only, and the syscall table covers 121 numbers. Anything
  outside it prints as `syscall_N`, which is honest, not wrong.
- `-e` filters by name only. strace also takes classes (`-e trace=file`,
  `%net`), negation (`-e trace=!write`), and `-e` qualifiers other than
  `trace`. None of those are here.

## License

GPL-3.0-or-later.
