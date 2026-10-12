#!/bin/sh
# Three things get checked, in order of how much they matter.
#
# 1. Transparency. A tracer that changes the traced program is worthless, no
#    matter how pretty its output. Exit status and stdout must be byte-identical
#    traced and untraced.
# 2. Count accuracy against ground truth. t/workload.c issues an exactly known
#    number of each syscall. Static linking keeps ld.so's own syscalls out, so
#    the expected numbers are exact rather than approximate.
# 3. Differential against strace -c, which is the external oracle: an
#    independently written tracer must see the same counts we do.
cd "$(dirname "$0")/.." || exit 1

pass=0
fail=0

ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }

# Static, so the dynamic loader does not contribute syscalls we did not ask for.
cc -O1 -static -o t/workload.bin t/workload.c 2>/dev/null || {
  echo "cannot build t/workload.c"; exit 1; }

# ---------------------------------------------------------------- 1. transparency

untraced_out=$(./t/workload.bin 2>/dev/null); untraced_rc=$?
traced_out=$(./trace ./t/workload.bin 2>/dev/null); traced_rc=$?

[ "$untraced_rc" = "$traced_rc" ] \
  && ok "exit status unchanged by tracing ($traced_rc)" \
  || bad "exit status changed: untraced=$untraced_rc traced=$traced_rc"

[ "$untraced_out" = "$traced_out" ] \
  && ok "stdout unchanged by tracing" \
  || bad "stdout changed under tracing"

# A nonzero exit must be propagated, not swallowed.
./trace /bin/sh -c 'exit 42' >/dev/null 2>&1
[ $? = 42 ] && ok "propagates exit 42" || bad "did not propagate exit 42"

# A program killed by a signal must not look like a clean exit.
./trace /bin/sh -c 'kill -TERM $$' >/dev/null 2>&1
rc=$?
[ "$rc" -ge 128 ] && ok "signal death reported as $rc" || bad "signal death reported as $rc"

# Exec failure must be distinguishable.
./trace /nonexistent/binary >/dev/null 2>&1
[ $? = 127 ] && ok "missing binary exits 127" || bad "missing binary did not exit 127"

# -------------------------------------------------------- 2. counts vs ground truth

count_of() {   # count_of <syscall> <tracer-output-file>
  awk -v want="$1" '$3 == want { print $1; found=1 } END { if (!found) print 0 }' "$2"
}

./trace -c ./t/workload.bin >/dev/null 2>t/ours.tmp

# workload.c writes exactly 10 times to stdout and 3 times to stderr.
w=$(count_of write t/ours.tmp)
[ "$w" = 13 ] && ok "write count exact (13)" || bad "write count: got $w, want 13"

# ...opens exactly 4 files, all via openat.
o=$(count_of openat t/ours.tmp)
[ "$o" = 4 ] && ok "openat count exact (4)" || bad "openat count: got $o, want 4"

# ...and one of those opens deliberately fails, so the error column must show it.
e=$(awk '$3 == "openat" { print $2 }' t/ours.tmp)
[ "$e" = 1 ] && ok "openat error count exact (1)" || bad "openat errors: got $e, want 1"

# -------------------------------------------------------- 3. differential vs strace

if command -v strace >/dev/null 2>&1; then
  strace -c -o t/strace.tmp ./t/workload.bin >/dev/null 2>&1

  # Nonzero first. write and openat have exact ground-truth assertions above,
  # but close and fsync have none, so this differential is their only check --
  # and it was `[ "$ours" = "$theirs" ]` with nothing else, which 0 == 0
  # satisfies. Deleting the fsync call from t/workload.c left "ok strace
  # agrees on fsync (0)" and a green run. The -e and -p oracles further down
  # this same file already guard for it, in those words: "two empty outputs
  # compare equal and prove nothing".
  for sc in write openat close fsync; do
    ours=$(count_of "$sc" t/ours.tmp)
    # strace -c puts the name last and counts in a different column order.
    theirs=$(awk -v want="$sc" '$NF == want { print $4; found=1 } END { if (!found) print 0 }' t/strace.tmp)
    if [ "$ours" = 0 ] && [ "$theirs" = 0 ]; then
      bad "strace and trace both counted zero $sc, so the comparison is vacuous"
    elif [ "$ours" = "$theirs" ]; then
      ok "strace agrees on $sc ($ours)"
    else
      bad "strace disagrees on $sc: trace=$ours strace=$theirs"
    fi
  done
else
  printf 'SKIP strace not installed, differential oracle unavailable\n'
fi

# ------------------------------------------------------------------- 4. decoding

# The path of a failing open must appear in the per-call output, escaped.
./trace ./t/workload.bin 2>t/calls.tmp >/dev/null
grep -q '/nonexistent/for-trace-test' t/calls.tmp \
  && ok "decodes openat path argument" \
  || bad "did not decode openat path argument"

grep -q 'ENOENT\|No such file' t/calls.tmp \
  && ok "decodes -errno into a name" \
  || bad "did not decode errno"

# A path containing a newline must not be able to forge an output line.
mkdir -p t/d 2>/dev/null
weird=$(printf 't/d/a\nb')
: > "$weird" 2>/dev/null
if [ -e "$weird" ]; then
  ./trace /bin/cat "$weird" 2>t/esc.tmp >/dev/null
  grep -q '\\n' t/esc.tmp \
    && ok "escapes newline in a path" \
    || bad "did not escape newline in a path"
  rm -f "$weird"
else
  printf 'SKIP filesystem rejected a newline in a filename\n'
fi
rm -rf t/d

# ------------------------------------------------------- 5. following children

cc -O1 -static -o t/forker.bin t/forker.c 2>/dev/null || {
  echo "cannot build t/forker.c"; exit 1; }

# Transparency has to hold with -f too: three children writing to the same stdout
# must still produce the same bytes in the same order.
f_untraced=$(./t/forker.bin 2>/dev/null); f_rc=$?
f_traced=$(./trace -f ./t/forker.bin 2>/dev/null); ft_rc=$?
[ "$f_untraced" = "$f_traced" ] && ok "stdout unchanged under -f" \
                               || bad "stdout changed under -f"
[ "$f_rc" = "$ft_rc" ] && ok "exit status unchanged under -f" \
                       || bad "exit status changed under -f"

# Without -f only the parent is visible: 1 write.
./trace -c ./t/forker.bin >/dev/null 2>t/nof.tmp
w=$(count_of write t/nof.tmp)
[ "$w" = 1 ] && ok "without -f sees only the parent's write" \
             || bad "without -f: write count $w, want 1"

# With -f all four processes are: 3 children x 1 write, plus the parent's.
./trace -cf ./t/forker.bin >/dev/null 2>t/withf.tmp
w=$(count_of write t/withf.tmp)
[ "$w" = 4 ] && ok "with -f sees all 4 writes" \
             || bad "with -f: write count $w, want 4"

c=$(count_of clone t/withf.tmp)
[ "$c" = 3 ] && ok "counts 3 clones" || bad "clone count $c, want 3"

# One announcement per new process.
n=$(./trace -f ./t/forker.bin 2>&1 >/dev/null | grep -c 'new process')
[ "$n" = 3 ] && ok "announces 3 new processes" || bad "announced $n new processes, want 3"

# And the external oracle: strace -f must agree on both counts.
if command -v strace >/dev/null 2>&1; then
  strace -f -c -o t/stf.tmp ./t/forker.bin >/dev/null 2>&1
  for sc in write clone; do
    ours=$(count_of "$sc" t/withf.tmp)
    theirs=$(awk -v want="$sc" '$NF == want { print $4; found=1 } END { if (!found) print 0 }' t/stf.tmp)
    if [ "$ours" = 0 ] && [ "$theirs" = 0 ]; then
      bad "strace -f and trace -f both counted zero $sc, so this is vacuous"
    else
      [ "$ours" = "$theirs" ] && ok "strace -f agrees on $sc ($ours)" \
                              || bad "strace -f disagrees on $sc: trace=$ours strace=$theirs"
    fi
  done
else
  printf 'SKIP strace not installed, the -f differential did not run\n'
fi

# ------------------------------------------------------------ 6. -e filtering

# Filtering decides what is reported, not what is counted, so a filtered count
# must equal the unfiltered one for the same syscall. If -e changed the number
# then the filter would be interfering with the measurement rather than with
# the output.
./trace -c -e write ./t/workload.bin >/dev/null 2>t/ef.tmp
fw=$(count_of write t/ef.tmp)
[ "$fw" = 13 ] && ok "-e write: count unchanged by filtering (13)" \
                || bad "-e write: got $fw, want 13"

# ...and nothing else may appear. One syscall row plus the total row.
rows=$(grep -cE '^ *[0-9]+ ' t/ef.tmp)
[ "$rows" = 2 ] && ok "-e write: summary has only write and total" \
                 || bad "-e write: summary has $rows numbered rows, want 2"

# The strace spelling of the same flag has to mean the same thing, because the
# oracle below is invoked with it and the comparison is worthless otherwise.
./trace -c -e trace=write ./t/workload.bin >/dev/null 2>t/ef2.tmp
cmp -s t/ef.tmp t/ef2.tmp && ok "-e trace=write is the same as -e write" \
                          || bad "-e and -e trace= disagree"

# Per-call output. Every line must be a write, and -- the part that is easy to
# get wrong -- there must be no orphans. One call is printed by two stops, the
# name and arguments on entry and the result on exit, so a filter applied to
# only one of them leaves a dangling "(" or a bare ") = 0".
./trace -e write ./t/workload.bin >/dev/null 2>t/ec.tmp
if [ -s t/ec.tmp ] && ! grep -qvE '^write\(.*\) = ' t/ec.tmp; then
  ok "-e write: every line is a complete write call ($(wc -l < t/ec.tmp) of them)"
else
  bad "-e write: output has non-write or incomplete lines" \
      "$(grep -nvE '^write\(.*\) = ' t/ec.tmp | head -3)"
fi

# Two names means both and nothing else.
./trace -e write,close ./t/workload.bin >/dev/null 2>t/ec2.tmp
if ! grep -qvE '^(write|close)\(' t/ec2.tmp && grep -q '^close(' t/ec2.tmp; then
  ok "-e write,close: both appear and nothing else"
else
  bad "-e write,close: wrong set of calls" "$(grep -vE '^(write|close)\(' t/ec2.tmp | head -3)"
fi

# A typo must be refused rather than quietly matching nothing, which would
# read exactly like a program that makes no syscalls at all. strace exits 1
# and says "invalid system call"; we exit 2 because 2 is this program's own
# usage status, and say the same thing.
./trace -e nosuchcall ./t/workload.bin >/dev/null 2>t/ebad.tmp
rc=$?
[ "$rc" = 2 ] && ok "-e with an unknown name exits 2" \
              || bad "-e with an unknown name exited $rc, want 2"
grep -q "invalid system call 'nosuchcall'" t/ebad.tmp \
  && ok "-e names the syscall it did not recognise" \
  || bad "-e did not name the bad syscall"

# Transparency still holds with a filter on: suppressing output must not
# change the traced program.
fout=$(./trace -e write ./t/workload.bin 2>/dev/null); frc=$?
[ "$frc" = "$untraced_rc" ] && [ "$fout" = "$untraced_out" ] \
  && ok "-e does not change the traced program" \
  || bad "-e changed the program: rc=$frc want $untraced_rc"

# The oracle. strace filters its own summary the same way, and must agree on
# the number -- having first confirmed the number is not zero, because two
# empty outputs compare equal and prove nothing.
if command -v strace >/dev/null 2>&1; then
  strace -c -e trace=write -o t/sef.tmp ./t/workload.bin >/dev/null 2>&1
  theirs=$(awk '$NF == "write" { print $4; f=1 } END { if (!f) print 0 }' t/sef.tmp)
  if [ "$theirs" = 0 ]; then
    bad "strace -e write counted nothing, so the comparison is vacuous"
  elif [ "$fw" = "$theirs" ]; then
    ok "strace -e trace=write agrees on write ($fw)"
  else
    bad "strace -e disagrees: trace=$fw strace=$theirs"
  fi
  # And strace's filtered summary must also contain only write.
  srows=$(awk '$NF != "" && $1 ~ /^[0-9]/ { n++ } END { print n+0 }' t/sef.tmp)
  [ "$srows" = 2 ] && ok "strace -e also reports a single syscall row" \
                   || bad "strace -e reported $srows rows; the oracle is not comparable"
fi

# ----------------------------------------------------- 7. -p attaching

# Argument handling first; it needs no target and cannot hang.
./trace -p 0 >/dev/null 2>&1
[ $? = 2 ] && ok "-p rejects pid 0" || bad "-p accepted pid 0"
./trace -p notanumber >/dev/null 2>&1
[ $? = 2 ] && ok "-p rejects a non-numeric pid" || bad "-p accepted a non-numeric pid"
./trace -p 1 /bin/true >/dev/null 2>&1
[ $? = 2 ] && ok "-p with a command is refused" || bad "-p accepted both a pid and a command"

# An unattachable pid must fail with a message, not hang waiting for a stop
# that will never come. Pid 1 is init: attaching to it needs privileges we do
# not have, which makes it a reliably unattachable live process.
timeout 10 ./trace -p 1 >/dev/null 2>t/pfail.tmp
rc=$?
if [ "$rc" = 124 ]; then
  bad "-p on an unattachable pid hung instead of failing"
elif [ "$rc" = 0 ]; then
  printf 'SKIP -p on pid 1 succeeded, so this process has more privilege than assumed\n'
elif grep -q 'cannot attach to 1' t/pfail.tmp; then
  ok "-p on an unattachable pid fails and says so"
else
  bad "-p on an unattachable pid failed without explaining" "$(head -2 t/pfail.tmp)"
fi

# The real thing needs a process that is already running and making a known
# syscall. ptrace_scope 1 permits attaching only to descendants, and the
# target below is a sibling, so on such a machine this is skipped rather than
# failed -- the kernel is the authority and it is entitled to say no.
scope=0
[ -r /proc/sys/kernel/yama/ptrace_scope ] && scope=$(cat /proc/sys/kernel/yama/ptrace_scope)

cc -O1 -static -o t/looper.bin t/looper.c 2>/dev/null || {
  echo "cannot build t/looper.c"; exit 1; }

if [ "$scope" != 0 ]; then
  printf 'SKIP -p: kernel.yama.ptrace_scope is %s, which forbids attaching to a sibling\n' "$scope"
else
  t/looper.bin > t/lpid.tmp 2>/dev/null &
  looper=$!
  # Wait for it to print its pid, rather than sleeping a guessed interval.
  i=0
  while [ ! -s t/lpid.tmp ] && [ $i -lt 100 ]; do i=$((i + 1)); sleep 0.05; done
  target=$(cat t/lpid.tmp 2>/dev/null)

  if [ -z "$target" ]; then
    bad "-p: the looper never reported its pid"
  else
    timeout 5 ./trace -e write -p "$target" >/dev/null 2>t/pout.tmp
    n=$(grep -c '^write(' t/pout.tmp)
    [ "$n" -gt 0 ] && ok "-p: traced $n write calls in an already-running process" \
                   || bad "-p: saw no write calls" "$(head -3 t/pout.tmp)"
    grep -q "attached to $target" t/pout.tmp \
      && ok "-p: reports which pid it attached to" \
      || bad "-p: did not report the attach"

    # The assertion this feature exists to satisfy. A process we attached to is
    # not ours: when the tracer goes away the target must still be running.
    # Getting the detach wrong leaves it stopped forever, and "stopped forever"
    # looks exactly like "alive" to kill -0, so the state has to be read.
    if kill -0 "$target" 2>/dev/null; then
      ok "-p: the target is still alive after the tracer exits"
    else
      bad "-p: the target died when the tracer exited"
    fi
    st=$(awk '{print $3}' /proc/"$target"/stat 2>/dev/null)
    case "$st" in
      T|t) bad "-p: the target was left stopped (state $st), not resumed" ;;
      "")  bad "-p: the target is gone, so its state cannot be read" ;;
      *)   ok "-p: the target was resumed, not left stopped (state $st)" ;;
    esac

    # The oracle: strace attaching to the same kind of target must also see
    # writes. Checked for nonzero first, because two empty outputs agree.
    if command -v strace >/dev/null 2>&1; then
      timeout 5 strace -e trace=write -p "$target" -o t/spout.tmp >/dev/null 2>&1
      # `grep -c ... || echo 0` is wrong in a way that looks right: grep -c
      # prints 0 AND exits 1 when nothing matches, so the `||` appends a
      # second zero, sn becomes "0\n0", and `[ -gt ]` is an
      # integer-expression error rather than a comparison. It lands in the
      # bad branch, which is the intended direction, by accident. The same
      # spelling was found in prof and fixed there.
      sn=$(grep -c '^write(' t/spout.tmp 2>/dev/null); sn=${sn:-0}
      [ "$sn" -gt 0 ] && ok "strace -p also sees writes in it ($sn)" \
                      || bad "strace -p saw none, so the comparison is vacuous"
    fi

    # And it still exits on its own terms, with its own status.
    kill -TERM "$target" 2>/dev/null
    wait "$looper" 2>/dev/null
    lrc=$?
    [ "$lrc" = 0 ] && ok "-p: the target exits with its own status after all that" \
                   || bad "-p: the target exited $lrc, want 0"
  fi
fi

rm -f t/workload.bin t/forker.bin t/looper.bin t/ours.tmp t/strace.tmp t/calls.tmp t/esc.tmp t/nof.tmp t/withf.tmp t/stf.tmp t/ef.tmp t/ef2.tmp t/ec.tmp t/ec2.tmp t/ebad.tmp t/sef.tmp t/pfail.tmp t/pout.tmp t/spout.tmp t/lpid.tmp
# The count is pinned. The gate was `[ "$fail" = 0 ]` alone, so every way of
# losing assertions was a green run: making `command -v strace` fail dropped
# 9 of 43 and still exited 0, and a nonzero kernel.yama.ptrace_scope drops the
# 6 that are the whole point of PLAN item 09b -- including the two /proc/PID/stat
# checks PLAN.md calls "the two that matter" -- on any default Debian or Ubuntu
# box. Those are legitimate environment skips, so they are allowed, but they
# have to be declared rather than absorbed: ASSERTIONS_EXPECTED is what ran
# here, and each skip states its own cost.
ASSERTIONS_EXPECTED=43
total=$((pass + fail))
printf '\n%d passed, %d failed\n' "$pass" "$fail"
if [ "$total" -ne "$ASSERTIONS_EXPECTED" ]; then
  printf 'run.sh: %d assertions ran, expected %d.\n' "$total" "$ASSERTIONS_EXPECTED" >&2
  printf '  Any SKIP lines above say what was lost and why. If a skip is\n' >&2
  printf '  expected in this environment, subtract its cost from\n' >&2
  printf '  ASSERTIONS_EXPECTED in the same commit that explains it:\n' >&2
  printf '    no strace                      -9\n' >&2
  printf '    kernel.yama.ptrace_scope != 0  -6\n' >&2
  exit 1
fi
[ "$fail" = 0 ]
