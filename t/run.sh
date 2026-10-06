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

  for sc in write openat close fsync; do
    ours=$(count_of "$sc" t/ours.tmp)
    # strace -c puts the name last and counts in a different column order.
    theirs=$(awk -v want="$sc" '$NF == want { print $4; found=1 } END { if (!found) print 0 }' t/strace.tmp)
    if [ "$ours" = "$theirs" ]; then
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
    [ "$ours" = "$theirs" ] && ok "strace -f agrees on $sc ($ours)" \
                            || bad "strace -f disagrees on $sc: trace=$ours strace=$theirs"
  done
fi

rm -f t/workload.bin t/forker.bin t/ours.tmp t/strace.tmp t/calls.tmp t/esc.tmp t/nof.tmp t/withf.tmp t/stf.tmp
printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
