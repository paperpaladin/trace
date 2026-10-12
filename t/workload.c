// Ground truth for the tracer: a program whose syscall counts are exactly known.
//
// Built -static on purpose. Dynamically linked, ld.so issues a dozen openat and
// mmap calls of its own before main runs, and the expected counts stop being
// exact. Raw write(2) and openat(2) rather than stdio, so buffering cannot merge
// or split the calls we are counting.
//
// Contract with t/run.sh:  13 write, 4 openat (1 failing), 3 close, 1 fsync.
// Three closes, not four: the failing openat never yields an fd to close.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
  // 10 writes to stdout.
  for (int i = 0; i < 10; i++)
    write(1, "x", 1);
  write(1, "\n", 1);          // 11

  // 2 writes to stderr. The loop above does 10 and the newline makes 11, so
  // stdout gets 11 and stderr gets 2 for a total of 13. This said "3 writes
  // to stderr" while the next sentence said 2 and the code did 2.
  write(2, "e", 1);           // 12
  write(2, "e", 1);           // 13

  // 4 openat calls. The first fails, which exercises the -errno path.
  int fd = openat(AT_FDCWD, "/nonexistent/for-trace-test", O_RDONLY);
  if (fd >= 0) close(fd);     // will not happen; kept so the count is honest

  const char *tmp = "t/workload.tmp";
  int a = openat(AT_FDCWD, tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (a < 0) return 1;
  fsync(a);                   // 1 fsync
  close(a);

  int b = openat(AT_FDCWD, tmp, O_RDONLY);
  if (b < 0) return 1;
  close(b);

  int c = openat(AT_FDCWD, "/dev/null", O_RDONLY);
  if (c < 0) return 1;
  close(c);

  unlink(tmp);
  return 0;
}
