// Ground truth for -f: a known process tree with known syscall counts.
//
// Contract with t/run.sh: 3 clone (one per fork), and 4 write total -- one "c"
// from each of the 3 children plus one "\n" from the parent. Without -f only the
// parent's 1 write is visible; with -f all 4 are.
//
// Static for the same reason as workload.c: ld.so would contribute syscalls of
// its own in each child and the numbers would stop being exact.
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/wait.h>

int main(void) {
  for (int i = 0; i < 3; i++) {
    pid_t p = fork();
    if (p < 0) return 1;
    if (p == 0) { write(1, "c", 1); _exit(0); }
    waitpid(p, 0, 0);
  }
  write(1, "\n", 1);
  return 0;
}
