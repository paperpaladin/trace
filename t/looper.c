/*
 * looper - a target for `trace -p` to attach to.
 *
 * Writes one byte to /dev/null, sleeps a millisecond, repeats. It exists so a
 * test has a process that is already running and making a known syscall at a
 * known rate, which is the situation -p is for.
 *
 * Two things here are for the harness rather than for realism. It prints its
 * pid and flushes, so the test knows what to attach to without scanning
 * /proc. And it exits on its own after a bounded number of iterations as well
 * as on SIGTERM, so a harness that dies before killing it cannot leave it
 * running forever -- a test helper that outlives its suite is worse than a
 * failing test.
 *
 * Copyright (C) 2026  PLACEHOLDER.  Licensed under the GPLv3 (see LICENSE).
 */
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stop;
static void onterm(int s) { (void)s; stop = 1; }

int main(void) {
  signal(SIGTERM, onterm);
  signal(SIGINT, onterm);

  int fd = open("/dev/null", O_WRONLY);
  if (fd < 0) return 1;

  printf("%d\n", (int)getpid());
  fflush(stdout);

  struct timespec ms = { 0, 1000000 };
  for (long i = 0; i < 30000 && !stop; i++) {
    if (write(fd, "x", 1) != 1) return 1;
    nanosleep(&ms, NULL);
  }
  return 0;
}
