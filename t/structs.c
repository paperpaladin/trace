// Fixture for struct decoding (PLAN item 10). Every value in here is chosen to
// be distinctive, because a struct of zeroes decodes correctly under almost any
// implementation: a decoder reading the wrong offset, or only the first array
// element, still agrees with the oracle on zero.
//
//   mode 0751        not 0644, so a hardcoded default is visible
//   size 4919        a prime, not a round number of blocks
//   3 iovecs         lengths 5, 7, 11, so reading only element 0, or using the
//                    wrong stride, changes the printed sequence
//   127.0.0.42:9999  every byte of the address differs, and both bytes of the
//                    port differ, so a missing ntohs is visible
//
// Takes a scratch directory as argv[1]; t/run.sh gives it a per-run one, and
// optionally a path in argv[2] whose owner and group differ (see below).
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <unistd.h>

#define FILLER 4919
#define LINK_TARGET "0123456789abcdefghi"   // 19 bytes, so st_size=19 on the link

int main(int argc, char **argv) {
  if (argc < 2 || argc > 3) { fprintf(stderr, "usage: structs DIR [PATH]\n"); return 2; }
  char file[256], link[256], sock[256];
  snprintf(file, sizeof file, "%s/stat.tmp", argv[1]);
  snprintf(link, sizeof link, "%s/link.tmp", argv[1]);
  snprintf(sock, sizeof sock, "%s/nosock.tmp", argv[1]);

  int fd = openat(AT_FDCWD, file, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND | O_CLOEXEC, 0751);
  if (fd < 0) { perror("openat"); return 1; }

  static char buf[FILLER];
  memset(buf, 'z', sizeof buf);
  if (write(fd, buf, sizeof buf) != FILLER) { perror("write"); return 1; }

  // fchmod rather than trusting the open mode: umask would otherwise decide
  // what st_mode says, and the oracle comparison wants a value we picked.
  if (fchmod(fd, 0751) < 0) { perror("fchmod"); return 1; }

  struct stat st;
  if (fstat(fd, &st) < 0) { perror("fstat"); return 1; }

  // A symlink, so the second stat sees a different file type and a different
  // size. A decoder that always prints S_IFREG passes the first and fails here.
  symlink(LINK_TARGET, link);            // EEXIST on a re-run is fine
  if (syscall(SYS_newfstatat, AT_FDCWD, link, &st, AT_SYMLINK_NOFOLLOW) < 0) {
    perror("newfstatat"); return 1;
  }

  // A third stat, on a path t/run.sh picked for having a group that is not its
  // owner. While st_uid == st_gid, a decoder that prints the two the other way
  // round is indistinguishable from a correct one. SYS_stat rather than the
  // libc wrapper, both to reach the third stat-family syscall number and to
  // keep this line apart from the newfstatat above.
  //
  // fchown on our own file would be the obvious way to arrange this and does
  // not work in the container this was written in: changing a file into a
  // supplementary group of its owner returns EPERM there.
  if (argc == 3 && argv[2][0])
    syscall(SYS_stat, argv[2], &st);        // its failure is the harness's to see

  struct iovec iov[3] = {
    { (void *)"abcde", 5 },
    { (void *)"fghijkl", 7 },
    { (void *)"mnopqrstuvw", 11 },
  };
  if (writev(1, iov, 3) != 23) { perror("writev"); return 1; }
  write(1, "\n", 1);

  struct sockaddr_in in;
  memset(&in, 0, sizeof in);
  in.sin_family = AF_INET;
  in.sin_port = htons(9999);
  in.sin_addr.s_addr = htonl(0x7f00002a);   // 127.0.0.42
  int s4 = socket(AF_INET, SOCK_STREAM, 0);
  if (s4 < 0) { perror("socket"); return 1; }
  connect(s4, (struct sockaddr *)&in, sizeof in);   // expected to fail
  close(s4);

  // The same thing again, 16 bytes before the end of a mapping with nothing
  // after it. A tracer that reads sizeof(struct sockaddr_storage) regardless
  // of the addrlen it was given runs off the end and decodes nothing, while a
  // tracer that reads the addrlen bytes it was promised decodes it. The read
  // is the most intrusive thing this program does and the one place it can be
  // wrong without the output looking wrong.
  long pgsz = sysconf(_SC_PAGESIZE);
  char *m = mmap(NULL, 2 * (size_t)pgsz, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (m == MAP_FAILED) { perror("mmap"); return 1; }
  if (munmap(m + pgsz, (size_t)pgsz) < 0) { perror("munmap"); return 1; }
  struct sockaddr_in *edge = (struct sockaddr_in *)(m + pgsz - sizeof *edge);
  memset(edge, 0, sizeof *edge);
  edge->sin_family = AF_INET;
  edge->sin_port = htons(7777);
  edge->sin_addr.s_addr = htonl(0x7f000017);        // 127.0.0.23
  int se = socket(AF_INET, SOCK_STREAM, 0);
  if (se < 0) { perror("socket"); return 1; }
  connect(se, (struct sockaddr *)edge, sizeof *edge);
  close(se);

  struct sockaddr_un un;
  memset(&un, 0, sizeof un);
  un.sun_family = AF_UNIX;
  snprintf(un.sun_path, sizeof un.sun_path, "%s", sock);
  int su = socket(AF_UNIX, SOCK_STREAM, 0);
  if (su < 0) { perror("socket"); return 1; }
  connect(su, (struct sockaddr *)&un, sizeof un);   // expected to fail, ENOENT
  close(su);

  close(fd);
  return 0;
}
