// trace -- a syscall tracer built on ptrace(2).
//
// Generation one of three. The plan is to implement the same tracer three ways
// (ptrace, seccomp user notification, eBPF) and publish what each API can and
// cannot see, plus the per-syscall overhead of each. This is the one that works
// everywhere and costs the most: two stops per syscall, each a full context
// switch into the tracer.
//
// The invariant that matters more than any output format: tracing must not
// change the traced program. Same exit status, same stdout, every time. t/ checks
// that before it checks anything else.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

// x86-64 syscall numbers. Sparse on purpose: the ones a normal process actually
// issues, plus anything the tests exercise. Unknown numbers print as syscall_N,
// which is honest rather than wrong.
static const char *SYSCALL_NAME[] = {
  [0]="read",[1]="write",[2]="open",[3]="close",[4]="stat",[5]="fstat",[6]="lstat",
  [7]="poll",[8]="lseek",[9]="mmap",[10]="mprotect",[11]="munmap",[12]="brk",
  [13]="rt_sigaction",[14]="rt_sigprocmask",[15]="rt_sigreturn",[16]="ioctl",
  [17]="pread64",[18]="pwrite64",[19]="readv",[20]="writev",[21]="access",
  [22]="pipe",[23]="select",[24]="sched_yield",[25]="mremap",[26]="msync",
  [27]="mincore",[28]="madvise",[32]="dup",[33]="dup2",[35]="nanosleep",
  [39]="getpid",[40]="sendfile",[41]="socket",[42]="connect",[43]="accept",
  [44]="sendto",[45]="recvfrom",[46]="sendmsg",[47]="recvmsg",[48]="shutdown",
  [49]="bind",[50]="listen",[51]="getsockname",[53]="socketpair",
  [54]="setsockopt",[55]="getsockopt",[56]="clone",[57]="fork",[58]="vfork",
  [59]="execve",[60]="exit",[61]="wait4",[62]="kill",[63]="uname",
  [72]="fcntl",[73]="flock",[74]="fsync",[75]="fdatasync",[76]="truncate",
  [77]="ftruncate",[78]="getdents",[79]="getcwd",[80]="chdir",[81]="fchdir",
  [82]="rename",[83]="mkdir",[84]="rmdir",[85]="creat",[86]="link",[87]="unlink",
  [88]="symlink",[89]="readlink",[90]="chmod",[91]="fchmod",[92]="chown",
  [95]="umask",[96]="gettimeofday",[97]="getrlimit",[98]="getrusage",
  [99]="sysinfo",[100]="times",[101]="ptrace",[102]="getuid",[104]="getgid",
  [105]="setuid",[106]="setgid",[107]="geteuid",[108]="getegid",[109]="setpgid",
  [110]="getppid",[137]="statfs",[138]="fstatfs",[158]="arch_prctl",
  [186]="gettid",[201]="time",[202]="futex",[204]="sched_getaffinity",
  [217]="getdents64",[218]="set_tid_address",[228]="clock_gettime",
  [231]="exit_group",[232]="epoll_wait",[233]="epoll_ctl",[257]="openat",
  [262]="newfstatat",[263]="unlinkat",[269]="faccessat",[273]="set_robust_list",
  [280]="utimensat",[290]="eventfd2",[291]="epoll_create1",[292]="dup3",
  [293]="pipe2",[302]="prlimit64",[318]="getrandom",[332]="statx",
  [334]="rseq",[439]="faccessat2",[452]="fchmodat2",
};
#define NSYSCALL (sizeof(SYSCALL_NAME) / sizeof(SYSCALL_NAME[0]))

static long counts[512];
static long errors[512];

// -e: which syscalls to report, by number. Empty means all of them, which is
// why there is a separate flag rather than a table filled in with true -- "no
// -e given" and "-e naming everything" should behave the same, and they do,
// but only one of them can be distinguished from "-e naming nothing".
static bool shown[512];
static bool filtering = false;

static bool is_shown(long nr) {
  if (!filtering) return true;
  return nr >= 0 && nr < 512 && shown[nr];
}

// Parse "-e read,write" or "-e trace=read,write". The second spelling is
// strace's, accepted here so the flag can be copied between the two without
// editing -- which matters because the oracle is invoked with the same list.
//
// An unknown name is an error rather than a silently empty filter. strace
// refuses too, and the alternative is a typo producing a quiet "no syscalls
// matched" that reads exactly like a program making no calls.
static int parse_filter(const char *list) {
  if (!strncmp(list, "trace=", 6)) list += 6;
  if (!*list) { fprintf(stderr, "trace: -e needs at least one name\n"); return 2; }

  while (*list) {
    const char *end = strchr(list, ',');
    size_t len = end ? (size_t)(end - list) : strlen(list);
    bool found = false;
    for (size_t nr = 0; nr < NSYSCALL && nr < 512; nr++) {
      if (SYSCALL_NAME[nr] && strlen(SYSCALL_NAME[nr]) == len &&
          !strncmp(SYSCALL_NAME[nr], list, len)) {
        shown[nr] = true;
        found = true;
        break;
      }
    }
    if (!found) {
      fprintf(stderr, "trace: invalid system call '%.*s'\n", (int)len, list);
      return 2;
    }
    list = end ? end + 1 : list + len;
  }
  filtering = true;
  return 0;
}
static bool count_only = false;
static pid_t attach_pid = 0;   // -p: trace this instead of starting a command
static bool follow = false;        // -f: trace children too
static pid_t root_pid;             // whose exit status we propagate

// Per-tracee state. Each process has its own entering/exiting phase and its own
// outstanding syscall, so a single pair of globals stops working the moment a
// second process exists.
typedef struct {
  pid_t pid;
  bool in_use;
  bool entering;
  long pending_nr;
  unsigned long pending_args[6];   // arguments seen on entry, for the exit half
} Tracee;

#define MAX_TRACEES 512
static Tracee tracees[MAX_TRACEES];
static int live_tracees;

static Tracee *tracee_find(pid_t pid) {
  for (int i = 0; i < MAX_TRACEES; i++)
    if (tracees[i].in_use && tracees[i].pid == pid) return &tracees[i];
  return NULL;
}

static Tracee *tracee_add(pid_t pid) {
  Tracee *t = tracee_find(pid);
  if (t) return t;
  for (int i = 0; i < MAX_TRACEES; i++) {
    if (tracees[i].in_use) continue;
    tracees[i].in_use = true;
    tracees[i].pid = pid;
    tracees[i].entering = true;
    tracees[i].pending_nr = -1;
    live_tracees++;
    return &tracees[i];
  }
  fprintf(stderr, "trace: more than %d processes, giving up\n", MAX_TRACEES);
  exit(1);
}

static void tracee_drop(Tracee *t) {
  t->in_use = false;
  live_tracees--;
}

// Only prefix lines with a pid when more than one process can appear, so the
// single-process output stays identical to what it was before -f existed.
static void line_prefix(pid_t pid) {
  if (follow) fprintf(stderr, "[%d] ", (int)pid);
}

static const char *syscall_name(long nr) {
  static char buf[32];
  if (nr >= 0 && (size_t)nr < NSYSCALL && SYSCALL_NAME[nr]) return SYSCALL_NAME[nr];
  snprintf(buf, sizeof(buf), "syscall_%ld", nr);
  return buf;
}

// Which syscalls take a path as their first (or second, for *at) argument.
// Used only to make the output readable; nothing depends on it.
static int path_arg(long nr) {
  switch (nr) {
  case 2: case 4: case 6: case 21: case 80: case 83: case 84: case 87:
  case 89: case 90: case 92: case 137:
    return 0;
  case 257: case 262: case 263: case 269: case 439: case 452:
    return 1;      // openat(dirfd, path, ...)
  default:
    return -1;
  }
}

// Reads a fixed number of bytes out of the tracee. All struct decoding goes
// through here, so a tracee that died or unmapped the page under us produces a
// false return and a hex pointer, never a half-read struct printed as fact.
static bool read_mem(pid_t pid, unsigned long addr, void *buf, size_t len) {
  if (!addr || !len) return false;
  struct iovec local = { .iov_base = buf, .iov_len = len };
  struct iovec remote = { .iov_base = (void *)addr, .iov_len = len };
  return process_vm_readv(pid, &local, 1, &remote, 1, 0) == (ssize_t)len;
}

// Quote and escape n bytes of tracee memory, so a path or a buffer containing a
// newline cannot forge a line of our own output.
static void escape_into(const unsigned char *raw, size_t n, char *out, size_t cap) {
  size_t o = 0;
  out[o++] = '"';
  for (size_t i = 0; i < n && o + 6 < cap; i++) {
    unsigned char c = raw[i];
    if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = c; }
    else if (c == '\n') { out[o++] = '\\'; out[o++] = 'n'; }
    else if (c < 32 || c > 126) { o += snprintf(out + o, cap - o, "\\x%02x", c); }
    else out[o++] = c;
  }
  if (o + 2 < cap) out[o++] = '"';
  out[o] = 0;
}

// Reads a NUL-terminated string out of the tracee. process_vm_readv does it in
// one call; PTRACE_PEEKDATA would need a word-at-a-time loop.
static void read_string(pid_t pid, unsigned long addr, char *out, size_t cap) {
  if (!addr) { snprintf(out, cap, "NULL"); return; }

  unsigned char raw[256];
  size_t want = cap < sizeof(raw) ? cap : sizeof(raw);
  struct iovec local = { .iov_base = raw, .iov_len = want - 1 };
  struct iovec remote = { .iov_base = (void *)addr, .iov_len = want - 1 };

  ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
  if (n <= 0) { snprintf(out, cap, "0x%lx", addr); return; }
  escape_into(raw, strnlen((char *)raw, (size_t)n), out, cap);
}

// ---------------------------------------------------------------- decoding

// open(2) flags as names. The access mode is a 2-bit field, not a bit, so it
// comes first and on its own; everything after it is a single bit.
static void print_open_flags(unsigned long f) {
  static const struct { unsigned long bit; const char *name; } BITS[] = {
    // O_SYNC and O_TMPFILE are each two bits, and must be tested before the
    // single bit they contain or they print as that bit instead.
    { O_SYNC, "O_SYNC" }, { O_TMPFILE, "O_TMPFILE" },
    { O_CREAT, "O_CREAT" }, { O_EXCL, "O_EXCL" }, { O_NOCTTY, "O_NOCTTY" },
    { O_TRUNC, "O_TRUNC" }, { O_APPEND, "O_APPEND" }, { O_NONBLOCK, "O_NONBLOCK" },
    { O_DSYNC, "O_DSYNC" }, { O_ASYNC, "O_ASYNC" }, { O_DIRECT, "O_DIRECT" },
    { 0100000UL, "O_LARGEFILE" }, { O_DIRECTORY, "O_DIRECTORY" },
    { O_NOFOLLOW, "O_NOFOLLOW" }, { O_NOATIME, "O_NOATIME" },
    { O_CLOEXEC, "O_CLOEXEC" }, { O_PATH, "O_PATH" },
  };
  switch (f & O_ACCMODE) {
  case O_RDONLY: fputs("O_RDONLY", stderr); break;
  case O_WRONLY: fputs("O_WRONLY", stderr); break;
  case O_RDWR:   fputs("O_RDWR", stderr); break;
  default:       fputs("O_ACCMODE", stderr); break;
  }
  f &= ~(unsigned long)O_ACCMODE;
  for (size_t i = 0; i < sizeof(BITS) / sizeof(BITS[0]); i++)
    if ((f & BITS[i].bit) == BITS[i].bit) { fprintf(stderr, "|%s", BITS[i].name); f &= ~BITS[i].bit; }
  if (f) fprintf(stderr, "|0x%lx", f);   // an unknown bit is shown, not dropped
}

// *at() flags. 0 prints as 0, as strace does.
static void print_at_flags(unsigned long f) {
  static const struct { unsigned long bit; const char *name; } BITS[] = {
    { 0x100, "AT_SYMLINK_NOFOLLOW" }, { 0x200, "AT_EACCESS" },
    { 0x400, "AT_REMOVEDIR" }, { 0x800, "AT_NO_AUTOMOUNT" },
    { 0x1000, "AT_EMPTY_PATH" },
  };
  if (!f) { fputs("0", stderr); return; }
  const char *sep = "";
  for (size_t i = 0; i < sizeof(BITS) / sizeof(BITS[0]); i++)
    if (f & BITS[i].bit) { fprintf(stderr, "%s%s", sep, BITS[i].name); sep = "|"; f &= ~BITS[i].bit; }
  if (f) fprintf(stderr, "%s0x%lx", sep, f);
}

// A dirfd is an int, so AT_FDCWD arrives in the register as 0xffffff9c and
// comparing the full 64-bit word against -100 never matches.
static const char *dirfd_str(unsigned long raw) {
  static char b[24];
  int fd = (int)raw;
  if (fd == AT_FDCWD) return "AT_FDCWD";
  snprintf(b, sizeof(b), "%d", fd);
  return b;
}

// struct stat. The glibc x86-64 layout is the kernel's byte for byte
// (st_nlink before st_mode, a 4-byte pad after st_gid), which is why this can
// read into one directly. That is an x86-64 fact, and this tracer is x86-64
// only; a port would need the kernel struct written out by hand.
//
// shortcut: st_atime and friends are not printed. They are the three fields
// whose value is a clock rather than a property of the file, so they cannot be
// compared against the oracle in a second process at a second time. Printing
// them needs them excluded from the differential, which is work for no reader.
static void print_stat(pid_t pid, unsigned long addr) {
  struct stat st;
  if (!read_mem(pid, addr, &st, sizeof st)) { fprintf(stderr, "0x%lx", addr); return; }

  const char *type = "S_IFREG";
  switch (st.st_mode & S_IFMT) {
  case S_IFDIR:  type = "S_IFDIR";  break;
  case S_IFCHR:  type = "S_IFCHR";  break;
  case S_IFBLK:  type = "S_IFBLK";  break;
  case S_IFIFO:  type = "S_IFIFO";  break;
  case S_IFLNK:  type = "S_IFLNK";  break;
  case S_IFSOCK: type = "S_IFSOCK"; break;
  case S_IFREG:  break;
  default:       type = "S_IFMT";   break;
  }
  // setuid, setgid and sticky are named, not folded into the octal. They were
  // folded into it until the oracle disagreed about /usr/bin/expiry, which is
  // setgid: we said S_IFREG|02755 where strace says S_IFREG|S_ISGID|0755.
  char special[32] = "";
  if (st.st_mode & S_ISUID) strcat(special, "|S_ISUID");
  if (st.st_mode & S_ISGID) strcat(special, "|S_ISGID");
  if (st.st_mode & S_ISVTX) strcat(special, "|S_ISVTX");

  fprintf(stderr,
          "{st_dev=makedev(%u, %u), st_ino=%lu, st_mode=%s%s|0%03o, st_nlink=%lu, "
          "st_uid=%u, st_gid=%u, st_blksize=%ld, st_blocks=%ld, st_size=%ld}",
          major(st.st_dev), minor(st.st_dev), (unsigned long)st.st_ino,
          type, special, (unsigned)(st.st_mode & 0777), (unsigned long)st.st_nlink,
          (unsigned)st.st_uid, (unsigned)st.st_gid, (long)st.st_blksize,
          (long)st.st_blocks, (long)st.st_size);
}

// An iovec array. Printing only element zero, or walking it with the wrong
// stride, is the whole failure mode here, so the count comes from the syscall's
// own argument and every element is read separately.
#define IOV_SHOW 16      // shortcut: a longer array prints "..."; raising it is one number
#define IOV_BYTES 32     // as strace's default -s, so the oracle truncates where we do
static void print_iovec(pid_t pid, unsigned long addr, long cnt) {
  if (cnt < 0 || !addr) { fprintf(stderr, "0x%lx", addr); return; }
  fputs("[", stderr);
  for (long i = 0; i < cnt && i < IOV_SHOW; i++) {
    struct iovec v;
    if (!read_mem(pid, addr + (unsigned long)i * sizeof v, &v, sizeof v)) {
      fprintf(stderr, "%s...", i ? ", " : "");
      break;
    }
    size_t n = v.iov_len < IOV_BYTES ? v.iov_len : IOV_BYTES;
    unsigned char raw[IOV_BYTES];
    char esc[IOV_BYTES * 4 + 8];
    if (n && read_mem(pid, (unsigned long)v.iov_base, raw, n)) escape_into(raw, n, esc, sizeof esc);
    else snprintf(esc, sizeof esc, "0x%lx", (unsigned long)v.iov_base);
    fprintf(stderr, "%s{iov_base=%s%s, iov_len=%lu}", i ? ", " : "", esc,
            v.iov_len > IOV_BYTES ? "..." : "", (unsigned long)v.iov_len);
  }
  if (cnt > IOV_SHOW) fputs(", ...", stderr);
  fputs("]", stderr);
}

// struct sockaddr. The family decides how to read the rest, so it is read
// first and nothing beyond addrlen is ever touched.
static void print_sockaddr(pid_t pid, unsigned long addr, unsigned long len) {
  struct sockaddr_storage ss;
  memset(&ss, 0, sizeof ss);
  size_t n = len > sizeof ss ? sizeof ss : (size_t)len;
  if (n < sizeof(sa_family_t) || !read_mem(pid, addr, &ss, n)) {
    fprintf(stderr, "0x%lx", addr);
    return;
  }
  switch (ss.ss_family) {
  case AF_INET: {
    struct sockaddr_in *in = (struct sockaddr_in *)&ss;
    char ip[INET_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET, &in->sin_addr, ip, sizeof ip);
    fprintf(stderr, "{sa_family=AF_INET, sin_port=htons(%u), sin_addr=inet_addr(\"%s\")}",
            ntohs(in->sin_port), ip);
    return;
  }
  case AF_INET6: {
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&ss;
    char ip[INET6_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET6, &in6->sin6_addr, ip, sizeof ip);
    fprintf(stderr, "{sa_family=AF_INET6, sin6_port=htons(%u), inet_pton(AF_INET6, \"%s\", "
                    "&sin6_addr), sin6_flowinfo=htonl(%u), sin6_scope_id=%u}",
            ntohs(in6->sin6_port), ip, ntohl(in6->sin6_flowinfo), in6->sin6_scope_id);
    return;
  }
  case AF_UNIX: {
    struct sockaddr_un *un = (struct sockaddr_un *)&ss;
    size_t plen = n > offsetof(struct sockaddr_un, sun_path)
                ? n - offsetof(struct sockaddr_un, sun_path) : 0;
    char esc[sizeof un->sun_path * 4 + 8];
    if (plen && un->sun_path[0] == 0) {    // abstract: the name follows a NUL
      escape_into((unsigned char *)un->sun_path + 1, plen - 1, esc, sizeof esc);
      fprintf(stderr, "{sa_family=AF_UNIX, sun_path=@%s}", esc);
    } else {
      escape_into((unsigned char *)un->sun_path, strnlen(un->sun_path, plen), esc, sizeof esc);
      fprintf(stderr, "{sa_family=AF_UNIX, sun_path=%s}", esc);
    }
    return;
  }
  default: {
    // shortcut: other families print the number. AF_NETLINK and AF_PACKET have
    // their own layouts and no test here reaches them; adding one is a case.
    fprintf(stderr, "{sa_family=%u, ...}", (unsigned)ss.ss_family);
    return;
  }
  }
}

// Does this syscall's struct get filled in by the kernel, so it can only be
// printed on the exit half? Returns the argument index of the buffer, or -1.
static int stat_buf_arg(long nr) {
  switch (nr) {
  case 4: case 6: case 5: return 1;    // stat, lstat, fstat
  case 262:               return 2;    // newfstatat(dirfd, path, buf, flags)
  default:                return -1;
  }
}

// The entry half of one call: the name and everything known before the kernel
// runs. Leaves the line open; the exit half closes it.
static void print_entry(pid_t pid, long nr, const unsigned long *a) {
  const char *nm = syscall_name(nr);
  char path[512];

  switch (nr) {
  case 2:                                     // open(path, flags, mode)
    read_string(pid, a[0], path, sizeof path);
    fprintf(stderr, "%s(%s, ", nm, path);
    print_open_flags(a[1]);
    if (a[1] & O_CREAT) fprintf(stderr, ", 0%03o", (unsigned)(a[2] & 07777));
    return;
  case 257:                                   // openat(dirfd, path, flags, mode)
    read_string(pid, a[1], path, sizeof path);
    fprintf(stderr, "%s(%s, %s, ", nm, dirfd_str(a[0]), path);
    print_open_flags(a[2]);
    if (a[2] & O_CREAT) fprintf(stderr, ", 0%03o", (unsigned)(a[3] & 07777));
    return;
  case 19: case 20:                           // readv, writev (fd, iov, iovcnt)
    fprintf(stderr, "%s(%ld, ", nm, (long)a[0]);
    // readv's buffers are uninitialised here; only writev's are real data.
    if (nr == 20) print_iovec(pid, a[1], (long)a[2]);
    else fprintf(stderr, "0x%lx", a[1]);
    fprintf(stderr, ", %ld", (long)a[2]);
    return;
  case 42: case 49:                           // connect, bind (fd, addr, addrlen)
    fprintf(stderr, "%s(%ld, ", nm, (long)a[0]);
    print_sockaddr(pid, a[1], a[2]);
    fprintf(stderr, ", %lu", a[2]);
    return;
  case 4: case 6:                             // stat, lstat: struct at exit
    read_string(pid, a[0], path, sizeof path);
    fprintf(stderr, "%s(%s", nm, path);
    return;
  case 5:                                     // fstat(fd, buf)
    fprintf(stderr, "%s(%ld", nm, (long)a[0]);
    return;
  case 262:                                   // newfstatat(dirfd, path, buf, flags)
    read_string(pid, a[1], path, sizeof path);
    fprintf(stderr, "%s(%s, %s", nm, dirfd_str(a[0]), path);
    return;
  default: break;
  }

  int pi = path_arg(nr);
  if (pi >= 0) {
    read_string(pid, a[pi], path, sizeof path);
    if (pi == 0) fprintf(stderr, "%s(%s, ...", nm, path);
    else         fprintf(stderr, "%s(%ld, %s, ...", nm, (long)a[0], path);
  } else {
    fprintf(stderr, "%s(0x%lx, 0x%lx, 0x%lx", nm, a[0], a[1], a[2]);
  }
}

// The arguments the kernel wrote, printed on the exit half because they do not
// exist yet on entry. A failed call wrote nothing, so the pointer is printed
// instead of a struct full of whatever was there before.
static void print_exit_args(pid_t pid, long nr, const unsigned long *a, long ret) {
  int bi = stat_buf_arg(nr);
  if (bi < 0) return;
  fputs(", ", stderr);
  if (ret == 0) print_stat(pid, a[bi]);
  else fprintf(stderr, "0x%lx", a[bi]);
  if (nr == 262) { fputs(", ", stderr); print_at_flags(a[3]); }
}

static int cmp_count(const void *a, const void *b) {
  long ia = *(const long *)a, ib = *(const long *)b;
  if (counts[ia] != counts[ib]) return counts[ib] - counts[ia] > 0 ? 1 : -1;
  return ia - ib;
}

static void print_summary(void) {
  long idx[512];
  int n = 0;
  long total = 0;
  for (long i = 0; i < 512; i++)
    if (counts[i] && is_shown(i)) { idx[n++] = i; total += counts[i]; }

  qsort(idx, n, sizeof(long), cmp_count);

  fprintf(stderr, "%8s %8s %-20s\n", "calls", "errors", "syscall");
  for (int i = 0; i < n; i++)
    fprintf(stderr, "%8ld %8ld %-20s\n", counts[idx[i]], errors[idx[i]], syscall_name(idx[i]));
  fprintf(stderr, "%8ld %8s %-20s\n", total, "", "total");
}

// -p: take over a process that is already running.
//
// PTRACE_SEIZE rather than PTRACE_ATTACH. ATTACH sends SIGSTOP and leaves a
// stop the tracer has to recognise and swallow, and getting that dance wrong
// is how an attached process ends up stopped forever. SEIZE does not signal
// the target at all, and it is the only way to set options and attach in one
// operation, which matters because between an attach and a SETOPTIONS the
// target is running untraced.
//
// EXITKILL is deliberately NOT in these options, where it is in the options
// for a process we started ourselves. There it means "do not leave an orphan
// stopped forever if the tracer dies". Here the process is not ours, it was
// running before we arrived, and killing it because our own process exited
// would be the worst thing this program could do.
//
// PTRACE_INTERRUPT after the seize, because SEIZE leaves the target running
// and PTRACE_SYSCALL needs it stopped. The group-stop that produces is what
// the main loop's first waitpid collects.
static int attach(pid_t pid) {
  long opts = PTRACE_O_TRACESYSGOOD;
  if (follow) opts |= PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE;

  if (ptrace(PTRACE_SEIZE, pid, 0, (void *)opts) < 0) {
    // EPERM here is usually not a permission problem in the usual sense: it is
    // kernel.yama.ptrace_scope refusing an attach to a process that is not a
    // descendant. Saying so saves the next person the hour.
    fprintf(stderr, "trace: cannot attach to %d: %s\n", (int)pid, strerror(errno));
    if (errno == EPERM)
      fprintf(stderr, "trace: check kernel.yama.ptrace_scope; 1 allows "
                      "attaching only to descendants\n");
    return 1;
  }
  if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) < 0) {
    perror("PTRACE_INTERRUPT");
    ptrace(PTRACE_DETACH, pid, 0, 0);
    return 1;
  }

  root_pid = pid;
  tracee_add(pid);
  if (!count_only) fprintf(stderr, "+++ attached to %d +++\n", (int)pid);
  return 0;
}

int main(int argc, char **argv) {
  int argi = 1;
  for (; argi < argc && argv[argi][0] == '-'; argi++) {
    if (!strcmp(argv[argi], "-c")) count_only = true;
    else if (!strcmp(argv[argi], "-f")) follow = true;
    else if (!strcmp(argv[argi], "-cf") || !strcmp(argv[argi], "-fc")) { count_only = follow = true; }
    else if (!strcmp(argv[argi], "-e")) {
      if (argi + 1 >= argc) { fprintf(stderr, "trace: -e needs a list\n"); return 2; }
      int rc = parse_filter(argv[++argi]);
      if (rc) return rc;
    }
    else if (!strncmp(argv[argi], "-e", 2) && argv[argi][2]) {
      int rc = parse_filter(argv[argi] + 2);  // -eread,write, as strace allows
      if (rc) return rc;
    }
    else if (!strcmp(argv[argi], "-p")) {
      if (argi + 1 >= argc) { fprintf(stderr, "trace: -p needs a pid\n"); return 2; }
      char *end;
      long v = strtol(argv[++argi], &end, 10);
      if (*end || v <= 0) {
        fprintf(stderr, "trace: -p: not a pid: %s\n", argv[argi]);
        return 2;
      }
      attach_pid = (pid_t)v;
    }
    else if (!strcmp(argv[argi], "--")) { argi++; break; }
    else { fprintf(stderr, "trace: unknown option %s\n", argv[argi]); return 2; }
  }
  if (attach_pid && argi < argc) {
    fprintf(stderr, "trace: -p takes a pid, not a command\n");
    return 2;
  }
  if (!attach_pid && argi >= argc) {
    fprintf(stderr, "usage: trace [-c] [-f] [-e LIST] CMD [ARGS...]\n"
                    "       trace [-c] [-f] [-e LIST] -p PID\n"
                    "  -c        print a per-syscall summary instead of each call\n"
                    "  -f        follow fork, vfork and clone into children\n"
                    "  -e LIST   report only these syscalls, comma separated.\n"
                    "            'trace=' may prefix the list, as in strace.\n"
                    "  -p PID    attach to a running process and trace until it\n"
                    "            exits or this is interrupted\n");
    return 2;
  }

  int status;

  if (attach_pid) {
    int rc = attach(attach_pid);
    if (rc) return rc;
  } else {
  pid_t pid = fork();
  if (pid < 0) { perror("fork"); return 1; }

  if (pid == 0) {
    // Ask to be traced, then stop at the exec so the parent can set options.
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) { perror("PTRACE_TRACEME"); _exit(127); }
    execvp(argv[argi], &argv[argi]);
    fprintf(stderr, "trace: cannot exec %s: %s\n", argv[argi], strerror(errno));
    _exit(127);
  }

  root_pid = pid;
  if (waitpid(pid, &status, 0) < 0) { perror("waitpid"); return 1; }

  // If execvp failed there was never an exec, so there is no stop to attach
  // options to -- the child has already exited. Propagate its status instead of
  // reporting a ptrace error.
  if (WIFEXITED(status)) return WEXITSTATUS(status);

  // TRACESYSGOOD marks syscall stops with SIGTRAP|0x80, so they are
  // distinguishable from a real SIGTRAP. EXITKILL means the tracee dies with us
  // instead of being left stopped forever if we crash. The TRACE{FORK,VFORK,
  // CLONE} options make the kernel attach us to every new child automatically
  // and tell us its pid, which closes the race you would otherwise have between
  // the child being created and us finding out about it.
  long opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL;
  if (follow) opts |= PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE;
  if (ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)opts) < 0) {
    perror("PTRACE_SETOPTIONS");
    return 1;
  }

  tracee_add(pid);

  // The exec stop was already consumed above, so the tracee is stopped and
  // nothing has restarted it. The loop below begins with waitpid, so it must be
  // running by then or we wait forever for a stop that already happened.
  if (ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0) { perror("PTRACE_SYSCALL"); return 1; }
  }

  int root_status = 0;

  // One loop for every process. waitpid(-1) because any tracee may stop next,
  // and __WALL so clone()d threads are reported too.
  for (;;) {
    if (live_tracees == 0) break;

    pid_t who = waitpid(-1, &status, __WALL);
    if (who < 0) {
      if (errno == EINTR) continue;
      break;                      // ECHILD: nothing left to wait for
    }

    Tracee *t = tracee_find(who);
    if (!t) {
      // A child reported before its parent's fork-event stop. It is already
      // traced and stopped; adopt it and let it run.
      t = tracee_add(who);
      ptrace(PTRACE_SYSCALL, who, 0, 0);
      continue;
    }

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      if (!t->entering && t->pending_nr >= 0 && !count_only &&
          is_shown(t->pending_nr)) {
        // exit_group produces no syscall-exit stop, so the last call is still
        // outstanding. Report it unreturned rather than dropping it.
        line_prefix(who);
        fprintf(stderr, "%s(...) = ?\n", syscall_name(t->pending_nr));
      }
      if (who == root_pid) root_status = status;
      tracee_drop(t);
      continue;
    }

    if (!WIFSTOPPED(status)) continue;

    int sig = WSTOPSIG(status);
    int event = status >> 16;

    // A ptrace event stop: SIGTRAP with an event code in the high bits.
    if (sig == SIGTRAP && event) {
      if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
          event == PTRACE_EVENT_CLONE) {
        unsigned long child = 0;
        if (ptrace(PTRACE_GETEVENTMSG, who, 0, &child) == 0) {
          tracee_add((pid_t)child);
          if (!count_only) {
            line_prefix(who);
            fprintf(stderr, "+++ new process %lu +++\n", child);
          }
        }
      }
      ptrace(PTRACE_SYSCALL, who, 0, 0);
      continue;
    }

    // Not a syscall stop: a real signal is being delivered. Pass it through so
    // the tracee behaves exactly as it would untraced.
    if (sig != (SIGTRAP | 0x80)) {
      ptrace(PTRACE_SYSCALL, who, 0, (void *)(long)(sig == SIGTRAP ? 0 : sig));
      continue;
    }

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, who, 0, &regs) < 0) { ptrace(PTRACE_SYSCALL, who, 0, 0); continue; }

    if (t->entering) {
      long nr = (long)regs.orig_rax;
      t->pending_nr = nr;
      if (nr >= 0 && nr < 512) counts[nr]++;

      // The filter is applied here and again on the exit half below, both
      // keyed on the same number, because one call is printed by two stops:
      // the name and arguments on entry, the result on exit. Gating only one
      // of them would leave a dangling open paren or an orphan " = 0".
      // Kept for the exit half: a struct the kernel fills in can only be read
      // after the call returns, and rax has been overwritten by then.
      unsigned long a[6] = { regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9 };
      memcpy(t->pending_args, a, sizeof a);

      if (!count_only && is_shown(nr)) {
        line_prefix(who);
        print_entry(who, nr, a);
      }
      t->entering = false;
    } else {
      long ret = (long)regs.rax;
      long nr = t->pending_nr;
      // The kernel returns -errno in rax; the libc wrapper is what turns that
      // into -1 plus errno, so we have to recognise it ourselves.
      bool is_err = (ret < 0 && ret > -4096);
      if (is_err && nr >= 0 && nr < 512) errors[nr]++;

      if (!count_only && is_shown(nr)) {
        print_exit_args(who, nr, t->pending_args, is_err ? -1 : ret);
        if (is_err) fprintf(stderr, ") = -1 %s\n", strerror((int)-ret));
        else        fprintf(stderr, ") = %ld\n", ret);
      }
      t->entering = true;
      t->pending_nr = -1;
    }

    ptrace(PTRACE_SYSCALL, who, 0, 0);
  }

  if (count_only) print_summary();

  // Mirror the shell's convention so a signal death is distinguishable from a
  // clean exit. Returning WEXITSTATUS unconditionally reports 0 for a killed
  // process, which is exactly the bug this file already fixed once.
  if (WIFEXITED(root_status)) return WEXITSTATUS(root_status);
  if (WIFSIGNALED(root_status)) {
    fprintf(stderr, "trace: killed by signal %d\n", WTERMSIG(root_status));
    return 128 + WTERMSIG(root_status);
  }
  return 0;
}
