#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Linux host tests of extracted production Bionic spawn fd-hygiene code.

Only syscall call sites are redirected for fault injection. Real procfs,
fcntl, fork/vfork, dup2 file actions and exec are used. This is not an
Android-on-tablet test. Usage: test-spawn-cloexec.py path/to/spawn.cpp
"""
import argparse
from pathlib import Path
import platform
import subprocess
import tempfile


def extract(source, signature):
    start = source.index(signature)
    brace = source.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


PREFIX = r'''
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/close_range.h>
#include <linux/magic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>
#include <assert.h>

enum Mode { REAL, NO_SYSCALL, NO_FLAG, DENIED, OPEN_ERROR, READ_ERROR,
            SHORT_RECORD, ZERO_RECORD, NO_NUL, BAD_NAME, OVERFLOW_NAME,
            OVERSIZE_READ, GETFD_ERROR, SETFD_ERROR, NO_SLOT, NON_PROC, FS_ERROR, EMPTY_SCAN };
static Mode mode;
static int reads;
static int TestCloseRange(unsigned int first, unsigned int last, int flags) {
  if (first != 3 || last != ~0U || flags != CLOSE_RANGE_CLOEXEC) _exit(90);
  if (mode == REAL) return syscall(SYS_close_range, first, last, flags);
  errno = mode == NO_FLAG ? EINVAL : mode == DENIED ? EPERM : ENOSYS;
  return -1;
}
static int TestOpen(const char* path, int flags) {
  if (mode == OPEN_ERROR) { errno = EACCES; return -1; }
  // Exercise a real non-procfs directory, not a mocked filesystem magic.
  return open(mode == NON_PROC ? "/" : path, flags);
}
static int TestFstatfs(int fd, struct statfs* fs) {
  if (mode == FS_ERROR) { errno = EACCES; return -1; }
  return fstatfs(fd, fs);
}
static int TestFcntl(int fd, int cmd, int arg) {
  if ((mode == GETFD_ERROR && cmd == F_GETFD) ||
      (mode == SETFD_ERROR && cmd == F_SETFD)) { errno = EACCES; return -1; }
  return fcntl(fd, cmd, arg);
}
extern "C" int __getdents64(unsigned int fd, dirent* buffer, unsigned int count) {
  ++reads;
  if (mode == EMPTY_SCAN) return 0;
  if (mode == READ_ERROR) { errno = EIO; return -1; }
  if (mode == SHORT_RECORD) return 5;
  if (mode == OVERSIZE_READ) return count + 1;
  if (mode >= ZERO_RECORD && mode <= OVERFLOW_NAME) {
    memset(buffer, mode == NO_NUL ? '1' : 0, count);
    buffer->d_reclen = mode == ZERO_RECORD ? 0 : mode == OVERFLOW_NAME ? 48 : 24;
    if (mode == BAD_NAME) strcpy(buffer->d_name, "bad");
    if (mode == OVERFLOW_NAME) strcpy(buffer->d_name, "999999999999999999999999");
    return mode == OVERFLOW_NAME ? 48 : 24;
  }
  return syscall(SYS_getdents64, fd, buffer, count);
}
'''

SUFFIX = r'''
static int CountFds() {
  int count = 0;
  for (int fd = 0; fd <= 5000; ++fd) if (fcntl(fd, F_GETFD) != -1) ++count;
  return count;
}
static bool Closed(int fd) { return fcntl(fd, F_GETFD) == -1 && errno == EBADF; }
static int VerifyExec() {
  // No descriptors other than stdio and the explicitly requested file action
  // may survive exec, including descriptors above the lowered RLIMIT_NOFILE.
  for (int fd = 3; fd <= 5000; ++fd) {
    if (fd == 10) { if (Closed(fd)) return 80; }
    else if (!Closed(fd)) return 81;
  }
  return 0;
}
int main(int argc, char**) {
  if (argc == 2) return VerifyExec();
  struct rlimit initial_limit;
  assert(getrlimit(RLIMIT_NOFILE, &initial_limit) == 0 && initial_limit.rlim_max >= 8192);
  initial_limit.rlim_cur = 8192;
  assert(setrlimit(RLIMIT_NOFILE, &initial_limit) == 0);
  int extra[400];
  for (int& fd : extra) { fd = open("/dev/null", O_RDONLY); assert(fd >= 0); }
  int first = fcntl(extra[0], F_DUPFD, 1000);
  int high = fcntl(extra[0], F_DUPFD, 4096);
  assert(first >= 1000 && high >= 4096);
  int hole = extra[200];
  assert(hole < 256 && close(hole) == 0);
  extra[200] = -1;  // Leave one slot for opening procfs after lowering the limit.
  int passed = 0;
  for (int m = REAL; m <= EMPTY_SCAN; ++m) {
    const bool success = m <= NO_FLAG;
    for (int use_vfork = 0; use_vfork != 2; ++use_vfork) {
      for (int same_fd = 0; same_fd != 2; ++same_fd) {
        if (!success && same_fd) continue;
        mode = static_cast<Mode>(m);
        reads = 0;
        char exe[] = "/proc/self/exe", check[] = "check";
        char* argv[] = {exe, check, nullptr};
        pid_t pid = use_vfork ? vfork() : fork();
        assert(pid >= 0);
        if (pid == 0) {
          struct rlimit limit;
          if (getrlimit(RLIMIT_NOFILE, &limit)) _exit(70);
          limit.rlim_cur = limit.rlim_max = 256;  // Existing fds remain above both limits.
          if (setrlimit(RLIMIT_NOFILE, &limit)) _exit(71);
          if (mode == NO_SLOT && dup2(first, hole) != hole) _exit(83);
          int std_flags[3];
          for (int fd = 0; fd < 3; ++fd) std_flags[fd] = fcntl(fd, F_GETFD);
          int count_before = CountFds();
          int result = SetAllFdsCloseOnExec();
          int error = errno;
          if (CountFds() != count_before) _exit(72);  // The scan fd must be closed.
          if (!success) {
            int expected = mode == DENIED ? EPERM : mode == NO_SLOT ? EMFILE :
                mode == NON_PROC ? ENOTSUP :
                (mode == OPEN_ERROR || mode == GETFD_ERROR || mode == SETFD_ERROR ||
                 mode == FS_ERROR) ? EACCES : EIO;
            if (result != -1 || error != expected) _exit(73);
            if ((mode == DENIED || mode == OPEN_ERROR) && reads != 0) _exit(74);
            _exit(0);
          }
          if (result != 0) _exit(75);
          if ((mode == REAL && reads != 0) || (mode != REAL && reads < 2)) _exit(76);
          for (int fd = 0; fd < 3; ++fd) if (fcntl(fd, F_GETFD) != std_flags[fd]) _exit(77);
          for (int fd : extra) if (fd != -1 && !(fcntl(fd, F_GETFD) & FD_CLOEXEC)) _exit(78);
          if (!(fcntl(first, F_GETFD) & FD_CLOEXEC) ||
              !(fcntl(high, F_GETFD) & FD_CLOEXEC)) _exit(79);
          // Exercise the actual production dup2 action, including the fd==new_fd case.
          __posix_spawn_file_action action{};
          action.what = kDup2;
          action.fd = same_fd ? 10 : first;
          action.new_fd = 10;
          action.Do();
          execv(exe, argv);
          _exit(82);
        }
        int status;
        assert(waitpid(pid, &status, 0) == pid);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
          fprintf(stderr, "FAIL mode=%d vfork=%d same_fd=%d status=%d\n", m, use_vfork, same_fd, status);
          return 1;
        }
        // Child flag changes must not change the parent's fd table.
        assert(fcntl(first, F_GETFD) == 0 && fcntl(high, F_GETFD) == 0);
        for (int fd : extra) if (fd != -1) assert(fcntl(fd, F_GETFD) == 0);
        ++passed;
      }
    }
  }
  printf("PASS: %d extracted Bionic fd-hygiene cases (fork/vfork, exec, errors).\n", passed);
  return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    args = parser.parse_args()
    if platform.system() != 'Linux':
        parser.error('Requires Linux procfs, getdents64 and close_range; run on the build VM')
    source = args.source.read_text()
    functions = '\n\n'.join(extract(source, 'static int ' + name + '(') for name in
                            ['CloseOnExecScanError', 'SetCloseOnExecFromProc', 'SetAllFdsCloseOnExec'])
    assert functions.count('close_range(3,') == 1
    assert functions.count('open("/proc/self/fd",') == 1
    functions = functions.replace('close_range(3,', 'TestCloseRange(3,')
    functions = functions.replace('open("/proc/self/fd",', 'TestOpen("/proc/self/fd",')
    functions = functions.replace('fcntl(fd,', 'TestFcntl(fd,')
    functions = functions.replace('fstatfs(dir_fd,', 'TestFstatfs(dir_fd,')
    actions = source[source.index('enum Action {'):source.index('struct __posix_spawn_file_actions {')]
    with tempfile.TemporaryDirectory(prefix='gta3xlwifi-spawn-') as d:
        cpp, binary = Path(d) / 'test.cpp', Path(d) / 'test'
        cpp.write_text(PREFIX + actions + functions + SUFFIX)
        subprocess.run(['c++', '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(cpp), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    main()
