// SPDX-License-Identifier: Apache-2.0
// Optional on-device test of the actual libprocessgroup and kernel lifecycle.
#include <processgroup/processgroup.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <unistd.h>

static constexpr uid_t kUid = 99002;
static volatile sig_atomic_t child = -1, grandchild = -1;

static void timeout_handler(int) {
    if (grandchild > 0) kill(grandchild, SIGKILL);
    if (child > 0) { kill(-child, SIGKILL); kill(child, SIGKILL); }
    constexpr char message[] = "FAIL: lifecycle test timed out\n";
    write(STDERR_FILENO, message, sizeof(message) - 1);
    _exit(2);
}

static void cleanup() {
    if (grandchild > 0) kill(grandchild, SIGKILL);
    if (child > 0) kill(child, SIGKILL);
    while (waitpid(-1, nullptr, 0) > 0 || errno == EINTR) {}
    char path[160];
    if (child > 0) {
        snprintf(path, sizeof(path), "/acct/uid_%u/pid_%d", kUid, child);
        rmdir(path);
    }
    snprintf(path, sizeof(path), "/acct/uid_%u", kUid);
    rmdir(path);
}

static void fail(const char* message) {
    const int error = errno;
    fprintf(stderr, "FAIL: %s: %s\n", message, strerror(error));
    cleanup();
    exit(1);
}

static void receive(int fd, void* data, size_t length) {
    ssize_t n;
    do { n = read(fd, data, length); } while (n < 0 && errno == EINTR);
    if (n != static_cast<ssize_t>(length)) fail("child handshake");
}

int main() {
    if (getuid() != 0) { fprintf(stderr, "Requires rooted debugging\n"); return 1; }
    struct statfs filesystem;
    if (access("/system/etc/cgroups.gta3xlwifi.json", R_OK) ||
        statfs("/acct", &filesystem) || filesystem.f_type != CGROUP_SUPER_MAGIC) {
        fprintf(stderr, "Requires the SM-T510 cgroup v1 backend and mounted controller\n");
        return 1;
    }
    char path[160];
    snprintf(path, sizeof(path), "/acct/uid_%u", kUid);
    struct stat st;
    if (lstat(path, &st) == 0 || errno != ENOENT) {
        fprintf(stderr, "Test UID cgroup already exists; leaving it untouched\n");
        return 1;
    }
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)) fail("subreaper setup");
    signal(SIGALRM, timeout_handler);
    alarm(15);
    int command[2], report[2];
    if (pipe(command) || pipe(report)) fail("pipe setup");
    child = fork();
    if (child < 0) fail("fork");
    if (child == 0) {
        close(command[1]); close(report[0]);
        if (setsid() < 0) _exit(10);
        char byte = 'r';
        if (write(report[1], &byte, 1) != 1 || read(command[0], &byte, 1) != 1) _exit(11);
        const pid_t descendant = fork();
        if (descendant < 0) _exit(12);
        if (descendant == 0) {
            // Escape the parent's Unix process group. cgroup membership must
            // still allow the library to find and kill this descendant.
            const pid_t self = getpid();
            if (write(report[1], &self, sizeof(self)) != sizeof(self)) _exit(14);
            // Wait until the parent knows this PID before escaping its group.
            if (read(command[0], &byte, 1) != 1 || setsid() < 0 || setuid(kUid)) _exit(13);
            if (write(report[1], &byte, 1) != 1) _exit(16);
            for (;;) pause();
        }
        if (setuid(kUid)) _exit(15);
        for (;;) pause();
    }
    close(command[0]); close(report[1]);
    char ready;
    receive(report[0], &ready, 1);
    const int created = createProcessGroup(kUid, child, false);
    if (created) { errno = -created; fail("createProcessGroup"); }
    if (write(command[1], "g", 1) != 1) fail("start descendant");
    pid_t descendant;
    receive(report[0], &descendant, sizeof(descendant));
    grandchild = descendant;
    if (write(command[1], "g", 1) != 1) fail("release descendant");
    receive(report[0], &ready, 1);
    if (grandchild <= 0 || getpgid(grandchild) != grandchild) fail("descendant process group");
    snprintf(path, sizeof(path), "/acct/uid_%u/pid_%d/cgroup.procs", kUid, child);
    FILE* fp = fopen(path, "re");
    if (!fp) fail("real cgroup membership");
    bool parent_found = false, descendant_found = false;
    int pid;
    while (fscanf(fp, "%d", &pid) == 1) {
        parent_found |= pid == child;
        descendant_found |= pid == grandchild;
    }
    fclose(fp);
    if (!parent_found || !descendant_found) fail("both descendants in cgroup");
    if (killProcessGroup(kUid, child, SIGKILL)) fail("killProcessGroup");
    int reaped = 0;
    while (reaped < 2) {
        int status;
        pid_t pid = waitpid(-1, &status, 0);
        if (pid < 0 && errno == EINTR) continue;
        if (pid != child && pid != grandchild) fail("reap descendants");
        if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) fail("descendant exit status");
        ++reaped;
    }
    snprintf(path, sizeof(path), "/acct/uid_%u/pid_%d", kUid, child);
    if (lstat(path, &st) == 0 || errno != ENOENT) fail("process cgroup cleanup");
    snprintf(path, sizeof(path), "/acct/uid_%u", kUid);
    if (lstat(path, &st) == 0 || errno != ENOENT) fail("isolated UID cgroup cleanup");
    printf("PASS: real cgroup v1 creation, inherited membership, escaped descendant SIGKILL and cleanup\n");
    alarm(0);
    return 0;
}
