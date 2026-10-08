// SPDX-License-Identifier: Apache-2.0
// Non-A/B OTA helper: synchronize only a recognized TWRP boot-header OS word.
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <openssl/sha.h>
#include <stdexcept>
#include <string>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
constexpr uint64_t kPartitionBytes = 47185920;
constexpr char kByName[] = "/dev/block/platform/13500000.dwmmc0/by-name/recovery";
constexpr char kBlock[] = "/dev/block/mmcblk0p16";
// Exact identities of the two physically tested 3.7.1_12 images, excluding
// only OS/SPL bytes 44..47. Kernel, ramdisk, DTBO and trailer remain guarded.
struct KnownRecovery { size_t bytes; const char* identity; };
constexpr KnownRecovery kKnownRecoveries[] = {
    {38979600, "0c641ba8f29bd9a4063cf9e8670dfc84124bc926f7bead643977685827306cc6"},
    {38981648, "d8878895ec55959e9f3697c1ee3e8a983e304067a2cde26baa51d00fe664b751"},
};
constexpr char kStatus[] = "/tmp/gta3xlwifi-recovery-header.status";

struct Fd {
    int value;
    explicit Fd(int fd) : value(fd) {}
    ~Fd() { if (value >= 0) close(value); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
};
void Require(bool ok, const char* reason) {
    if (!ok) throw std::runtime_error(reason);
}
void Read(int fd, void* data, size_t n, off_t offset) {
    size_t done = 0;
    while (done < n) {
        ssize_t rc = pread(fd, static_cast<char*>(data) + done, n - done, offset + done);
        if (rc < 0 && errno == EINTR) continue;
        Require(rc > 0, "Cannot read RECOVERY");
        done += static_cast<size_t>(rc);
    }
}
void Write(int fd, const void* data, size_t n, off_t offset) {
    size_t done = 0;
    while (done < n) {
        ssize_t rc = pwrite(fd, static_cast<const char*>(data) + done, n - done, offset + done);
        if (rc < 0 && errno == EINTR) continue;
        Require(rc > 0, "Cannot write RECOVERY header");
        done += static_cast<size_t>(rc);
    }
}
uint32_t Word(const std::array<uint8_t, 512>& page) {
    return uint32_t(page[44]) | uint32_t(page[45]) << 8 |
           uint32_t(page[46]) << 16 | uint32_t(page[47]) << 24;
}
std::string Identity(int fd, size_t image_bytes) {
    SHA256_CTX ctx;
    Require(SHA256_Init(&ctx) == 1, "SHA-256 initialization failed");
    std::array<uint8_t, 65536> chunk;
    for (size_t offset = 0; offset < image_bytes;) {
        size_t n = std::min(chunk.size(), image_bytes - offset);
        Read(fd, chunk.data(), n, offset);
        if (offset == 0) std::memset(chunk.data() + 44, 0, 4);
        Require(SHA256_Update(&ctx, chunk.data(), n) == 1, "SHA-256 update failed");
        offset += n;
    }
    std::array<uint8_t, SHA256_DIGEST_LENGTH> digest;
    Require(SHA256_Final(digest.data(), &ctx) == 1, "SHA-256 finalization failed");
    char text[SHA256_DIGEST_LENGTH * 2 + 1];
    for (size_t i = 0; i < digest.size(); ++i) std::snprintf(text + 2 * i, 3, "%02x", digest[i]);
    return text;
}
void Status(const char* path, const char* result) {
    Fd fd(open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600));
    Require(fd.value >= 0, "Cannot create temporary recovery status");
    std::string contents = std::string("result=") + result + "\n";
    Write(fd.value, contents.data(), contents.size(), 0);
    Require(fsync(fd.value) == 0, "Cannot synchronize temporary status");
}
void ValidateWord(uint32_t word) {
    Require((word >> 11) == (14U << 14), "Only tested Android 14 recovery compatibility is supported");
    Require((word & 15) >= 1 && (word & 15) <= 12 && ((word >> 4) & 127) >= 20,
            "Invalid recovery patch level");
}
}  // namespace

int main(int argc, char** argv) {
    try {
        Require(argc >= 3, "Usage: recovery-header-sync --preflight|--apply OS_WORD");
        bool apply = std::strcmp(argv[1], "--apply") == 0;
        Require(apply || std::strcmp(argv[1], "--preflight") == 0, "Unknown mode");
        errno = 0;
        char* end = nullptr;
        unsigned long value = std::strtoul(argv[2], &end, 0);
        Require(errno == 0 && end != argv[2] && *end == '\0' && value <= UINT32_MAX,
                "Invalid target OS word");
        uint32_t target = static_cast<uint32_t>(value);
        ValidateWord(target);
        const char* path = kBlock;
        const char* status = kStatus;
        bool test = false;
#ifdef RECOVERY_HEADER_SYNC_HOST_TEST
        if (argc == 7 && std::strcmp(argv[3], "--test-image") == 0 &&
            std::strcmp(argv[5], "--status-file") == 0) {
            test = true;
            path = argv[4];
            status = argv[6];
        }
#endif
        Require(argc == 3 || test, "Unexpected arguments");
        if (!test) {
            char canonical[PATH_MAX];
            Require(realpath(kByName, canonical) != nullptr && std::strcmp(canonical, kBlock) == 0,
                    "Unexpected RECOVERY partition path");
        }
        Fd fd(open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_SYNC));
        Require(fd.value >= 0, "Cannot open RECOVERY for synchronization");
        Require(flock(fd.value, LOCK_EX) == 0, "Cannot lock RECOVERY");
        struct stat st;
        Require(fstat(fd.value, &st) == 0, "Cannot inspect RECOVERY");
        uint64_t bytes = 0;
        if (test) {
            Require(S_ISREG(st.st_mode), "Test input must be a regular file");
            bytes = st.st_size;
        } else {
            Require(S_ISBLK(st.st_mode), "RECOVERY is not a block device");
            Require(ioctl(fd.value, BLKGETSIZE64, &bytes) == 0, "Cannot inspect RECOVERY size");
        }
        Require(bytes == kPartitionBytes, "Unexpected RECOVERY partition size");
        std::array<uint8_t, 512> original;
        Read(fd.value, original.data(), original.size(), 0);
        const KnownRecovery* recognized = nullptr;
        if (std::memcmp(original.data(), "ANDROID!", 8) == 0) {
            for (const auto& candidate : kKnownRecoveries) {
                if (Identity(fd.value, candidate.bytes) == candidate.identity) {
                    recognized = &candidate;
                    break;
                }
            }
        }
        if (!recognized) {
            Status(status, "unsupported");
            std::puts("Recovery is not the recognized TWRP image; left unchanged.");
            return 0;
        }
        uint32_t current = Word(original);
        ValidateWord(current);
        Require((target & 2047) >= (current & 2047), "Refusing a recovery patch-level downgrade");
        if (!apply) {
            Status(status, "supported");
            std::puts("Recognized TWRP: recovery header preflight passed.");
            return 0;
        }
        if (target == current) {
            Status(status, "synchronized");
            std::puts("TWRP header already matches this ROM; no partition write needed.");
            return 0;
        }
        auto updated = original;
        for (unsigned int i = 0; i < 4; ++i) updated[44 + i] = (target >> (8 * i)) & 255;
        std::array<uint8_t, 512> latest;
        Read(fd.value, latest.data(), latest.size(), 0);
        Require(latest == original, "Recovery header changed after preflight");
        try {
            // One aligned sector, with only the four metadata bytes changed.
            Write(fd.value, updated.data(), updated.size(), 0);
#ifdef RECOVERY_HEADER_SYNC_HOST_TEST
            if (std::getenv("GTA3XLWIFI_TEST_FAIL_AFTER_WRITE")) {
                throw std::runtime_error("Injected test failure after header write");
            }
#endif
            Require(fsync(fd.value) == 0, "Cannot synchronize RECOVERY write");
            Read(fd.value, latest.data(), latest.size(), 0);
            Require(latest == updated && Identity(fd.value, recognized->bytes) == recognized->identity,
                    "RECOVERY readback failed");
            Status(status, "synchronized");
        } catch (...) {
            Write(fd.value, original.data(), original.size(), 0);
            Require(fsync(fd.value) == 0, "RECOVERY rollback synchronization failed");
            Read(fd.value, latest.data(), latest.size(), 0);
            Require(latest == original && Identity(fd.value, recognized->bytes) == recognized->identity,
                    "RECOVERY rollback verification failed");
            std::fputs("Original recovery header restored after synchronization failure.\n", stderr);
            throw;
        }
        std::printf("TWRP header synchronized: 0x%08x -> 0x%08x; image payload unchanged.\n",
                    current, target);
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "Recovery header synchronization failed: %s\n", error.what());
        return 1;
    }
}
