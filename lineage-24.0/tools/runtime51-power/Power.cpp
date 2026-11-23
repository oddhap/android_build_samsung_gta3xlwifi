// SPDX-License-Identifier: Apache-2.0
#define LOG_TAG "Gta3xlwifiPower"
#include "BoostWindow.h"
#include "Gta3xlwifiPower.h"
#include "RetryBackoff.h"
#include "TouchWake.h"
#include <aidl/android/hardware/power/Mode.h>
#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>
#include <android-base/strings.h>
#include <android/log.h>
#include <log/log.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>

// Failures and recoveries also go to the system log buffer, which keeps far fewer
// lines than main, so the reason is still there long after the event.
#define LOG_BOTH(prio, ...)                                                   \
    do {                                                                      \
        __android_log_print(prio, LOG_TAG, __VA_ARGS__);                      \
        __android_log_buf_print(LOG_ID_SYSTEM, prio, LOG_TAG, __VA_ARGS__);   \
    } while (0)

using android::base::unique_fd;
using aidl::android::hardware::power::Mode;
namespace gta3xlwifi {
namespace {
constexpr const char* kLittlePath = "/dev/gta3xlwifi_cluster0_min";
constexpr const char* kBigPath = "/dev/gta3xlwifi_cluster1_min";
constexpr const char* kGpuPath = "/sys/devices/platform/11500000.mali/gta3xlwifi_min_lock";
}  // namespace

// A failed open or write no longer disables the boost until reboot: the request is
// released (CPU fds closed, GPU slot cleared), the reason is logged to main and system,
// and the controls are reopened on a later request after a 1 s .. 60 s backoff.
class Power {
  public:
    Power() {
        std::lock_guard<std::mutex> guard(mMutex);
        // Constructed by nativeInit inside system_server, never in the zygote.
        tryEnable(Clock::now(), "init");
        mWorker = std::thread([this] { run(); });
    }
    void interaction(int32_t durationMs) {
        std::lock_guard<std::mutex> guard(mMutex);
        const auto now = Clock::now();
        ++mInteractions;
        mWindow.interaction(durationMs, now);
        update("interaction", now);
    }
    bool mode(int32_t value, bool enabled) {
        std::lock_guard<std::mutex> guard(mMutex);
        // Gesture/touch control is independent of CPU/GPU boost readiness.
        if (static_cast<Mode>(value) == Mode::DOUBLE_TAP_TO_WAKE)
            return mTouch.doubleTap(enabled);
        const bool touchHandled = static_cast<Mode>(value) == Mode::INTERACTIVE &&
                                  mTouch.interactive(enabled);
        const auto now = Clock::now();
        // The window state is tracked even while the controls are suspended, so a
        // recovery applies the correct floors (e.g. none while the screen is off).
        switch (static_cast<Mode>(value)) {
            case Mode::INTERACTIVE: mWindow.interactive(enabled); break;
            case Mode::LOW_POWER: mWindow.lowPower(enabled); break;
            case Mode::LAUNCH:
                if (enabled) ++mLaunches;
                mWindow.launch(enabled, now);
                break;
            default: return false;
        }
        // Clear before the caller can suspend, not after a worker wakeup.
        update("mode", now);
        return mReady || touchHandled;
    }
  private:
    static bool writeTouchControl(TouchControl control, bool enabled) {
        const char* path = control == TouchControl::DoubleTap
                ? "/sys/class/sec/tsp/double_tap_to_wake"
                : "/sys/class/sec/tsp/input_enabled";
        const char value = enabled ? '1' : '0';
        unique_fd fd(open(path, O_WRONLY | O_CLOEXEC));
        if (!fd.ok() || TEMP_FAILURE_RETRY(write(fd.get(), &value, 1)) != 1) {
            ALOGE("Touch power control failed: %s=%c errno=%d", path, value, errno);
            return false;
        }
        std::string readback;
        if (!android::base::ReadFileToString(path, &readback) ||
                android::base::Trim(readback) != std::string(1, value)) {
            ALOGE("Touch power readback failed: %s=%c", path, value);
            return false;
        }
        return true;
    }
    static bool writeCpu(int fd, int frequency) {
        const int32_t value = frequency;
        return TEMP_FAILURE_RETRY(write(fd, &value, sizeof(value))) == static_cast<ssize_t>(sizeof(value));
    }
    bool writeGpu(int frequency) {
        const std::string value = std::to_string(frequency);
        return lseek(mGpu.get(), 0, SEEK_SET) == 0 &&
               TEMP_FAILURE_RETRY(write(mGpu.get(), value.data(), value.size())) == static_cast<ssize_t>(value.size());
    }
    // Opens all three controls and writes zero floors. Rate limited by mRetry.
    void tryEnable(Clock::time_point now, const char* reason) {
        if (mReady || !mRetry.canAttempt(now)) return;
        errno = 0;
        mLittle.reset(open(kLittlePath, O_RDWR | O_CLOEXEC));
        if (!mLittle.ok()) return fail("open", kLittlePath, errno, now);
        mBig.reset(open(kBigPath, O_RDWR | O_CLOEXEC));
        if (!mBig.ok()) return fail("open", kBigPath, errno, now);
        mGpu.reset(open(kGpuPath, O_WRONLY | O_CLOEXEC));
        if (!mGpu.ok()) return fail("open", kGpuPath, errno, now);
        mReady = true;
        if (!apply({}, now)) return;
        if (mRetry.total() == 0) {
            ALOGI("Bounded CPU/GPU boost ready: touch=400ms launch<=2000ms");
        } else {
            LOG_BOTH(ANDROID_LOG_INFO, "Power boost recovered (%s) after %u consecutive failure(s), %u total",
                     reason, mRetry.consecutive(), mRetry.total());
        }
        mRetry.success();
    }
    // Releases this backend's requests and schedules a retry; never disables for good.
    void fail(const char* op, const char* control, int err, Clock::time_point now) {
        // Closing a QoS fd removes only our request, including on process death.
        mLittle.reset();
        mBig.reset();
        if (mGpu.ok()) writeGpu(0);
        mGpu.reset();
        mReady = false;
        mApplied = {};
        const auto delay = mRetry.failure(now);
        LOG_BOTH(ANDROID_LOG_ERROR,
                 "Power boost suspended: %s %s failed errno=%d (%s); failure %u (total %u), retry after %lld ms",
                 op, control, err, strerror(err), mRetry.consecutive(), mRetry.total(),
                 static_cast<long long>(delay.count()));
    }
    bool apply(const Floors& floors, Clock::time_point now) {
        errno = 0;
        if (!writeCpu(mLittle.get(), floors.little)) {
            fail("write", kLittlePath, errno, now);
            return false;
        }
        if (!writeCpu(mBig.get(), floors.big)) {
            fail("write", kBigPath, errno, now);
            return false;
        }
        if (!writeGpu(floors.gpu)) {
            fail("write", kGpuPath, errno, now);
            return false;
        }
        mApplied = floors;
        return true;
    }
    void update(const char* reason, Clock::time_point now) {
        tryEnable(now, reason);
        if (mReady) {
            const Floors floors = mWindow.floors(now);
            if (floors != mApplied) apply(floors, now);
        }
        if (android::base::GetBoolProperty("debug.gta3xlwifi.power_log", false)) {
            ALOGI("%s: requests=%llu/%llu floor_khz=%d/%d/%d ready=%d failures=%u",
                  reason, static_cast<unsigned long long>(mInteractions),
                  static_cast<unsigned long long>(mLaunches), mApplied.little,
                  mApplied.big, mApplied.gpu, mReady, mRetry.total());
        }
        mChanged.notify_all();
    }
    void run() {
        std::unique_lock<std::mutex> guard(mMutex);
        // Lives as long as system_server; while suspended it sleeps until a request
        // (update() reopens the controls and notifies).
        for (;;) {
            const auto now = Clock::now();
            if (mReady) {
                const Floors floors = mWindow.floors(now);
                if (floors != mApplied) {
                    apply(floors, now);
                    if (android::base::GetBoolProperty("debug.gta3xlwifi.power_log", false))
                        ALOGI("expiry: floor_khz=%d/%d/%d ready=%d", mApplied.little,
                              mApplied.big, mApplied.gpu, mReady);
                }
            }
            const auto deadline = mReady ? mWindow.nextDeadline(now) : std::nullopt;
            if (deadline) mChanged.wait_until(guard, *deadline);
            else mChanged.wait(guard);
        }
    }
    unique_fd mLittle, mBig, mGpu;
    TouchWake mTouch{writeTouchControl};
    bool mReady = false;
    BoostWindow mWindow;
    RetryBackoff mRetry;
    Floors mApplied;
    std::mutex mMutex;
    std::condition_variable mChanged;
    std::thread mWorker;
    uint64_t mInteractions = 0, mLaunches = 0;
};
// Lifetime is that of system_server. Never destroy a joinable worker at exit;
// kernel fd cleanup and init's zygote restart trigger release the constraints.
static Power& power() { static Power* instance = new Power(); return *instance; }
void initPower() { (void)power(); }
void interactionBoost(int32_t durationMs) { power().interaction(durationMs); }
bool powerMode(int32_t mode, bool enabled) { return power().mode(mode, enabled); }
}  // namespace gta3xlwifi
