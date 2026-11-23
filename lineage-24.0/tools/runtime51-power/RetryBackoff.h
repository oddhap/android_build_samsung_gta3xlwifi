// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <algorithm>
#include <chrono>
#include <optional>

namespace gta3xlwifi {

// Rate limit for reopening the boost controls after an open/write failure.
// The first attempt is always allowed; each failure doubles the wait (1 s .. 60 s).
// A success resets the wait. Uses its own clock alias so the header stays standalone.
class RetryBackoff {
  public:
    using TimePoint = std::chrono::steady_clock::time_point;
    using Millis = std::chrono::milliseconds;
    static constexpr Millis kMin{1000};
    static constexpr Millis kMax{60000};

    bool canAttempt(TimePoint now) const { return !mNext || now >= *mNext; }
    // Records a failure at `now` and returns the delay before the next attempt.
    Millis failure(TimePoint now) {
        ++mTotal;
        ++mConsecutive;
        const Millis delay = mDelay;
        mNext = now + delay;
        mDelay = std::min(mDelay * 2, kMax);
        return delay;
    }
    void success() {
        mConsecutive = 0;
        mDelay = kMin;
        mNext.reset();
    }
    unsigned total() const { return mTotal; }
    unsigned consecutive() const { return mConsecutive; }

  private:
    Millis mDelay = kMin;
    std::optional<TimePoint> mNext;
    unsigned mTotal = 0;
    unsigned mConsecutive = 0;
};

}  // namespace gta3xlwifi
