// SPDX-License-Identifier: Apache-2.0
#include "RetryBackoff.h"
#include <cassert>

using gta3xlwifi::RetryBackoff;
using Millis = RetryBackoff::Millis;

int main() {
    const RetryBackoff::TimePoint t0{};
    RetryBackoff retry;
    // First attempt is always allowed.
    assert(retry.canAttempt(t0));
    assert(retry.total() == 0 && retry.consecutive() == 0);

    // Failures double the wait from 1 s up to the 60 s cap.
    const long expected[] = {1000, 2000, 4000, 8000, 16000, 32000, 60000, 60000};
    RetryBackoff::TimePoint now = t0;
    for (long ms : expected) {
        assert(retry.canAttempt(now));
        const Millis delay = retry.failure(now);
        assert(delay.count() == ms);
        assert(!retry.canAttempt(now));
        assert(!retry.canAttempt(now + delay - Millis(1)));
        assert(retry.canAttempt(now + delay));
        now += delay;
    }
    assert(retry.total() == 8 && retry.consecutive() == 8);

    // Success allows an immediate attempt and restarts at 1 s; total is kept.
    retry.success();
    assert(retry.canAttempt(now));
    assert(retry.consecutive() == 0 && retry.total() == 8);
    assert(retry.failure(now).count() == 1000);
    assert(retry.total() == 9 && retry.consecutive() == 1);
    return 0;
}
