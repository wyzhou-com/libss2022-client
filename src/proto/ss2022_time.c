#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "ss2022_internal.h"

static uint64_t seconds_from_clock(clockid_t id) {
    struct timespec ts;
    if (clock_gettime(id, &ts) != 0 || ts.tv_sec < (time_t)0) {
        return 0u;
    }
    return (uint64_t)ts.tv_sec;
}

uint64_t ss2022_now_seconds(void) {
#ifdef CLOCK_REALTIME_COARSE
    uint64_t now = seconds_from_clock(CLOCK_REALTIME_COARSE);
    if (now != 0u) {
        return now;
    }
#endif
    return seconds_from_clock(CLOCK_REALTIME);
}

uint64_t ss2022_now_milliseconds(void) {
    struct timespec ts;
#ifdef CLOCK_MONOTONIC_COARSE
    if (clock_gettime(CLOCK_MONOTONIC_COARSE, &ts) != 0)
#else
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
#endif
    {
        return ss2022_now_seconds() * 1000u;
    }
    if (ts.tv_sec < (time_t)0 || ts.tv_nsec < 0) {
        return 0u;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

int ss2022_check_timestamp(uint64_t timestamp) {
    uint64_t now = ss2022_now_seconds();
    uint64_t diff = (timestamp > now) ? (timestamp - now) : (now - timestamp);
    if (diff > (uint64_t)SS2022_TIMESTAMP_TOLERANCE_SECONDS) {
        return SS2022_ERR_STALE_TIMESTAMP;
    }
    return SS2022_OK;
}
