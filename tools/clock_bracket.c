#define _POSIX_C_SOURCE 200809L

/* Three sequential reads. This does not make the bracket atomic. */
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifndef __linux__
#error "clock_bracket requires Linux"
#endif

_Static_assert(sizeof(long) == 8 && LONG_MAX == INT64_MAX,
               "clock_bracket requires a 64-bit Linux long");
_Static_assert(sizeof(long long) == 8 && LLONG_MAX == INT64_MAX,
               "clock_bracket requires a 64-bit long long");
_Static_assert(sizeof(time_t) == 8 && (time_t)-1 < (time_t)0,
               "clock_bracket requires signed 64-bit time_t");
_Static_assert(sizeof(struct timespec) == 16 &&
               sizeof(((struct timespec *)0)->tv_sec) == 8 &&
               sizeof(((struct timespec *)0)->tv_nsec) == 8 &&
               offsetof(struct timespec, tv_nsec) == 8,
               "clock_bracket requires the Linux 64-bit timespec layout");

struct etc_clock_bracket {
    int64_t monotonic_before_ns;
    int64_t realtime_ns;
    int64_t monotonic_after_ns;
};

_Static_assert(sizeof(struct etc_clock_bracket) == 24,
               "clock_bracket ABI must occupy exactly 24 bytes");

int etc_clock_bracket_abi(void) {
    return 1;
}

size_t etc_clock_bracket_size(void) {
    return sizeof(struct etc_clock_bracket);
}

static int timespec_ns(const struct timespec *value, int64_t *result) {
    const int64_t billion = INT64_C(1000000000);
    const int64_t seconds = (int64_t)value->tv_sec;
    const int64_t nanos = (int64_t)value->tv_nsec;
    const int64_t maximum_seconds = INT64_MAX / billion;
    const int64_t minimum_seconds = INT64_MIN / billion;

    if (nanos < 0 || nanos >= billion) {
        return EOVERFLOW;
    }
    if (seconds > maximum_seconds ||
        (seconds == maximum_seconds && nanos > INT64_MAX % billion) ||
        seconds < minimum_seconds - 1 ||
        (seconds == minimum_seconds - 1 &&
         nanos < billion + INT64_MIN % billion)) {
        return EOVERFLOW;
    }
    /* The shifted expression also handles INT64_MIN without overflow. */
    *result = seconds < 0 ? (seconds + 1) * billion + (nanos - billion)
                         : seconds * billion + nanos;
    return 0;
}

int etc_read_clock_bracket(struct etc_clock_bracket *output) {
    struct timespec before;
    struct timespec realtime;
    struct timespec after;

    if (output == NULL) {
        return EINVAL;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &before) != 0) {
        return errno != 0 ? errno : EIO;
    }
    if (clock_gettime(CLOCK_REALTIME, &realtime) != 0) {
        return errno != 0 ? errno : EIO;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &after) != 0) {
        return errno != 0 ? errno : EIO;
    }

    /* No conversion or output construction occurs between the clock reads. */
    struct etc_clock_bracket converted;
    int error = timespec_ns(&before, &converted.monotonic_before_ns);
    if (error != 0) {
        return error;
    }
    error = timespec_ns(&realtime, &converted.realtime_ns);
    if (error != 0) {
        return error;
    }
    error = timespec_ns(&after, &converted.monotonic_after_ns);
    if (error != 0) {
        return error;
    }
    *output = converted;
    return 0;
}
