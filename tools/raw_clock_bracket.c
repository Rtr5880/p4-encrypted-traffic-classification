#define _GNU_SOURCE
#include <stdint.h>
#include <time.h>
#include <errno.h>

/* Read only. Keep all five reads inside one native call, not Python/GIL gaps.
 * These sequential reads remain preemptible and are never retried/filtered. */
static int64_t as_ns(struct timespec value) {
    return (int64_t)value.tv_sec * INT64_C(1000000000) + value.tv_nsec;
}

int raw_clock_abi_version(void) { return 1; }

int read_raw_clock_bracket(int64_t *out) {
    struct timespec rb, mb, rt, ma, ra;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &rb) ||
        clock_gettime(CLOCK_MONOTONIC, &mb) ||
        clock_gettime(CLOCK_REALTIME, &rt) ||
        clock_gettime(CLOCK_MONOTONIC, &ma) ||
        clock_gettime(CLOCK_MONOTONIC_RAW, &ra)) return errno;
    out[0] = as_ns(rb); out[1] = as_ns(mb); out[2] = as_ns(rt);
    out[3] = as_ns(ma); out[4] = as_ns(ra);
    return 0;
}
