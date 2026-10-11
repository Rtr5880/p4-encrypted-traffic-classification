#define _POSIX_C_SOURCE 200809L
/* One nonblocking datagram send attempt per prebuilt frame. No filtering,
 * busy waiting, deadline rebasing, priority changes, or send/sleep retries. */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#define ETC_MAX_PACKETS 500000U
#define ETC_MAX_DURATION_NS INT64_C(60000000000)
#define ETC_MIN_INTERVAL_NS INT64_C(100000)
#define ETC_MAX_INTERVAL_NS INT64_C(1000000000)

enum etc_sender_status {
    ETC_OK = 0, ETC_ARGUMENT = 1, ETC_FD = 2, ETC_CLOCK = 3,
    ETC_SLEEP = 4, ETC_CANCELLED = 5, ETC_WINDOW = 6,
    ETC_SEND = 7, ETC_PARTIAL_SEND = 8
};

struct etc_sender_result {
    int64_t scheduled_start_ns;
    int64_t send_window_end_ns;
    int64_t sent_count;
    int64_t attempted_count;
    int64_t error_code;
    int64_t error_errno;
    int64_t error_index;
    int64_t returned_bytes;
};

struct etc_cancel_flag { atomic_int requested; };

int etc_paced_sender_abi(void) { return 1; }
size_t etc_paced_sender_result_size(void) { return sizeof(struct etc_sender_result); }
void *etc_paced_sender_cancel_new(void) {
    struct etc_cancel_flag *flag = malloc(sizeof(*flag));
    if (flag != NULL) atomic_init(&flag->requested, 0);
    return flag;
}
void etc_paced_sender_cancel_request(void *opaque) {
    struct etc_cancel_flag *flag = opaque;
    if (flag != NULL) atomic_store_explicit(&flag->requested, 1, memory_order_release);
}
void etc_paced_sender_cancel_free(void *opaque) { free(opaque); }

static int cancelled(const struct etc_cancel_flag *flag) {
    return atomic_load_explicit(&flag->requested, memory_order_acquire) != 0;
}
static int read_monotonic(int64_t *value) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return errno;
    if (ts.tv_sec < 0 || ts.tv_sec > INT64_MAX / INT64_C(1000000000)) return EOVERFLOW;
    *value = (int64_t) ts.tv_sec * INT64_C(1000000000) + ts.tv_nsec;
    return 0;
}
static int sleep_absolute(int64_t deadline) {
    struct timespec ts;
    ts.tv_sec = (time_t) (deadline / INT64_C(1000000000));
    ts.tv_nsec = (long) (deadline % INT64_C(1000000000));
    return clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL);
}
static void fail(struct etc_sender_result *out, int code, int error, size_t index,
                 int64_t returned_bytes) {
    out->error_code = code;
    out->error_errno = error;
    out->error_index = (int64_t) index;
    out->returned_bytes = returned_bytes;
}

int etc_paced_sender_run(int fd, const unsigned char *blob, size_t blob_size,
                        const uint64_t *frame_offsets, const uint32_t *lengths,
                        const int64_t *deadlines, size_t count, int64_t duration_ns,
                        int64_t *starts, int64_t *finishes, void *cancel_opaque,
                        struct etc_sender_result *out) {
    size_t i;
    int error;
    int64_t now = 0, end;
    struct etc_cancel_flag *flag = cancel_opaque;
    if (out == NULL) return EINVAL;
    memset(out, 0, sizeof(*out));
    out->error_index = -1;
    out->returned_bytes = -1;
    if (blob == NULL || frame_offsets == NULL || lengths == NULL || deadlines == NULL ||
        starts == NULL || finishes == NULL || flag == NULL || count < 1 ||
        count > ETC_MAX_PACKETS || duration_ns <= 0 || duration_ns > ETC_MAX_DURATION_NS ||
        deadlines[0] != 0 || duration_ns / (int64_t) count < ETC_MIN_INTERVAL_NS ||
        duration_ns / (int64_t) count > ETC_MAX_INTERVAL_NS) {
        fail(out, ETC_ARGUMENT, EINVAL, 0, -1); return EINVAL;
    }
    for (i = 0; i < count; ++i) {
        if (lengths[i] < 60 || lengths[i] > 1514 || frame_offsets[i] > blob_size ||
            lengths[i] > blob_size - frame_offsets[i] || deadlines[i] < 0 ||
            deadlines[i] >= duration_ns ||
            (i > 0 && (deadlines[i] - deadlines[i-1] < ETC_MIN_INTERVAL_NS ||
                       deadlines[i] - deadlines[i-1] > ETC_MAX_INTERVAL_NS))) {
            fail(out, ETC_ARGUMENT, EINVAL, i, -1); return EINVAL;
        }
    }
    if (duration_ns - deadlines[count-1] > ETC_MAX_INTERVAL_NS) {
        fail(out, ETC_ARGUMENT, EINVAL, count-1, -1); return EINVAL;
    }
    error = fcntl(fd, F_GETFL);
    if (error < 0 || (error & O_NONBLOCK) == 0) {
        fail(out, ETC_FD, error < 0 ? errno : EINVAL, 0, -1); return 0;
    }
    if ((error = read_monotonic(&now)) != 0 || now > INT64_MAX - duration_ns) {
        fail(out, ETC_CLOCK, error != 0 ? error : EOVERFLOW, 0, -1); return 0;
    }
    out->scheduled_start_ns = now;
    end = now + duration_ns;
    for (i = 0; i < count; ++i) {
        ssize_t sent;
        int send_error;
        if (cancelled(flag)) { fail(out, ETC_CANCELLED, ECANCELED, i, -1); break; }
        error = sleep_absolute(out->scheduled_start_ns + deadlines[i]);
        if (error != 0) { fail(out, ETC_SLEEP, error, i, -1); break; }
        if (cancelled(flag)) { fail(out, ETC_CANCELLED, ECANCELED, i, -1); break; }
        error = read_monotonic(&now);
        if (error != 0) { fail(out, ETC_CLOCK, error, i, -1); break; }
        if (now >= end) { fail(out, ETC_WINDOW, ETIMEDOUT, i, -1); break; }
        starts[i] = now;
        sent = send(fd, blob + frame_offsets[i], lengths[i], MSG_DONTWAIT | MSG_NOSIGNAL);
        send_error = sent < 0 ? errno : 0;
        out->attempted_count = (int64_t) i + 1;
        error = read_monotonic(&finishes[i]);
        if (error != 0) { fail(out, ETC_CLOCK, error, i, sent); break; }
        if (sent < 0) { fail(out, ETC_SEND, send_error, i, sent); break; }
        if (sent != lengths[i]) { fail(out, ETC_PARTIAL_SEND, 0, i, sent); break; }
        out->sent_count = (int64_t) i + 1;
    }
    if (out->error_code == ETC_OK) {
        if (cancelled(flag)) fail(out, ETC_CANCELLED, ECANCELED, count, -1);
        else if ((error = sleep_absolute(end)) != 0) fail(out, ETC_SLEEP, error, count, -1);
        else if (cancelled(flag)) fail(out, ETC_CANCELLED, ECANCELED, count, -1);
    }
    error = read_monotonic(&out->send_window_end_ns);
    if (error != 0 && out->error_code == ETC_OK) fail(out, ETC_CLOCK, error, count, -1);
    return 0;
}
