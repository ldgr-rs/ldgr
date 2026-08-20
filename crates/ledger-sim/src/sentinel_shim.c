/*
 * Process-belt interposition shim for the determinism leak sentinel.
 *
 * Load this shared library through LD_PRELOAD. Each interposed ambient API
 * appends one line named after the function to the file in
 * LEDGER_SENTINEL_LOG, then either serves a virtualized deterministic value
 * or calls the real libc function resolved by dlsym.
 *
 * Virtualization is host-side and opt-in through environment:
 * - LEDGER_VIRTUAL_TICKS_PATH: path to a file containing current virtual
 *   time as decimal microseconds. When set, clock_gettime, gettimeofday and
 *   time read the file on each call and convert micros to the requested
 *   structure. The file is small; the shim uses only open/read/close so it
 *   never re-enters an interposed symbol.
 * - LEDGER_VIRTUAL_SEED_HEX: 64 hex chars that seed a deterministic entropy
 *   stream. When set, getrandom and getentropy fill the caller buffer from
 *   that stream instead of the OS. The stream is SplitMix64 seeded from the
 *   first 8 bytes (16 hex chars) of the seed in big-endian order, advancing
 *   state by 0x9e3779b97f4a7c15 per 8-byte block. This is deterministic across
 *   runs with the same seed and needs no external library.
 *
 * When the virtual env vars are absent the shim is pure log-and-passthrough.
 * Logging still happens when LEDGER_SENTINEL_LOG is set, even in virtual
 * mode, so the sentinel retains its leak-reporting role.
 *
 * The shim never calls any interposed function to do its own work. It uses
 * only open, read, write, close, getenv, and strlen.
 *
 * clock_gettime, gettimeofday, and time are vDSO-resident on glibc. Calls
 * that go through the PLT are interposed here, so the vDSO fast path is not
 * reached from interposed code; the dlsym-resolved libc function behind the
 * shim serves the read, still inside the vDSO where the kernel allows it.
 * Only code that bypasses the PLT entirely (a direct __vdso_clock_gettime
 * call, or an inlined copy of the vDSO sequence) escapes the shim; that
 * residual is what the seccomp denylist and
 * the runtime belt exist to catch as far as possible.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static ssize_t (*real_getrandom)(void *, size_t, unsigned int) = NULL;
static int (*real_getentropy)(void *, size_t) = NULL;
static int (*real_clock_gettime)(clockid_t, struct timespec *) = NULL;
static int (*real_gettimeofday)(struct timeval *, void *) = NULL;
static time_t (*real_time)(time_t *) = NULL;

/* Virtualization state, initialized once. */
static pthread_once_t virtual_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t virtual_entropy_mutex = PTHREAD_MUTEX_INITIALIZER;
static const char *virtual_ticks_path = NULL;
static const char *virtual_seed_hex = NULL;
static int virtual_time_enabled = 0;
static int virtual_entropy_enabled = 0;
static uint64_t virtual_prng_state = 0;

static int hex_val(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int parse_seed_hex(const char *hex, uint64_t *out) {
    uint64_t v = 0;
    int i;
    for (i = 0; i < 16; i++) {
        int nib = hex_val(hex[i]);
        if (nib < 0) {
            return 0;
        }
        v = (v << 4) | (uint64_t)nib;
    }
    *out = v;
    return 1;
}

static uint64_t splitmix64_next(uint64_t *state) {
    uint64_t z = (*state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static void virtual_init(void) {
    const char *ticks = getenv("LEDGER_VIRTUAL_TICKS_PATH");
    if (ticks != NULL && ticks[0] != '\0') {
        virtual_ticks_path = ticks;
        virtual_time_enabled = 1;
    }
    const char *seed = getenv("LEDGER_VIRTUAL_SEED_HEX");
    if (seed != NULL && seed[0] != '\0') {
        size_t len = strlen(seed);
        int hex_ok = 1;
        size_t check_len = len < 64 ? len : 64;
        size_t i;
        for (i = 0; i < check_len; i++) {
            if (hex_val(seed[i]) < 0) {
                hex_ok = 0;
                break;
            }
        }
        if (hex_ok && len >= 16) {
            uint64_t state = 0;
            if (parse_seed_hex(seed, &state)) {
                virtual_seed_hex = seed;
                virtual_prng_state = state;
                virtual_entropy_enabled = 1;
            }
        }
    }
}

static int read_virtual_micros(uint64_t *out) {
    char buf[64];
    char *p;
    uint64_t val;
    int digits;
    ssize_t n;
    int fd;
    if (!virtual_time_enabled || virtual_ticks_path == NULL) {
        return 0;
    }
    fd = open(virtual_ticks_path, O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    n = read(fd, buf, sizeof(buf) - 1);
    (void)close(fd);
    if (n <= 0) {
        return 0;
    }
    buf[n] = '\0';
    p = buf;
    while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') {
        p++;
    }
    if (*p == '\0') {
        return 0;
    }
    val = 0;
    digits = 0;
    while (*p >= '0' && *p <= '9') {
        val = val * 10 + (uint64_t)(*p - '0');
        p++;
        digits++;
    }
    if (digits == 0) {
        return 0;
    }
    *out = val;
    return 1;
}

static void fill_virtual_random(void *buf, size_t buflen) {
    uint8_t *dst = (uint8_t *)buf;
    size_t off = 0;
    if (buflen == 0 || dst == NULL) {
        return;
    }
    (void)pthread_mutex_lock(&virtual_entropy_mutex);
    while (off < buflen) {
        uint64_t rnd = splitmix64_next(&virtual_prng_state);
        size_t chunk = buflen - off;
        size_t i;
        if (chunk > 8) {
            chunk = 8;
        }
        for (i = 0; i < chunk; i++) {
            dst[off + i] = (uint8_t)(rnd >> (i * 8));
        }
        off += chunk;
    }
    (void)pthread_mutex_unlock(&virtual_entropy_mutex);
}

/* Append one newline-terminated line to the sentinel log file. */
static void log_call(const char *name) {
    const char *path = getenv("LEDGER_SENTINEL_LOG");
    int fd;
    size_t len;
    size_t written;
    if (path == NULL) {
        return;
    }
    fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        return;
    }
    len = strlen(name);
    written = 0;
    while (written < len) {
        ssize_t n = write(fd, name + written, len - written);
        if (n <= 0) {
            break;
        }
        written += (size_t)n;
    }
    if (write(fd, "\n", 1) < 0) {
        /* The line is best effort; never surface an error to the caller. */
    }
    (void)close(fd);
}

static void resolve_symbols(void) {
    real_getrandom = (ssize_t (*)(void *, size_t, unsigned int))dlsym(
        RTLD_NEXT, "getrandom");
    real_getentropy = (int (*)(void *, size_t))dlsym(RTLD_NEXT, "getentropy");
    real_clock_gettime = (int (*)(clockid_t, struct timespec *))dlsym(
        RTLD_NEXT, "clock_gettime");
    real_gettimeofday = (int (*)(struct timeval *, void *))dlsym(
        RTLD_NEXT, "gettimeofday");
    real_time = (time_t (*)(time_t *))dlsym(RTLD_NEXT, "time");
}

__attribute__((constructor))
static void sentinel_shim_init(void) {
    resolve_symbols();
}

ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) {
    log_call("getrandom");
    (void)pthread_once(&virtual_once, virtual_init);
    if (virtual_entropy_enabled) {
        if (buflen == 0) {
            return 0;
        }
        if (buf != NULL) {
            fill_virtual_random(buf, buflen);
            return (ssize_t)buflen;
        }
    }
    if (real_getrandom != NULL) {
        return real_getrandom(buf, buflen, flags);
    }
    errno = ENOSYS;
    return -1;
}

int getentropy(void *buf, size_t buflen) {
    log_call("getentropy");
    (void)pthread_once(&virtual_once, virtual_init);
    if (virtual_entropy_enabled) {
        if (buflen == 0) {
            return 0;
        }
        if (buf != NULL) {
            fill_virtual_random(buf, buflen);
            return 0;
        }
    }
    if (real_getentropy != NULL) {
        return real_getentropy(buf, buflen);
    }
    errno = ENOSYS;
    return -1;
}

int clock_gettime(clockid_t clk_id, struct timespec *tp) {
    uint64_t micros;
    (void)clk_id;
    log_call("clock_gettime");
    (void)pthread_once(&virtual_once, virtual_init);
    if (virtual_time_enabled && read_virtual_micros(&micros)) {
        if (tp != NULL) {
            tp->tv_sec = (time_t)(micros / 1000000ULL);
            tp->tv_nsec = (long)((micros % 1000000ULL) * 1000ULL);
        }
        return 0;
    }
    if (real_clock_gettime != NULL) {
        return real_clock_gettime(clk_id, tp);
    }
    errno = ENOSYS;
    return -1;
}

int gettimeofday(struct timeval *tv, void *tz) {
    uint64_t micros;
    log_call("gettimeofday");
    (void)pthread_once(&virtual_once, virtual_init);
    if (virtual_time_enabled && read_virtual_micros(&micros)) {
        if (tv != NULL) {
            tv->tv_sec = (time_t)(micros / 1000000ULL);
            tv->tv_usec = (suseconds_t)(micros % 1000000ULL);
        }
        (void)tz;
        return 0;
    }
    if (real_gettimeofday != NULL) {
        return real_gettimeofday(tv, tz);
    }
    errno = ENOSYS;
    return -1;
}

time_t time(time_t *tloc) {
    uint64_t micros;
    time_t sec;
    log_call("time");
    (void)pthread_once(&virtual_once, virtual_init);
    if (virtual_time_enabled && read_virtual_micros(&micros)) {
        sec = (time_t)(micros / 1000000ULL);
        if (tloc != NULL) {
            *tloc = sec;
        }
        return sec;
    }
    if (real_time != NULL) {
        return real_time(tloc);
    }
    errno = ENOSYS;
    return (time_t)-1;
}
