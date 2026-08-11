/*
 * Process-belt interposition shim for the determinism leak sentinel.
 *
 * Load this shared library through LD_PRELOAD. Each interposed ambient API
 * appends one line named after the function to the file in
 * LEDGER_SENTINEL_LOG, then calls the real libc function resolved by dlsym.
 *
 * The shim never calls any interposed function to do its own work. It uses
 * only open, write, close, getenv, and strlen.
 *
 * clock_gettime, gettimeofday, and time are vDSO-resident on glibc. Calls
 * that go through the PLT are interposed here, so the vDSO fast path is not
 * reached from interposed code; the dlsym-resolved libc function behind the
 * shim serves the read, still inside the vDSO where the kernel allows it.
 * Only code that bypasses the PLT entirely (a direct __vdso_clock_gettime
 * call, or an inlined copy of the vDSO sequence) escapes the shim; that
 * residual is documented in 03-lld 2.7 and is what the seccomp denylist and
 * the runtime belt exist to catch as far as possible.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
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

/* Append one newline-terminated line to the sentinel log file. */
static void log_call(const char *name) {
    const char *path = getenv("LEDGER_SENTINEL_LOG");
    if (path == NULL) {
        return;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        return;
    }
    size_t len = strlen(name);
    size_t written = 0;
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
    if (real_getrandom != NULL) {
        return real_getrandom(buf, buflen, flags);
    }
    errno = ENOSYS;
    return -1;
}

int getentropy(void *buf, size_t buflen) {
    log_call("getentropy");
    if (real_getentropy != NULL) {
        return real_getentropy(buf, buflen);
    }
    errno = ENOSYS;
    return -1;
}

int clock_gettime(clockid_t clk_id, struct timespec *tp) {
    log_call("clock_gettime");
    if (real_clock_gettime != NULL) {
        return real_clock_gettime(clk_id, tp);
    }
    errno = ENOSYS;
    return -1;
}

int gettimeofday(struct timeval *tv, void *tz) {
    log_call("gettimeofday");
    if (real_gettimeofday != NULL) {
        return real_gettimeofday(tv, tz);
    }
    errno = ENOSYS;
    return -1;
}

time_t time(time_t *tloc) {
    log_call("time");
    if (real_time != NULL) {
        return real_time(tloc);
    }
    errno = ENOSYS;
    return (time_t)-1;
}
