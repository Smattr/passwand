#include <assert.h>
#include "print.h"
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void print(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r __attribute__((unused)) = pthread_mutex_lock(&mutex);
    assert(r == 0);
    (void)vprintf(fmt, ap);
    r = pthread_mutex_unlock(&mutex);
    assert(r == 0);
    va_end(ap);
}

void eprint(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r __attribute__((unused)) = pthread_mutex_lock(&mutex);
    assert(r == 0);
    (void)vfprintf(stderr, fmt, ap);
    r = pthread_mutex_unlock(&mutex);
    assert(r == 0);
    va_end(ap);
}
