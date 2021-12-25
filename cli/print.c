#include "print.h"
#include <stdarg.h>
#include <stdio.h>

static void lock(void) {
  flockfile(stdout);
  flockfile(stderr);
}

static void unlock(void) {
  funlockfile(stderr);
  funlockfile(stdout);
}

void print(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  lock();
  (void)vprintf(fmt, ap);
  fflush(stdout);
  unlock();
  va_end(ap);
}

void eprint(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  lock();
  (void)vfprintf(stderr, fmt, ap);
  fflush(stderr);
  unlock();
  va_end(ap);
}
