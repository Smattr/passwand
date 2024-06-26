// Note that we avoid OpenSSL’s RAND_bytes because it does not contain as much
// entropy as it claims (https://eprint.iacr.org/2016/367).

#include <assert.h>
#include <errno.h>
#include <passwand/passwand.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
#if defined(__GLIBC__) &&                                                      \
    (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
#include <sys/random.h>
#else
// Before Glibc 2.25 we do not have a syscall wrapper for getrandom().
#include <linux/random.h>
#include <sys/syscall.h>

static ssize_t getrandom(void *buf, size_t buflen, unsigned flags) {
  return (ssize_t)syscall(SYS_getrandom, buf, buflen, flags);
}
#endif
#endif
#endif

passwand_error_t passwand_random_bytes(void *buffer, uint8_t buffer_len) {

  assert(buffer != NULL);

#if defined(__APPLE__) || defined(__DragonFly__) || defined(__FreeBSD__) ||    \
    defined(__NetBSD__)

  arc4random_buf(buffer, buffer_len);
  return PW_OK;

#elif defined(__linux__) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)

  ssize_t r;
  do {
    r = getrandom(buffer, buffer_len, 0);
  } while (r < 0 && errno == EAGAIN);

  if (r < 0)
    return PW_IO;

  assert(r <= UINT8_MAX && (uint8_t)r == buffer_len &&
         "unexpected number of bytes from getrandom()");

  return PW_OK;

#else

#error no usable kernel API for generating random data

#endif
}
