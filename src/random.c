/* The following implements a fairly heavyweight source of random bytes. In
 * particular, it can easily block if you request too many. This was judged
 * fine for Passwand because it's primarily used as an interactive tool and so
 * we don't need to worry about latency or liveness.
 *
 * Note that we avoid OpenSSL's RAND_bytes because it does not contain as much
 * entropy as it claims (https://eprint.iacr.org/2016/367). Using /dev/random
 * directly is really overkill to address this, but as we need relatively few
 * random bytes for this application and blocking is acceptable, there seemed
 * no reason not to.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include "internal.h"
#include <limits.h>
#include <passwand/passwand.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/** Open /dev/random for reading
 *
 * This function contains a fair bit of paranoia based on advice from 
 * http://insanecoding.blogspot.com.au/2014/05/a-good-idea-with-bad-usage-devurandom.html.
 * It's almost certainly overkill, but there seemed no reason not to do it.
 *
 * @return An open file descriptor or -1 on failure.
 */
static int open_dev_random(void) {

retry:;
    int fd = open("/dev/random", O_RDONLY|O_NOFOLLOW);
    if (fd == -1) {
        if (errno == EINTR)
            goto retry;
        return -1;
    }

    /* Check the thing we opened is actually a character device. */
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISCHR(st.st_mode)) {
        close(fd);
        return -1;
    }

    /* Check the device we opened is actually /dev/random. */
    static const int dev_random_major = 1;
    static const int dev_random_minor = 8;
    dev_t dev_random = makedev(dev_random_major, dev_random_minor);
    if (st.st_rdev != dev_random) {
        close(fd);
        return -1;
    }

    return fd;
}

/** Read from the given file descriptor
 *
 * @param fd Descriptor to read from
 * @param buf Target for read bytes
 * @param count Number of bytes to read
 * @return Number of bytes read
 */
static ssize_t read_bytes(int fd, void *buf, size_t count) {

    assert(fd >= 0);
    assert(buf != NULL);
    assert(count <= SSIZE_MAX);

    ssize_t r = 0;
    while (count > 0) {
        ssize_t l = read(fd, buf, count);
        if (l == -1) {
            if (errno != EAGAIN && errno != EINTR)
                return r;
        } else {
            assert(l >= 0 && l <= (ssize_t)count);
            r += l;
            count -= (size_t)l;
            buf += l;
        }
    }

    return r;
}

passwand_error_t random_bytes(void *buffer, size_t buffer_len) {

    assert(buffer != NULL);
    assert(buffer_len <= 512 && "exceeding blocking read limits of /dev/random");

    if (buffer_len == 0)
        return PW_OK;

    int fd = open_dev_random();
    if (fd == -1)
        return PW_IO;

    ssize_t r = read_bytes(fd, buffer, buffer_len);
    close(fd);
    return r == (ssize_t)buffer_len ? PW_OK : PW_IO;
}
