#include <assert.h>
#include <errno.h>
#include <passwand/passwand.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

enum { INITIAL_BUFFER_DEFAULT = 128 /* bytes */ };

int passwand_secure_read(void **p, size_t *size, size_t *size_read, int fd, size_t max) {

    assert(p != NULL);
    assert(size != NULL);
    assert(fd >= 0);

    char *buffer = NULL;
    size_t buffer_offset = 0;
    size_t buffer_size = 0;

    while (max > 0) {

        if (buffer == NULL || buffer_size - buffer_offset == 0) {

            /* Allocate a new buffer double the size of the old. */
            void *new_buffer;
            size_t new_size = buffer_size == 0 ? INITIAL_BUFFER_DEFAULT : buffer_size * 2;
            if (new_size - buffer_offset > max)
                new_size = buffer_offset + max;
            if (passwand_secure_malloc(&new_buffer, new_size) != 0)
                goto fail;

            /* Replace the old buffer. */
            memcpy(new_buffer, buffer, buffer_offset);
            passwand_secure_free(buffer, buffer_size);
            buffer = new_buffer;
            buffer_size = new_size;

        }

        assert(buffer != NULL);
        assert(buffer_size - buffer_offset > 0);

        size_t to_read = buffer_size - buffer_offset;
        if (to_read > max)
            to_read = max;

        ssize_t r = read(fd, buffer + buffer_offset, to_read);
        if (r == -1) {
            if (errno != EINTR)
                goto fail;
        } else if (r == 0) { // EOF
            break;
        } else {
            assert((size_t)r <= max);
            buffer_offset += (size_t)r;
            max -= (size_t)r;
        }
    }

    *p = buffer;
    *size_read = buffer_offset;
    *size = buffer_size;

    return 0;

fail:
    passwand_secure_free(buffer, buffer_size);
    return -1;
}
