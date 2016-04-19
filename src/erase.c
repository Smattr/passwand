#include <passwand/passwand.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Ideally, we would use memset_s for this task. However, it seems most C standard libraries do not
 * implement it :( Instead we need to rely on the compiler not having enough visibility to optimise
 * away the call to memset below.
 */

#pragma GCC push_options
#pragma GCC optimize("no-builtin-memset")

/* A volatile pointer through which memset will be accessed, preventing the compiler optimising its
 * call. Idea borrowed from NetBSD.
 */
void *(*volatile memset_explicit)(void*, int, size_t) = memset;

passwand_error_t passwand_erase(uint8_t *s, size_t len) {

    if (s == NULL)
        return PW_OK;

    memset_explicit(s, 0, len);
    __sync_synchronize();

    return PW_OK;
}
#pragma GCC pop_options
