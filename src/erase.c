#include <passwand/passwand.h>
#include <stddef.h>
#include <string.h>

/* Ideally, we would use memset_s for this task. However, it seems most C
 * standard libraries do not implement it :( Instead we need to rely on the
 * compiler not having enough visibility to optimise away the call to memset
 * below.
 */

#pragma GCC push_options
#pragma GCC optimize("no-builtin-memset")

/* A volatile pointer through which memset will be accessed, preventing the
 * compiler optimising its call. Idea borrowed from NetBSD.
 */
void *(*volatile memset_explicit)(void*, int, size_t) = memset;

int passwand_erase(char *s) {

    if (s == NULL)
        return 0;

    size_t len = strlen(s);

    memset_explicit(s, 0, len);
    __sync_synchronize();

    return 0;
}
#pragma GCC pop_options
