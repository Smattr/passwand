/* This file implements a malloc-style allocator with the following goal:
 *
 *  - Confidentiality and integrity of the backing memory. Currently this means
 *    the backing memory is not pageable. It is trivial to snoop the contents
 *    of the swap file, meaning any memory paged to disk is no longer
 *    confidential.
 *
 * The following are explicit non-goals:
 *
 *  - Low latency. It is assumed that the caller is never performing secure
 *    allocation on a critical path.
 *  - Availability. A non-trivial allocation pattern can easily cause
 *    irreversible internal fragmentation in the allocator's freelist. It is
 *    assumed that a small, linear number of allocations are performed.
 *  - Large allocations. The allocator cannot provide memory greater than a
 *    page. An implicit assumption is that all your allocations are small (<256
 *    bytes). You can allocate more than this, but performance and availability
 *    will degrade. In an unprivileged environment, a process' total secure
 *    allocation will be limited to RLIMIT_MEMLOCK.
 *  - Resource balancing. The backing memory for this allocator can only ever
 *    grow. This can effectively DoS other process activities (mprotect, mlock)
 *    if the caller does not pay attention to the high watermark of their
 *    secure allocation.
 */

#include <assert.h>
#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

/* Basic no-init-required spinlock implementation. */
static long l;
static void lock(void) {
    long expected;
    do {
        expected = 0;
    } while (!__atomic_compare_exchange_n(&l, &expected, 1, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
}
static void unlock(void) {
    long expected;
    do {
        expected = 1;
    } while (!__atomic_compare_exchange_n(&l, &expected, 0, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
}

static void lock_release(void *p __attribute__((unused))) {
    unlock();
}
#define LOCK_UNTIL_RET() \
    lock(); \
    int _lock __attribute__((unused, cleanup(lock_release)));

typedef struct chunk_ {
    void *base;
    size_t size;
    struct chunk_ *next;
} chunk_t;

static chunk_t *freelist;

static int prepend(void *p, size_t size) {

    /* Allocate heap memory to store the chunk. Note that it is fine to store the free list metadata
     * in insecure memory as this information can be learned from insecure pointers already.
     */
    chunk_t *c = malloc(sizeof *c);
    if (c == NULL)
        return -1;

    c->base = p;
    c->size = size;
    c->next = freelist;
    freelist = c;

    return 0;
}

static size_t pagesize(void) {
    static long size;
    if (size == 0) {
        size = sysconf(_SC_PAGESIZE);
        if (size == -1)
            size = 0;
    }
    return size;
}

static int morecore(void **p) {
    assert(p != NULL);

    size_t page = pagesize();
    if (page == 0)
        return -1;

    assert(page % sizeof(long long) == 0);

    /* Allocate a new mlocked page. */
    *p = mmap(NULL, page, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_LOCKED, -1, 0);
    if (*p == MAP_FAILED)
        return -1;

    return 0;
}

/* The following logic prevents other processes attaching to us with PTRACE_ATTACH. This goes
 * someway towards preventing an attack whereby a colocated process peeks at the secure heap while
 * we're running. Note that this is not a fool proof method and leaves other avenues (e.g. /proc)
 * open by which this can be accomplished.
 */
static bool ptrace_disabled;
static int disable_ptrace(void) {
    int r = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    if (r == 0)
        ptrace_disabled = true;
    return r;
}

static size_t round_size(size_t size) {
    if (size % sizeof(long long) == 0)
        return size;
    return size + (sizeof(long long) - size % sizeof(long long));
}

int passwand_secure_malloc(void **p, size_t size) {

    assert(p != NULL);

    if (size == 0) {
        *p = NULL;
        return 0;
    }

    if (SIZE_MAX - size < sizeof(long long))
        return -1;

    size = round_size(size);

    LOCK_UNTIL_RET();

    if (!ptrace_disabled)
        if (disable_ptrace() != 0)
            return -1;

    size_t page = pagesize();
    if (page == 0)
        return -1;
    if (size > page)
        return -1;

    for (chunk_t **n = &freelist; *n != NULL; n = &(*n)->next) {
        if ((*n)->size == size) {
            /* Found a node we can remove to fill this allocation. */
            *p = (*n)->base;
            chunk_t *m = *n;
            *n = (*n)->next;
            free(m);
            return 0;
        } else if ((*n)->size > size) {
            /* Found a node we can truncate to fill this allocation. */
            (*n)->size -= size;
            *p = (*n)->base + (*n)->size;
            return 0;
        }
    }

    /* Didn't find anything useful in the freelist. Acquire some more secure memory. */
    void *q;
    if (morecore(&q) != 0)
        return -1;

    /* Fill this allocation using the end of the memory just acquired, the prepend the remainder to
     * the freelist.
     */
    if (size == page) {
        *p = q;
    } else {
        if (prepend(q, page - size) != 0) {
            munmap(q, page);
            return -1;
        }
        *p = q + page - size;
    }

    return 0;
}

void passwand_secure_free(void *p, size_t size) {

    assert((uintptr_t)p % sizeof(long long) == 0);

    if (size == 0)
        return;

    assert(SIZE_MAX - size >= sizeof(long long));
    if (SIZE_MAX - size < sizeof(long long))
        return;

    size = round_size(size);

    passwand_erase(p, size);

    LOCK_UNTIL_RET();

    /* Look for a chunk this is a adjacent to in order to just concatenate it if possible. */
    for (chunk_t **n = &freelist; *n != NULL; n = &(*n)->next) {
        if ((uintptr_t)(*n)->base + (*n)->size == (uintptr_t)p) {
            /* Returned memory lies after this chunk. */
            (*n)->size += size;
            return;
        } else if ((uintptr_t)p + size == (uintptr_t)(*n)->base) {
            /* Returned memory lies before this chunk. */
            (*n)->base = p;
            (*n)->size += size;
            return;
        }
    }

    /* Failed to find an adjacent chunk. Just prepend it to the freelist. */
    prepend(p, size);
}
