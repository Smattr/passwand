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
#include <stddef.h>
#include <stdint.h>
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

typedef struct node_ {
    size_t size;
    struct node_ *next;
} node_t __attribute__((aligned(__alignof__(long long))));

static node_t *freelist;

static void prepend(void *p, size_t size) {

    assert(p != NULL);
    assert(size >= sizeof(node_t));
    assert((uintptr_t)p % __alignof__(node_t) == 0);

    node_t *n = p;
    n->size = size;
    n->next = freelist;
    freelist = n;
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

    assert(page % __alignof__(node_t) == 0);

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
    if (size < sizeof (node_t))
        size = sizeof(node_t);
    if (size % __alignof__(node_t) == 0)
        return size;
    return size + (__alignof__(node_t) - size % __alignof__(node_t));
}

int passwand_secure_malloc(void **p, size_t size) {

    assert(p != NULL);

    if (size == 0) {
        *p = NULL;
        return 0;
    }

    size = round_size(size);

    LOCK_UNTIL_RET();

    if (!ptrace_disabled)
        if (disable_ptrace() != 0)
            return -1;

    size_t page = pagesize();
    if (page == 0)
        return -1;
    if (size >= page)
        return -1;

    for (node_t **n = &freelist; *n != NULL; n = &(*n)->next) {
        if ((*n)->size >= size + sizeof(node_t)) {
            /* Found a node we can truncate to fill this allocation. */
            (*n)->size -= size;
            *p = (void*)(*n) + (*n)->size;
            return 0;
        } else if ((*n)->size == size) {
            /* Found a node we can remove to fill this allocation. */
            *p = *n;
            *n = (*n)->next;
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
    assert(size + sizeof(node_t) <= page);
    *p = q + page - size;
    prepend(q, page - size);

    return 0;
}

void passwand_secure_free(void *p, size_t size) {

    assert((uintptr_t)p % __alignof__(node_t) == 0);

    if (size == 0)
        return;

    size = round_size(size);

    passwand_erase(p, size);

    LOCK_UNTIL_RET();

    /* Look for a chunk this is a adjacent to in order to just concatenate it if possible. */
    for (node_t **n = &freelist; *n != NULL; n = &(*n)->next) {
        if ((uintptr_t)(*n) + (*n)->size == (uintptr_t)p) {
            /* Returned memory lies after this chunk. */
            (*n)->size += size;
            return;
        } else if ((uintptr_t)p + size == (uintptr_t)(*n)) {
            /* Returned memory lies before this chunk. */
            node_t *m = p;
            assert(size >= sizeof(node_t) && "accidental overlapping reads and writes");
            m->size = (*n)->size + size;
            m->next = (*n)->next;
            *n = m;
            return;
        }
    }

    /* Failed to find an adjacent chunk. Just prepend it to the freelist. */
    prepend(p, size);
}
