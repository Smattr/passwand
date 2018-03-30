/* This file implements a malloc-style allocator with the following goal:
 *
 *  - Confidentiality and integrity of the backing memory. Currently this means
 *    the backing memory is not pageable. It is trivial to snoop the contents
 *    of the swap file, meaning any memory paged to disk is no longer
 *    confidential. We also make some cursory attempts to suppress ptrace
 *    peeking.
 *
 * The following are explicit non-goals:
 *
 *  - Low latency. It is assumed that the caller is never performing secure
 *    allocation on a critical path.
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
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/prctl.h>
#endif

/* Basic no-init-required spinlock implementation. */
static atomic_long l;
static void lock(void) {
    long expected;
    do {
        expected = 0;
    } while (!atomic_compare_exchange_weak(&l, &expected, 1));
}
static void unlock(void) {
    long expected;
    do {
        expected = 1;
    } while (!atomic_compare_exchange_weak(&l, &expected, 0));
}

static void lock_release(void *p __attribute__((unused))) {
    unlock();
}
#define LOCK_UNTIL_RET() \
    lock(); \
    int _lock __attribute__((unused, cleanup(lock_release)));

/* Expected hardware page size. This is checked at runtime. */
#define EXPECTED_PAGE_SIZE 4096

/* We store the allocator's backing memory as a linked-list of "chunks," each of
 * `EXPECTED_PAGE_SIZE` bytes. The status of the bytes within each chunk is tracked per "block,"
 * where blocks are `sizeof(long long)`. Each chunk contains a bitmap of its blocks with 0
 * indicating a free block and 1 indicating an allocated block. A side-effect of this scheme is
 * that we can detect when a caller returns memory to us that we never allocated.
 *
 * The `last_index` member tracks the last index of the bitmap we examined. It is purely an
 * optimisation (to resume searches for new allocations where the last left off) and could be
 * removed to simplify the implementation.
 */
typedef struct chunk_ {
    void *base;
    uint8_t free[EXPECTED_PAGE_SIZE / sizeof(long long) / 8];
    unsigned last_index;
    struct chunk_ *next;
} chunk_t;

static bool read_bitmap(chunk_t *c, unsigned index) {
    assert(c != NULL);
    assert(index < sizeof(c->free) * 8);
    return c->free[index / 8] & (1 << (index % 8));
}

static void write_bitmap(chunk_t *c, unsigned index, bool value) {
    assert(c != NULL);
    assert(index < sizeof(c->free) * 8);
    if (value)
        c->free[index / 8] |= 1 << (index % 8);
    else
        c->free[index / 8] &= ~(1 << (index % 8));
}

static chunk_t *freelist;

/* This will only become set if the allocator detects inappropriate (potentially malicious) calls.
 */
static bool disabled;

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
    if (page == 0 || page != EXPECTED_PAGE_SIZE)
        return -1;

    assert(page % sizeof(long long) == 0);

    /* Allocate a new mlocked page. */
    if (posix_memalign(p, page, page) != 0)
        return -1;
    if (mlock(*p, page) != 0) {
        free(*p);
        return -1;
    }

    return 0;
}

/* The following logic prevents other processes attaching to us with PTRACE_ATTACH. This goes
 * someway towards preventing an attack whereby a colocated process peeks at the secure heap while
 * we're running. Note that this is not a fool proof method and leaves other avenues (e.g. /proc)
 * open by which this can be accomplished.
 */
static bool ptrace_disabled;
static int disable_ptrace(void) {
    int r = 0;
#if defined(__linux__)
    r = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    if (r == 0)
        ptrace_disabled = true;
#endif

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

    if (disabled)
        return -1;

    if (!ptrace_disabled)
        if (disable_ptrace() != 0)
            return -1;

    /* Don't allow allocations greater than a page. This avoids having to cope with allocations
     * that would span multiple chunks.
     */
    if (size > EXPECTED_PAGE_SIZE)
        return -1;

    for (chunk_t *n = freelist; n != NULL; n = n->next) {

retry:;
        unsigned first_index = n->last_index;

        while (n->last_index < sizeof(n->free) * 8) {

            /* Look for an unset bit. */
            while (n->last_index < sizeof(n->free) * 8 && read_bitmap(n, n->last_index))
                n->last_index++;

            /* Scan for `size` unset bits. */
            unsigned offset;
            for (offset = 0; offset * sizeof(long long) < size &&
                             n->last_index + offset < sizeof(n->free) * 8; offset++) {
                if (read_bitmap(n, n->last_index + offset))
                    break;
            }

            if (offset * sizeof(long long) == size) {
                /* We found enough contiguous free bits! */
                for (unsigned i = 0; i * sizeof(long long) < size; i++)
                    write_bitmap(n, n->last_index + i, true);
                *p = n->base + n->last_index * sizeof(long long);
                n->last_index += size / sizeof(long long);
                return 0;
            }

            /* Jump past the region we just scanned. */
            n->last_index += offset;
        }

        /* Reset the index for any future scans. */
        n->last_index = 0;

        if (first_index * sizeof(long long) >= size)
            /* There's entries at the front of the bitmap we haven't scanned that cover enough
             * memory to possibly fill this request.
             */
            goto retry;

    }

    /* Didn't find anything useful in the freelist. Acquire some more secure memory. */
    void *q;
    if (morecore(&q) != 0)
        return -1;

    /* Fill this allocation using the end of the memory just acquired. */
    chunk_t *c = calloc(1, sizeof(*c));
    if (c == NULL) {
        int r __attribute__((unused)) = munlock(q, EXPECTED_PAGE_SIZE);
        assert(r == 0 && "munlock unexpectedly failed");
        free(q);
        return -1;
    }
    c->base = q;
    c->next = freelist;
    freelist = c;
    for (unsigned index = (EXPECTED_PAGE_SIZE - size) / sizeof(long long);
            index < EXPECTED_PAGE_SIZE / sizeof(long long); index++)
        write_bitmap(c, index, true);
    *p = c->base + EXPECTED_PAGE_SIZE - size;

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

    LOCK_UNTIL_RET();

    if (disabled)
        return;

    /* Find the chunk this allocation came from. */
    for (chunk_t *c = freelist; c != NULL; c = c->next) {
        if (p >= c->base && p + size <= c->base + EXPECTED_PAGE_SIZE) {
            /* It came from this chunk. */
            for (unsigned index = (p - c->base) / sizeof(long long);
                    index * sizeof(long long) < size; index++) {
                assert(read_bitmap(c, index));
                if (!read_bitmap(c, index)) {
                    /* This memory was not in use. Double free? */
                    disabled = true;
                    return;
                }
                write_bitmap(c, index, false);
            }
            passwand_erase(p, size);
            return;
        }
    }

    /* If we reached here, the given blocks do not lie in the secure heap. */
    assert(!"free of non-heap memory");
    disabled = true;
}

void passwand_secure_heap_print(FILE *f) {
    for (chunk_t *c = freelist; c != NULL; c = c->next) {
        fprintf(f, "%p:\n", c->base);
        for (unsigned i = 0; i < EXPECTED_PAGE_SIZE / sizeof(long long); i++) {
            if (i % 64 == 0)
                fprintf(f, " ");
            fprintf(f, "%d", (int)read_bitmap(c, i));
            if (i % 64 == 63)
                fprintf(f, "\n");
        }
    }
}
