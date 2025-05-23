// This file implements a malloc-style allocator with the following goal:
//
//  - Confidentiality and integrity of the backing memory. Currently this means
//    the backing memory is not pageable. It is trivial to snoop the contents
//    of the swap file, meaning any memory paged to disk is no longer
//    confidential. We also make some cursory attempts to suppress ptrace
//    peeking.
//
// The following are explicit non-goals:
//
//  - Low latency. It is assumed that the caller is never performing secure
//    allocation on a critical path.
//  - Large allocations. The allocator cannot provide memory greater than a
//    page. An implicit assumption is that all your allocations are small (<256
//    bytes). You can allocate more than this, but performance and availability
//    will degrade. In an unprivileged environment, a process’ total secure
//    allocation will be limited to RLIMIT_MEMLOCK.
//  - Resource balancing. The backing memory for this allocator can only ever
//    grow. This can effectively DoS other process activities (mprotect, mlock)
//    if the caller does not pay attention to the high watermark of their
//    secure allocation.

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

#ifdef __has_feature
#if __has_feature(address_sanitizer)
#include <sanitizer/asan_interface.h>
#define POISON(addr, size) ASAN_POISON_MEMORY_REGION((addr), (size))
#define UNPOISON(addr, size) ASAN_UNPOISON_MEMORY_REGION((addr), (size))
#endif
#endif

#ifndef POISON
#define POISON(addr, size)                                                     \
  do {                                                                         \
  } while (0)
#endif
#ifndef UNPOISON
#define UNPOISON(addr, size)                                                   \
  do {                                                                         \
  } while (0)
#endif

// basic no-init-required spinlock implementation
static atomic_flag l = ATOMIC_FLAG_INIT;
static void lock(void) {
  while (atomic_flag_test_and_set_explicit(&l, memory_order_acq_rel))
    ;
  atomic_thread_fence(memory_order_acq_rel);
}
static void unlock(void) {
  assert(atomic_flag_test_and_set(&l));
  atomic_thread_fence(memory_order_acq_rel);
  atomic_flag_clear_explicit(&l, memory_order_release);
}

// Expected hardware page size. This is checked at runtime.
#define EXPECTED_PAGE_SIZE 4096

// We store the allocator’s backing memory as a linked-list of “chunks,” each of
// `EXPECTED_PAGE_SIZE` bytes. The status of the bytes within each chunk is
// tracked per “block,” where blocks are `sizeof(long long)`. Each chunk
// contains a bitmap of its blocks with 0 indicating a free block and 1
// indicating an allocated block. A side-effect of this scheme is that we can
// detect when a caller returns memory to us that we never allocated.
//
// The `last_index` member tracks the last index of the bitmap we examined. It
// is purely an optimisation (to resume searches for new allocations where the
// last left off) and could be removed to simplify the implementation.
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

// this will only become set if the allocator detects inappropriate (potentially
// malicious) calls
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

static void *morecore(void) {
  size_t page = pagesize();
  if (page < EXPECTED_PAGE_SIZE)
    return NULL;

  // allocate a new mlocked page
  void *const p = aligned_alloc(page, page);
  if (p == NULL)
    return NULL;
  if (mlock(p, EXPECTED_PAGE_SIZE) != 0) {
    free(p);
    return NULL;
  }

  // poison the new pool, marking it initially unusable
  POISON(p, EXPECTED_PAGE_SIZE);

  return p;
}

// The following logic prevents other processes attaching to us with
// PTRACE_ATTACH. This goes someway towards preventing an attack whereby a
// colocated process peeks at the secure heap while we are running. Note that
// this is not a fool proof method and leaves other avenues (e.g. /proc) open by
// which this can be accomplished.
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

void *passwand_secure_malloc(size_t size) {

  if (size == 0)
    return NULL;

  if (SIZE_MAX - size < sizeof(long long))
    return NULL;

  const size_t rounded = round_size(size);

  // Do not allow allocations greater than a page. This avoids having to cope
  // with allocations that would span multiple chunks.
  if (rounded > EXPECTED_PAGE_SIZE)
    return NULL;

  lock();

  if (disabled) {
    unlock();
    return NULL;
  }

  if (!ptrace_disabled) {
    if (disable_ptrace() != 0) {
      unlock();
      return NULL;
    }
  }

  for (chunk_t *n = freelist; n != NULL; n = n->next) {

  retry:;
    unsigned first_index = n->last_index;

    while (n->last_index < sizeof(n->free) * 8) {

      // look for an unset bit
      while (n->last_index < sizeof(n->free) * 8 &&
             read_bitmap(n, n->last_index))
        n->last_index++;

      // scan for `rounded` unset bits
      unsigned offset;
      for (offset = 0; offset * sizeof(long long) < rounded &&
                       n->last_index + offset < sizeof(n->free) * 8;
           offset++) {
        if (read_bitmap(n, n->last_index + offset))
          break;
      }

      if (offset * sizeof(long long) == rounded) {
        // we found enough contiguous free bits!
        for (unsigned i = 0; i * sizeof(long long) < rounded; i++)
          write_bitmap(n, n->last_index + i, true);
        void *const p = (char *)n->base + n->last_index * sizeof(long long);
        n->last_index += rounded / sizeof(long long);
        unlock();

        // mark the memory we are handing out (only the prefix `size` not the
        // full `rounded` allocation) usable
        UNPOISON(p, size);

        return p;
      }

      // jump past the region we just scanned
      n->last_index += offset;
    }

    // reset the index for any future scans
    n->last_index = 0;

    if (first_index * sizeof(long long) >= rounded)
      // there are entries at the front of the bitmap we have not scanned that
      // cover enough memory to possibly fill this request
      goto retry;
  }

  // Did not find anything useful in the freelist. Acquire some more secure
  // memory.
  void *const q = morecore();
  if (q == NULL) {
    unlock();
    return NULL;
  }

  // fill this allocation using the end of the memory just acquired
  chunk_t *c = calloc(1, sizeof(*c));
  if (c == NULL) {
    int r __attribute__((unused)) = munlock(q, EXPECTED_PAGE_SIZE);
    assert(r == 0 && "munlock unexpectedly failed");
    free(q);
    unlock();
    return NULL;
  }
  c->base = q;
  c->next = freelist;
  freelist = c;
  for (unsigned index = (EXPECTED_PAGE_SIZE - rounded) / sizeof(long long);
       index < EXPECTED_PAGE_SIZE / sizeof(long long); index++)
    write_bitmap(c, index, true);
  void *const p = (char *)c->base + EXPECTED_PAGE_SIZE - rounded;

  unlock();

  // mark the memory we are handing out (only the prefix `size` not the full
  // `rounded` allocation) usable
  UNPOISON(p, size);

  return p;
}

void passwand_secure_free(void *p, size_t size) {

  assert((uintptr_t)p % sizeof(long long) == 0);

  if (size == 0)
    return;

  assert(SIZE_MAX - size >= sizeof(long long));
  if (SIZE_MAX - size < sizeof(long long))
    return;

  const size_t rounded = round_size(size);

  const uintptr_t p_start = (uintptr_t)p;
  const uintptr_t p_end = p_start + rounded;

  lock();

  if (disabled) {
    unlock();
    return;
  }

  // is the range we were given invalid?
  if (p_end < p_start) {
    disabled = true;
    unlock();
    return;
  }

  // find the chunk this allocation came from
  for (chunk_t *c = freelist; c != NULL; c = c->next) {
    const uintptr_t base_start = (uintptr_t)c->base;
    const uintptr_t base_end = base_start + EXPECTED_PAGE_SIZE;
    if (p_start >= base_start && p_end <= base_end) {
      // it came from this chunk
      unsigned offset = (p_start - base_start) / sizeof(long long);
      for (unsigned index = 0; index * sizeof(long long) < rounded; index++) {
        assert(read_bitmap(c, index + offset));
        if (!read_bitmap(c, index + offset)) {
          // This memory was not in use. Double free?
          disabled = true;
          unlock();
          return;
        }
        write_bitmap(c, index + offset, false);
      }
      passwand_erase(p, size);
      POISON(p, rounded);
      unlock();
      return;
    }
  }

  // if we reached here, the given blocks do not lie in the secure heap
  assert(!"free of non-heap memory");
  disabled = true;
  unlock();
}

int passwand_secure_malloc_reset(void) {

  lock();

  if (disabled) {
    unlock();
    return -1;
  }

  // scan all chunks for occupied blocks
  for (chunk_t *c = freelist; c != NULL; c = c->next) {
    for (unsigned i = 0; i < sizeof(c->free) * 8; i++) {
      if (read_bitmap(c, i)) {
        // we found an in-use block
        unlock();
        return -1;
      }
    }
  }

  // now we can free all chunks
  for (chunk_t *c = freelist; c != NULL;) {
    int r __attribute__((unused)) = munlock(c->base, EXPECTED_PAGE_SIZE);
    assert(r == 0 && "munlock unexpectedly failed");
    free(c->base);
    chunk_t *next = c->next;
    free(c);
    c = next;
  }

  // reset the freelist head
  freelist = NULL;

  unlock();
  return 0;
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
