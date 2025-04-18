#include "test.h"
#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

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

TEST("malloc: basic functionality") {

  const char buffer[] = "hello world";

  char *const p = passwand_secure_malloc(10);
  ASSERT_NOT_NULL(p);
  memcpy(p, buffer, 10);

  char *const q = passwand_secure_malloc(100);
  ASSERT_NOT_NULL(q);
  memcpy(q, buffer, sizeof(buffer));

  // the two pointers should not overlap
  ASSERT((uintptr_t)p + 10 <= (uintptr_t)q ||
         (uintptr_t)q + 100 <= (uintptr_t)p);

  passwand_secure_free(q, 100);

  // cheat slightly and allow access to this memory that we know the allocator
  // has still retained internally
  UNPOISON(q, 100);

  // the memory should have been wiped
  ASSERT_NE(strncmp(q, buffer, sizeof(buffer)), 0);

  POISON(q, 100);

  // the first block of memory should not have been touched
  ASSERT_EQ(strncmp(p, buffer, 10), 0);

  passwand_secure_free(p, 10);
}

TEST("malloc: forever { malloc(x); free(x); }") {
  for (unsigned i = 0; i < 10000; i++) {
    void *const p = passwand_secure_malloc(128);
    ASSERT_NOT_NULL(p);
    passwand_secure_free(p, 128);
  }
}

TEST("malloc: limit") {

  typedef struct node_ {
    union {
      unsigned char unused[128];
      struct node_ *next;
    };
  } node_t;

  // malloc 10000 pages or until we run out of space
  node_t *n = NULL;
  for (unsigned i = 0; i < 10000; i++) {
    node_t *const m = passwand_secure_malloc(sizeof(*m));
    if (m == NULL)
      break;
    m->next = n;
    n = m;
  }

  // we should have got at least one allocation done
  ASSERT_NOT_NULL(n);

  // now free everything we just malloced
  while (n != NULL) {
    node_t *m = n->next;
    passwand_secure_free(n, sizeof(*n));
    n = m;
  }

  // now we should be able to do at least one allocation
  n = passwand_secure_malloc(sizeof(*n));
  ASSERT_NOT_NULL(n);
  passwand_secure_free(n, sizeof(*n));
}
