#include "test.h"
#include <CUnit/CUnit.h>
#include <passwand/passwand.h>
#include <stdbool.h>
#include <string.h>

TEST("malloc: basic functionality") {

  const char buffer[] = "hello world";

  void *p;
  int err = passwand_secure_malloc(&p, 10);
  CU_ASSERT_EQUAL_FATAL(err, 0);
  memcpy(p, buffer, 10);

  void *q;
  err = passwand_secure_malloc(&q, 100);
  CU_ASSERT_EQUAL_FATAL(err, 0);
  memcpy(q, buffer, sizeof(buffer));

  // The two pointers should not overlap.
  CU_ASSERT_EQUAL_FATAL(p + 10 <= q || q + 100 <= p, true);

  passwand_secure_free(q, 100);

  // The memory should have been wiped.
  CU_ASSERT_NOT_EQUAL_FATAL(strncmp(q, buffer, sizeof(buffer)), 0);

  // The first block of memory should not have been touched.
  CU_ASSERT_EQUAL_FATAL(strncmp(p, buffer, 10), 0);

  passwand_secure_free(p, 10);
}

TEST("malloc: forever { malloc(x); free(x); }") {
  for (unsigned i = 0; i < 10000; i++) {
    void *p;
    int err = passwand_secure_malloc(&p, 128);
    CU_ASSERT_EQUAL_FATAL(err, 0);
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

  // Malloc 10000 pages or until we run out of space.
  node_t *n = NULL;
  for (unsigned i = 0; i < 10000; i++) {
    node_t *m;
    int err = passwand_secure_malloc((void **)&m, sizeof(*m));
    if (err != 0)
      break;
    m->next = n;
    n = m;
  }

  // We should have got at least one allocation done.
  CU_ASSERT_PTR_NOT_NULL_FATAL(n);

  // Now free everything we just malloced.
  while (n != NULL) {
    node_t *m = n->next;
    passwand_secure_free(n, sizeof(*n));
    n = m;
  }

  // Now we should be able to do at least one allocation.
  int err = passwand_secure_malloc((void **)&n, sizeof(*n));
  CU_ASSERT_EQUAL_FATAL(err, 0);
  passwand_secure_free(n, sizeof(*n));
}
