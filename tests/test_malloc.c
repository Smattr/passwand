#include "test.h"
#include <passwand/passwand.h>
#include <stdbool.h>
#include <string.h>

TEST("malloc: basic functionality") {

  const char buffer[] = "hello world";

  char *p;
  int err = passwand_secure_malloc((void **)&p, 10);
  ASSERT_EQ(err, 0);
  memcpy(p, buffer, 10);

  char *q;
  err = passwand_secure_malloc((void **)&q, 100);
  ASSERT_EQ(err, 0);
  memcpy(q, buffer, sizeof(buffer));

  // the two pointers should not overlap
  ASSERT(p + 10 <= q || q + 100 <= p);

  passwand_secure_free(q, 100);

  // the memory should have been wiped
  ASSERT_NE(strncmp(q, buffer, sizeof(buffer)), 0);

  // the first block of memory should not have been touched
  ASSERT_EQ(strncmp(p, buffer, 10), 0);

  passwand_secure_free(p, 10);
}

TEST("malloc: forever { malloc(x); free(x); }") {
  for (unsigned i = 0; i < 10000; i++) {
    void *p;
    int err = passwand_secure_malloc(&p, 128);
    ASSERT_EQ(err, 0);
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
    node_t *m;
    int err = passwand_secure_malloc((void **)&m, sizeof(*m));
    if (err != 0)
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
  int err = passwand_secure_malloc((void **)&n, sizeof(*n));
  ASSERT_EQ(err, 0);
  passwand_secure_free(n, sizeof(*n));
}
