#include "test.h"
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

static void my_unlink(void *arg) {
  assert(arg != NULL);
  (void)unlink(arg);
}

char *mkpath(void) {

  // find where we should be creating temporary files
  const char *tmp = getenv("TMPDIR");
  if (tmp == NULL)
    tmp = "/tmp";

  // construct a temporary path template
  char *path = aprintf("%s/tmp.XXXXXX", tmp);

  // create a temporary file
  const int fd = mkostemp(path, O_CLOEXEC);
  ASSERT_NE(fd, -1);

  (void)close(fd);

  // allocate a new cleanup action
  cleanup_t *c = calloc(1, sizeof(*c));
  if (c == NULL)
    (void)unlink(path);
  ASSERT_NOT_NULL(c);

  // set it up to delete the path we just constructed
  c->function = my_unlink;
  c->arg = path;

  // register it
  c->next = cleanups;
  cleanups = c;

  return path;
}
