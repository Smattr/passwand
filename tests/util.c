#include "util.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

int run(const char *command, char **output) {
  assert(command != NULL);
  assert(output != NULL);

  FILE *p = popen(command, "r");
  if (p == NULL)
    return -1;

  *output = NULL;
  size_t buffer_len;
  FILE *b = open_memstream(output, &buffer_len);
  if (b == NULL) {
    pclose(p);
    return -1;
  }

  char window[1024];
  size_t read;
  while ((read = fread(window, 1, sizeof(window), p)) != 0) {
    assert(read <= sizeof(window));
    size_t written = fwrite(window, 1, read, b);
    if (read != written) {
      /* out of memory */
      fclose(b);
      free(*output);
      pclose(p);
      return -1;
    }
  }

  if (ferror(p)) {
    fclose(b);
    free(*output);
    pclose(p);
    return -1;
  }

  fclose(b);
  return pclose(p);
}
