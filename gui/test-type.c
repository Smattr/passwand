/// utility for manually experimenting with `send_text`

#include "gui.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {

  assert(supported_lower(' ') || supported_upper(' '));

  for (int i = 1; i < argc; ++i) {
    for (const char *j = argv[i]; *j != '\0'; ++j) {
      if (!supported_lower(*j) && !supported_upper(*j)) {
        fprintf(stderr, "unsupported character '%c' in input\n", *j);
        return EXIT_FAILURE;
      }
    }
  }

  for (int i = 1; i < argc; ++i) {

    if (i > 1) {
      if (send_text(" ") < 0) {
        fprintf(stderr, "failed to send \" \"\n");
        return EXIT_FAILURE;
      }
    }

    if (send_text(argv[i]) < 0) {
      fprintf(stderr, "failed to send \"%s\"\n", argv[i]);
      return EXIT_FAILURE;
    }
  }

  return EXIT_SUCCESS;
}
