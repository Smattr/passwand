// implementation of the ../exe/gui.h API for the purposes of command line
// testing

#include "../gui/gui.h"
#include <assert.h>
#include <passwand/passwand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *get_text(const char *title __attribute__((unused)),
               const char *message __attribute__((unused)),
               const char *initial __attribute__((unused)), bool hidden) {

  static const size_t buffer_size = 4096;
  char *buffer = malloc(buffer_size);
  if (fgets(buffer, buffer_size, stdin) == NULL) {
    free(buffer);
    return NULL;
  }

  if (buffer[strlen(buffer) - 1] == '\n')
    buffer[strlen(buffer) - 1] = '\0';

  char *r;
  if (hidden) {
    r = passwand_secure_malloc(strlen(buffer) + 1);
    if (r != NULL)
      strcpy(r, buffer);
    free(buffer);
  } else {
    r = buffer;
  }

  return r;
}

const char *describe_input(void) { return "stdin"; }

int send_text(const char *text) {
  assert(text != NULL);
  printf("%s\n", text);
  return 0;
}

const char *describe_output(void) { return "stdout"; }

void flush_state(void) {
  fflush(stdout);
  fflush(stderr);
}

void show_error(const char *message) { fprintf(stderr, "%s\n", message); }

int gui_init(void) {
  // nothing required
  return 0;
}

void gui_deinit(void) { /* nothing required */ }
