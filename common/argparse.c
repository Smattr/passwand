#include "argparse.h"
#include "getenv.h"
#include <assert.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

options_t options;

// default to use if --work-factor is not supplied
static const unsigned DEFAULT_WORK_FACTOR = 14;

// Overwrite command line arguments to conceal them from utils like `top`. This
// is not a good way to conceal this information from a concerted attacker, but
// useful for more lazy snooping tools that are not specifically targeting
// Passwand.
static void blank_arguments(int argc, char **argv) {
  for (size_t i = 0; i < (size_t)argc; i++) {
    size_t len = strlen(argv[i]);
    for (size_t j = 0; j < len; j++) {
      argv[i][j] = '\0';
    }
  }
}

int parse(int argc, char **argv) {

  options.db.work_factor = DEFAULT_WORK_FACTOR;
  options.jobs = 0; // == “number of CPUs”

  while (true) {
    struct option opts[] = {
        {"chain", required_argument, 0, 'c'},
        {"data", required_argument, 0, 'd'},
        {"jobs", required_argument, 0, 'j'},
        {"space", required_argument, 0, 's'},
        {"key", required_argument, 0, 'k'},
        {"value", required_argument, 0, 'v'},
        {"work-factor", required_argument, 0, 'N'},
        {0, 0, 0, 0},
    };

    int index;
    int c = getopt_long(argc, argv, "c:d:s:k:v:N:", opts, &index);

    if (c == -1)
      break;

    switch (c) {

#define HANDLE_ARG(field)                                                      \
  do {                                                                         \
    free(options.field);                                                       \
    options.field = strdup(optarg);                                            \
    if (options.field == NULL) {                                               \
      fprintf(stderr, "out of memory while processing arguments\n");           \
      return -1;                                                               \
    }                                                                          \
  } while (0)

    case 'c':
      ++options.chain_len;
      options.chain =
          realloc(options.chain, options.chain_len * sizeof(options.chain[0]));
      if (options.chain == NULL) {
        fprintf(stderr, "out of memory\n");
        return -1;
      }
      options.chain[options.chain_len - 1].path = NULL;
      options.chain[options.chain_len - 1].work_factor = DEFAULT_WORK_FACTOR;
      HANDLE_ARG(chain[options.chain_len - 1].path);
      break;

    case 'd':
      HANDLE_ARG(db.path);
      break;

    case 'j': {
      char *endptr;
      unsigned long jobs = strtoul(optarg, &endptr, 10);
      if (endptr == optarg || *endptr != '\0' || jobs == ULONG_MAX) {
        fprintf(stderr, "invalid argument to --jobs\n");
        return -1;
      }
      options.jobs = jobs;
      break;
    }

    case 's':
      HANDLE_ARG(space);
      break;

    case 'k':
      HANDLE_ARG(key);
      break;

    case 'v':
      HANDLE_ARG(value);
      break;

#undef HANDLE_ARG

    case 'N': {
      char *endptr;
      unsigned long wf = strtoul(optarg, &endptr, 10);
      if (endptr == optarg || *endptr != '\0' || wf < 10 || wf > 31) {
        fprintf(stderr, "invalid argument to --work-factor\n");
        return -1;
      }
      // should this apply to a chained database?
      if (options.chain_len > 0) {
        options.chain[options.chain_len - 1].work_factor = wf;
      } else {
        options.db.work_factor = wf;
      }
      break;
    }

    default:
      return -1;
    }
  }

  if (optind < argc) {
    fprintf(stderr, "unrecognised argument %s\n", argv[optind]);
    return -1;
  }

  if (options.db.path == NULL) {
    // setup default path
    char *home = getenv_("HOME");
    if (home == NULL)
      return -1;
    // check for overflow
    if (SIZE_MAX - strlen(home) < strlen("/.passwand.json"))
      return -1;
    if (SIZE_MAX - strlen(home) - strlen("/.passwand.json") < 1)
      return -1;
    char *path = malloc(strlen(home) + strlen("/.passwand.json") + 1);
    if (path == NULL)
      return -1;
    strcpy(path, home);
    strcat(path, "/.passwand.json");
    options.db.path = path;
  }

  // Try to resolve the path to its ultimate target if it is a symbolic link.
  // The purpose of this is so our caller can update the database by creating a
  // temporary file and renaming it to the target. Without resolving symlinks,
  // the temporary file may end up on a different partition to the target and
  // the rename will fail.
  for (;;) {
    char *target = malloc(PATH_MAX + 1);
    if (target == NULL)
      return -1;
    ssize_t r = readlink(options.db.path, target, PATH_MAX + 1);
    if (r == -1) {
      // if we fail for any reason, just bail out and let our caller deal with
      // having a symlink database
      free(target);
      break;
    }
    target[r] = '\0';
    free(options.db.path);
    options.db.path = target;
  }

  if (options.jobs == 0) { // automatic
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    assert(cpus >= 1);
    options.jobs = (unsigned long)cpus;
  }

  blank_arguments(argc, argv);

  return 0;
}
