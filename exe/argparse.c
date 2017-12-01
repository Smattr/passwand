#include "argparse.h"
#include <assert.h>
#include "getenv.h"
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int parse(int argc, char **argv, options_t *options) {

    assert(options != NULL);

    memset(options, 0, sizeof *options);
    options->work_factor = 14;
    options->jobs = 0; // == "number of CPUs"

    while (true) {
        struct option opts[] = {
            {"data", required_argument, 0, 'd'},
            {"jobs", required_argument, 0, 'j'},
            {"space", required_argument, 0, 's'},
            {"key", required_argument, 0, 'k'},
            {"value", required_argument, 0, 'v'},
            {"work-factor", required_argument, 0, 'N'},
            {0, 0, 0, 0},
        };

        int index;
        int c = getopt_long(argc, argv, "d:s:k:v:N:", opts, &index);

        if (c == -1)
            break;

        switch (c) {

#define HANDLE_ARG(field) \
    do { \
        if (options->field != NULL) { \
            free(options->field); \
        } \
        options->field = strdup(optarg); \
        if (options->field == NULL) { \
            fprintf(stderr, "out of memory while processing arguments\n"); \
            return -1; \
        } \
    } while (0)

            case 'd':
                HANDLE_ARG(data);
                break;

            case 'j': {
                char *endptr;
                unsigned long jobs = strtoul(optarg, &endptr, 10);
                if (endptr == optarg || *endptr != '\0' || jobs == ULONG_MAX) {
                    fprintf(stderr, "invalid argument to --jobs\n");
                    return -1;
                }
                options->jobs = jobs;
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
                if (endptr == optarg || *endptr != '\0' || wf == ULONG_MAX) {
                    fprintf(stderr, "invalid argument to --work-factor\n");
                    return -1;
                }
                options->work_factor = wf;
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

    if (options->data == NULL) {
        /* Setup default path. */
        char *home = getenv_("HOME");
        if (home == NULL)
            return -1;
        /* Check for overflow. */
        if (SIZE_MAX - strlen(home) < strlen("/.passwand.json"))
            return -1;
        if (SIZE_MAX - strlen(home) - strlen("/.passwand.json") < 1)
            return -1;
        char *path = malloc(strlen(home) + strlen("/.passwand.json") + 1);
        if (path == NULL)
            return -1;
        strcpy(path, home);
        strcat(path, "/.passwand.json");
        options->data = path;
    }

    return 0;
}
