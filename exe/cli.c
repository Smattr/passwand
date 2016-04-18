#include "argparse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int get(const options_t *options) {
    if (options->space == NULL) {
        fprintf(stderr, "missing required argument --space\n");
        return EXIT_FAILURE;
    } else if (options->key == NULL) {
        fprintf(stderr, "missing required argument --key\n");
        return EXIT_FAILURE;
    } else if (options->value != NULL) {
        fprintf(stderr, "irrelevant argument --value provided\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
    int (*action)(const options_t *options);

    if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-?") == 0) {
        printf("usage: %s action options...\n", argv[0]);
        return EXIT_SUCCESS;
    }

    if (strcmp(argv[1], "get") == 0) {
        action = get;
    } else {
        fprintf(stderr, "invalid action\n");
        return EXIT_FAILURE;
    }

    options_t options;
    if (parse(argc - 1, argv + 1, &options) != 0)
        return EXIT_FAILURE;

    return action(&options);
}
