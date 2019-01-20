#include "../common/argparse.h"
#include <assert.h>
#include "check.h"
#include "cli.h"
#include "print.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>

static atomic_bool found_weak;

static int initialize(const master_t *master __attribute__((unused)),
  passwand_entry_t *entries __attribute__((unused)), size_t entry_len __attribute__((unused))) {
    return 0;
}

static bool in_dictionary(const char *s) {

    /* open the system dictionary */
    FILE *f = fopen("/usr/share/dict/words", "r");
    if (f == NULL) {
        /* failed; perhaps the file doesn't exist */
        return false;
    }

    bool result = false;

    char *line = NULL;
    size_t size = 0;
    for (;;) {
        ssize_t r = getline(&line, &size, f);
        if (r < 0) {
            /* done or error */
            break;
        }

        if (r > 0) {
            /* delete the trailing \n */
            if (line[strlen(line) - 1] == '\n')
                line[strlen(line) - 1] = '\0';

            if (strcmp(s, line) == 0) {
                result = true;
                break;
            }
        }
    }

    free(line);
    fclose(f);

    return result;
}

static void loop_body(const char *space, const char *key, const char *value) {
    assert(space != NULL);
    assert(key != NULL);
    assert(value != NULL);

    /* if we were given a space, check that this entry is within it */
    if (options.space != NULL && strcmp(options.space, space) != 0)
        return;

    /* if we were given a key, check that this entry matches it */
    if (options.key != NULL && strcmp(options.key, key) != 0)
        return;

    if (in_dictionary(value)) {
        print("%s/%s: weak password (dictionary word)\n", space, key);
        found_weak = true;
    } else {
        print("%s/%s: OK\n", space, key);
    }
}

static int finalize(void) {
    return found_weak ? -1 : 0;
}

const command_t check = {
    .need_space = OPTIONAL,
    .need_key = OPTIONAL,
    .need_value = DISALLOWED,
    .access = LOCK_SH,
    .initialize = initialize,
    .loop_body = loop_body,
    .finalize = finalize,
};
