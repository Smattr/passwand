#include "argparse.h"
#include <assert.h>
#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define DIE(format, args...) \
    do { \
        fprintf(stderr, format "\n", ## args); \
        exit(EXIT_FAILURE); \
    } while (0)

static int getpassword(char **master, size_t *len) {
    static const size_t CHUNK = 128;

    char *m;
    if (passwand_secure_malloc((void**)&m, CHUNK) != 0)
        return -1;
    size_t size = CHUNK;

    printf("master password: ");
    fflush(stdout);

    struct termios old;
    if (tcgetattr(STDOUT_FILENO, &old) != 0) {
        passwand_secure_free(m, size);
        return -1;
    }
    struct termios new = old;
    cfmakeraw(&new);

    unsigned index = 0;
    int c;
    for (;;) {
        c = getchar();

        if (c == EOF) {
            tcsetattr(STDOUT_FILENO, 0, &old);
            passwand_secure_free(m, size);
            return -1;
        }

        if (c == '\r' || c == '\r' || c == '\f')
            break;

        m[index] = c;
        index++;
        if (index >= size) {
            char *n;
            if (passwand_secure_malloc((void**)&n, size + CHUNK) != 0) {
                tcsetattr(STDOUT_FILENO, 0, &old);
                passwand_secure_free(m, size);
                return -1;
            }
            strncpy(n, m, size);
            passwand_secure_free(m, size);
            m = n;
            size += CHUNK;
        }
    }

    m[index] = '\0';
    *master = m;
    *len = size;
    return 0;
}

typedef struct {
    const options_t *options;
    bool found;
} find_state_t;

static void find(void *state, const char *space, const char *key,
        const char *value) {
    assert(state != NULL);
    assert(space != NULL);
    assert(key != NULL);
    assert(value != NULL);

    find_state_t *st = state;
    if (strcmp(st->options->space, space) == 0 &&
            strcmp(st->options->key, key) == 0) {
        puts(value);
        st->found = true;
    }
}

static int get(const options_t *options, passwand_entry_t *entries, unsigned entry_len) {
    if (options->space == NULL)
        DIE("missing required argument --space");
    if (options->key == NULL)
        DIE("missing required argument --key");
    if (options->value != NULL)
        DIE("irrelevant argument --value provided");

    char *master;
    size_t size;
    if (getpassword(&master, &size) != 0)
        DIE("failed to read master password");

    find_state_t st = {
        .options = options,
        .found = false,
    };
    for (unsigned i = 0; !st.found && i < entry_len; i++) {
        if (passwand_entry_do(master, &entries[i], find, &st) != PW_OK) {
            passwand_secure_free(master, size);
            DIE("failed to handle entry %u", i);
        }
    }
    passwand_secure_free(master, size);

    if (!st.found)
        DIE("not found");

    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
    int (*action)(const options_t *options, passwand_entry_t *entries, unsigned entry_len);

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

    if (options.data == NULL) {
        /* Setup default path. */
        char *home = secure_getenv("HOME");
        if (home == NULL)
            DIE("can't determine home directory");
        char *path = malloc(strlen(home) + strlen("/.passwand.json") + 1);
        if (path == NULL)
            DIE("out of memory while constructing default path");
        strcpy(path, home);
        strcat(path, "/.passwand.json");
        options.data = path;
    }

    passwand_entry_t *entries;
    unsigned entry_len;
    if (passwand_import(options.data, &entries, &entry_len) != PW_OK)
        DIE("failed to load database");

    return action(&options, entries, entry_len);
}
