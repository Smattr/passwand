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

typedef struct {
    char *master;
    size_t master_len;
} master_t;

static int getpassword(const char *prompt, master_t *master) {

    static const size_t CHUNK = 128;

    char *m;
    if (passwand_secure_malloc((void**)&m, CHUNK) != 0)
        return -1;
    size_t size = CHUNK;

    printf("%s", prompt == NULL ? "master password: " : prompt);
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
    master->master = m;
    master->master_len = size;
    return 0;
}

typedef struct {
    const options_t *options;
    bool found;
} find_state_t;

static void get_body(void *state, const char *space, const char *key, const char *value) {

    assert(state != NULL);
    assert(space != NULL);
    assert(key != NULL);
    assert(value != NULL);

    find_state_t *st = state;
    if (strcmp(st->options->space, space) == 0 && strcmp(st->options->key, key) == 0) {
        puts(value);
        st->found = true;
    }
}

#define REQUIRED(field) \
    do { \
        if (options->field == NULL) { \
            DIE("missing required argument --" #field); \
        } \
    } while (0)
#define IGNORED(field) \
    do { \
        if (options->field != NULL) { \
            DIE("irrelevant argument --" #field); \
        } \
    } while (0)

static int get(const options_t *options, passwand_entry_t *entries, unsigned entry_len) {

    REQUIRED(space);
    REQUIRED(key);
    IGNORED(value);

    master_t master;
    if (getpassword(NULL, &master) != 0)
        DIE("failed to read master password");

    find_state_t st = {
        .options = options,
        .found = false,
    };
    for (unsigned i = 0; !st.found && i < entry_len; i++) {
        if (passwand_entry_do(master.master, &entries[i], get_body, &st) != PW_OK) {
            passwand_secure_free(master.master, master.master_len);
            DIE("failed to handle entry %u", i);
        }
    }
    passwand_secure_free(master.master, master.master_len);

    if (!st.found)
        DIE("not found");

    return EXIT_SUCCESS;
}

typedef struct {
    bool found;
    unsigned index;
    const char *space;
    const char *key;
} set_state_t;

static void set_body(void *state, const char *space, const char *key, const char *value) {

    assert(state != NULL);
    assert(space != NULL);
    assert(key != NULL);
    assert(value != NULL);

    set_state_t *st = state;
    if (strcmp(st->space, space) == 0 && strcmp(st->key, key) == 0) {
        /* This entry matches the one we just set. Mark it. */
        st->found = true;
    } else {
        st->index++;
    }
}

static int set(const options_t *options, passwand_entry_t *entries, unsigned entry_len) {

    REQUIRED(space);
    REQUIRED(key);
    REQUIRED(value);

    master_t master;
    if (getpassword(NULL, &master) != 0)
        DIE("failed to read master password");

    passwand_entry_t e;
    if (passwand_entry_new(&e, master.master, options->space, options->key, options->value,
            options->work_factor) != PW_OK)
        DIE("failed to create new entry");

    /* Figure out if the entry we've just created collides with (and overwrites) an existing one.
     */
    set_state_t st = {
        .found = false,
        .index = 0,
        .space = options->space,
        .key = options->key,
    };
    for (unsigned i = 0; !st.found && i < entry_len; i++) {
        if (passwand_entry_do(master.master, &entries[i], set_body, &st) != PW_OK) {
            passwand_secure_free(master.master, master.master_len);
            DIE("failed to handle entry %u", i);
        }
    }
    passwand_secure_free(master.master, master.master_len);

    passwand_entry_t *new_entries = calloc(entry_len + (st.found ? 0 : 1), sizeof(passwand_entry_t));
    if (new_entries == NULL)
        DIE("out of memory");

    memcpy(new_entries, entries, sizeof(passwand_entry_t) * st.index);
    if (st.found)
        memcpy(new_entries + st.index, entries + st.index + 1,
            sizeof(passwand_entry_t) * (entry_len - st.index - 1));
    size_t new_entry_len = st.found ? entry_len : entry_len + 1;

    if (passwand_export(options->data, new_entries, new_entry_len) != PW_OK)
        DIE("failed to export entries");

    return EXIT_SUCCESS;
}

static int list(const options_t *options, passwand_entry_t *entries, unsigned entry_len) {

    IGNORED(space);
    IGNORED(key);
    IGNORED(value);

    master_t master;
    if (getpassword(NULL, &master) != 0)
        DIE("failed to read master password");

    /* Note that this nested function does not induce a trampoline because it does not modify local
     * state.
     */
    void print(void *state __attribute__((unused)), const char *space, const char *key,
            const char *value __attribute__((unused))) {
        assert(space != NULL);
        assert(key != NULL);
        printf("%s/%s\n", space, key);
    }

    for (unsigned i = 0; i < entry_len; i++) {
        if (passwand_entry_do(master.master, &entries[i], print, NULL) != PW_OK) {
            passwand_secure_free(master.master, master.master_len);
            DIE("failed to handle entry %u", i);
        }
    }
    passwand_secure_free(master.master, master.master_len);

    return EXIT_SUCCESS;
}

static int change_master(const options_t *options, passwand_entry_t *entries, unsigned entry_len) {

    IGNORED(space);
    IGNORED(key);
    IGNORED(value);

    return EXIT_FAILURE;
}

int main(int argc, char **argv) {

    int (*action)(const options_t *options, passwand_entry_t *entries, unsigned entry_len);

    if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-?") == 0) {
        printf("usage: %s action options...\n", argv[0]);
        return EXIT_SUCCESS;
    }

    if (strcmp(argv[1], "get") == 0)
        action = get;
    else if (strcmp(argv[1], "set") == 0)
        action = set;
    else if (strcmp(argv[1], "list") == 0)
        action = list;
    else if (strcmp(argv[1], "change-master") == 0)
        action = change_master;
    else
        DIE("invalid action");

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
