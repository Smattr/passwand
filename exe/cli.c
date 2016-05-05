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
        discard_master(master); \
        fprintf(stderr, format "\n", ## args); \
        exit(EXIT_FAILURE); \
    } while (0)

typedef struct {
    char *master;
    size_t master_len;
} master_t;

static master_t *getpassword(const char *prompt) {

    static const size_t CHUNK = 128;

    char *m;
    if (passwand_secure_malloc((void**)&m, CHUNK) != 0)
        return NULL;
    size_t size = CHUNK;

    printf("%s", prompt == NULL ? "master password: " : prompt);
    fflush(stdout);

    struct termios old;
    if (tcgetattr(STDOUT_FILENO, &old) != 0) {
        passwand_secure_free(m, size);
        return NULL;
    }
    struct termios new = old;
    cfmakeraw(&new);
    if (tcsetattr(STDOUT_FILENO, 0, &new) != 0) {
        passwand_secure_free(m, size);
        return NULL;
    }

    unsigned index = 0;
    for (;;) {
        int c = getchar();

        if (c == EOF) {
            fflush(stdout);
            tcsetattr(STDOUT_FILENO, 0, &old);
            passwand_secure_free(m, size);
            return NULL;
        }

        if (c == '\n' || c == '\r' || c == '\f')
            break;

        m[index] = c;
        index++;
        if (index >= size) {
            char *n;
            if (passwand_secure_malloc((void**)&n, size + CHUNK) != 0) {
                fflush(stdout);
                tcsetattr(STDOUT_FILENO, 0, &old);
                passwand_secure_free(m, size);
                return NULL;
            }
            strncpy(n, m, size);
            passwand_secure_free(m, size);
            m = n;
            size += CHUNK;
        }
    }

    fflush(stdout);
    tcsetattr(STDOUT_FILENO, 0, &old);
    printf("\n");

    m[index] = '\0';

    master_t *master;
    if (passwand_secure_malloc((void**)&master, sizeof *master) != 0) {
        passwand_secure_free(m, size);
        return NULL;
    }
    master->master = m;
    master->master_len = size;

    return master;
}

static void discard_master(master_t *m) {
    if (m == NULL)
        return;
    passwand_secure_free(m->master, m->master_len);
    passwand_secure_free(m, sizeof *m);
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

static int get(const options_t *options, master_t *master, passwand_entry_t *entries,
        unsigned entry_len) {

    REQUIRED(space);
    REQUIRED(key);
    IGNORED(value);

    find_state_t st = {
        .options = options,
        .found = false,
    };
    for (unsigned i = 0; !st.found && i < entry_len; i++) {
        if (passwand_entry_do(master->master, &entries[i], get_body, &st) != PW_OK)
            DIE("failed to handle entry %u", i);
    }

    if (!st.found)
        DIE("not found");

    discard_master(master);
    return EXIT_SUCCESS;
}

typedef struct {
    bool found;
    unsigned index;
    const char *space;
    const char *key;
} set_state_t;

static void set_body(void *state, const char *space, const char *key,
        const char *value __attribute__((unused))) {

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

static int set(const options_t *options, master_t *master, passwand_entry_t *entries,
        unsigned entry_len) {

    REQUIRED(space);
    REQUIRED(key);
    REQUIRED(value);

    master_t *confirm = getpassword("confirm master password: ");
    if (confirm == NULL)
        DIE("out of memory");
    bool r = strcmp(master->master, confirm->master) == 0;
    discard_master(confirm);
    if (!r)
        DIE("passwords do not match");

    passwand_entry_t e;
    if (passwand_entry_new(&e, master->master, options->space, options->key, options->value,
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
        if (passwand_entry_do(master->master, &entries[i], set_body, &st) != PW_OK)
            DIE("failed to handle entry %u", i);
    }

    passwand_entry_t *new_entries = calloc(entry_len + (st.found ? 0 : 1), sizeof(passwand_entry_t));
    if (new_entries == NULL)
        DIE("out of memory");

    memcpy(new_entries, entries, sizeof(passwand_entry_t) * st.index);
    memcpy(new_entries + st.index, &e, sizeof(passwand_entry_t));
    if (st.found)
        memcpy(new_entries + st.index + 1, entries + st.index + 1,
            sizeof(passwand_entry_t) * (entry_len - st.index - 1));
    size_t new_entry_len = st.found ? entry_len : entry_len + 1;

    passwand_error_t err = passwand_export(options->data, new_entries, new_entry_len);
    if (err != PW_OK)
        DIE("failed to export entries: %s", passwand_error(err));

    discard_master(master);
    return EXIT_SUCCESS;
}

static int list(const options_t *options, master_t *master, passwand_entry_t *entries,
        unsigned entry_len) {

    IGNORED(space);
    IGNORED(key);
    IGNORED(value);

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
        passwand_error_t err = passwand_entry_do(master->master, &entries[i], print, NULL);
        if (err != PW_OK)
            DIE("failed to handle entry %u: %s", i, passwand_error(err));
    }

    discard_master(master);
    return EXIT_SUCCESS;
}

typedef struct {
    master_t *master;
    passwand_entry_t *entries;
    unsigned index;
    passwand_error_t err;
    int work_factor;
} change_master_state_t;

static void change_master_body(void *state, const char *space, const char *key,
        const char *value) {
    change_master_state_t *st = state;
    st->err = passwand_entry_new(&st->entries[st->index], st->master->master, space, key, value,
        st->work_factor);
    st->index++;
}

static int change_master(const options_t *options, master_t *master, passwand_entry_t *entries,
        unsigned entry_len) {

    IGNORED(space);
    IGNORED(key);
    IGNORED(value);

    master_t *new_master = getpassword("new master password: ");
    if (new_master == NULL)
        DIE("failed to read new password");

    master_t *confirm_new = getpassword("confirm new master password: ");
    if (confirm_new == NULL) {
        discard_master(new_master);
        DIE("failed to read confirmation of new password");
    }

    if (strcmp(new_master->master, confirm_new->master) != 0) {
        discard_master(confirm_new);
        discard_master(new_master);
        DIE("passwords do not match");
    }

    discard_master(confirm_new);

    passwand_entry_t *new_entries = calloc(entry_len, sizeof *new_entries);
    if (new_entries == NULL) {
        discard_master(new_master);
        DIE("out of memory");
    }

    change_master_state_t st = {
        .master = new_master,
        .entries = new_entries,
        .index = 0,
        .err = PW_OK,
        .work_factor = options->work_factor,
    };
    for (unsigned i = 0; i < entry_len; i++) {
        passwand_error_t err = passwand_entry_do(master->master, &entries[i], change_master_body,
            &st);
        if (err != PW_OK) {
            discard_master(new_master);
            DIE("failed to process entry %u: %s\n", i, passwand_error(err));
        }
        if (st.err != PW_OK) {
            discard_master(new_master);
            DIE("failed to process entry %u: %s\n", i, passwand_error(st.err));
        }
    }
    discard_master(new_master);

    passwand_error_t err = passwand_export(options->data, new_entries, entry_len);
    if (err != PW_OK)
        DIE("failed to export entries");

    discard_master(master);
    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {

    int (*action)(const options_t *options, master_t *master, passwand_entry_t *entries,
        unsigned entry_len);

    if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-?") == 0) {
        printf("usage: %s action options...\n", argv[0]);
        return EXIT_SUCCESS;
    }

    master_t *master = NULL;

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

    passwand_entry_t *entries;
    unsigned entry_len;
    passwand_error_t err = passwand_import(options.data, &entries, &entry_len);
    if (err != PW_OK)
        DIE("failed to load database: %s", passwand_error(err));

    for (unsigned i = 0; i < entry_len; i++)
        entries[i].work_factor = options.work_factor;

    master = getpassword(NULL);
    if (master == NULL)
        DIE("failed to read master password");

    return action(&options, master, entries, entry_len);
}
