#include "argparse.h"
#include <assert.h>
#include <limits.h>
#include <passwand/passwand.h>
#include <pthread.h>
#include <stdatomic.h>
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

    char *m;
    if (passwand_secure_malloc((void**)&m, BUFSIZ) != 0)
        return NULL;
    size_t size = BUFSIZ;

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

    size_t index = 0;
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
            if (passwand_secure_malloc((void**)&n, size + BUFSIZ) != 0) {
                fflush(stdout);
                tcsetattr(STDOUT_FILENO, 0, &old);
                passwand_secure_free(m, size);
                return NULL;
            }
            strncpy(n, m, size);
            passwand_secure_free(m, size);
            m = n;
            size += BUFSIZ;
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

static int get(const options_t *options, master_t *master, passwand_entry_t *entries,
        size_t entry_len) {

    find_state_t st = {
        .options = options,
        .found = false,
    };
    for (size_t i = 0; !st.found && i < entry_len; i++) {
        if (passwand_entry_do(master->master, &entries[i], get_body, &st) != PW_OK)
            DIE("failed to handle entry %zu", i);
    }

    if (!st.found)
        DIE("not found");

    discard_master(master);
    return EXIT_SUCCESS;
}

typedef struct {
    bool found;
    size_t index;
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
        size_t entry_len) {

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
    for (size_t i = 0; !st.found && i < entry_len; i++) {
        if (passwand_entry_do(master->master, &entries[i], set_body, &st) != PW_OK)
            DIE("failed to handle entry %zu", i);
    }

    if (!st.found && entry_len == SIZE_MAX)
        DIE("maximum number of entries exceeded");

    passwand_entry_t *new_entries = calloc(entry_len + (st.found ? 0 : 1), sizeof(passwand_entry_t));
    if (new_entries == NULL)
        DIE("out of memory");

    /* Insert the new or updated entry at the start of the list, as we assume
     * we'll be looking it up in the near future.
     */
    size_t count_before = st.found ? st.index : entry_len;
    size_t count_after = st.found ? entry_len - st.index - 1 : 0;
    new_entries[0] = e;
    memcpy(new_entries + 1, entries, sizeof(passwand_entry_t) * count_before);
    memcpy(new_entries + st.index + 1, entries + st.index + 1,
        sizeof(passwand_entry_t) * count_after);
    size_t new_entry_len = st.found ? entry_len : entry_len + 1;

    passwand_error_t err = passwand_export(options->data, new_entries, new_entry_len);
    if (err != PW_OK)
        DIE("failed to export entries: %s", passwand_error(err));

    discard_master(master);
    return EXIT_SUCCESS;
}

typedef struct {
    bool found;
    const char *space;
    const char *key;
} delete_state_t;

static void check(void *state, const char *space, const char *key,
        const char *value __attribute__((unused))) {

    assert(state != NULL);
    assert(space != NULL);
    assert(key != NULL);

    delete_state_t *st = state;
    assert(st->space != NULL);
    assert(st->key != NULL);

    assert(!st->found);
    st->found = strcmp(st->space, space) == 0 && strcmp(st->key, key) == 0;
}

static int delete(const options_t *options __attribute__((unused)), master_t *master,
        passwand_entry_t *entries, size_t entry_len) {

    delete_state_t st = {
        .found = false,
        .space = options->space,
        .key = options->key,
    };

    /* Try to find the entry to delete. */
    size_t i;
    for (i = 0; i < entry_len; i++) {
        if (passwand_entry_do(master->master, &entries[i], check, &st) != PW_OK)
            DIE("failed to handle entry %zu", i);
        if (st.found)
            break;
    }

    if (!st.found)
        DIE("failed to find entry");

    /* Shuffle entries following the one to be deleted, to remove the deleted one. */
    for (size_t j = i; j < entry_len - 1; j++)
        entries[j] = entries[j + 1];

    passwand_error_t err = passwand_export(options->data, entries, entry_len - 1);
    if (err != PW_OK)
        DIE("failed to export entries: %s", passwand_error(err));

    discard_master(master);
    return EXIT_SUCCESS;
}

static void print(void *state, const char *space, const char *key,
        const char *value __attribute__((unused))) {
    assert(space != NULL);
    assert(key != NULL);

    pthread_mutex_t *printf_lock = state;
    if (printf_lock != NULL) {
        int r __attribute__((unused)) = pthread_mutex_lock(printf_lock);
        assert(r == 0);
    }

    printf("%s/%s\n", space, key);

    if (printf_lock != NULL) {
        int r __attribute__((unused)) = pthread_mutex_unlock(printf_lock);
        assert(r == 0);
    }
}

typedef struct {
    atomic_size_t *index;
    const passwand_entry_t *entries;
    size_t entry_len;
    const char *master;
    pthread_mutex_t *printf_lock;
    size_t err_index;
} thread_state_t;

static void *list_loop(void *arg) {
    assert(arg != NULL);

    thread_state_t *ts = arg;
    assert(ts->index != NULL);
    assert(ts->entries != NULL || ts->entry_len == 0);

    for (;;) {

        size_t index = atomic_fetch_add(ts->index, 1);
        if (index >= ts->entry_len)
            break;

        passwand_error_t err = passwand_entry_do(ts->master, &ts->entries[index], print,
            ts->printf_lock);
        if (err != PW_OK) {
            static_assert(sizeof(passwand_error_t) <= sizeof(void*),
                "passwand error won't fit in return type");
            ts->err_index = index;
            return (void*)err;
        }

    }

    return (void*)PW_OK;
}

static int list(const options_t *options __attribute__((unused)), master_t *master,
        passwand_entry_t *entries, size_t entry_len) {

    unsigned long jobs = options->jobs;
    if (jobs == 0) { // automatic
        long cpus = sysconf(_SC_NPROCESSORS_ONLN);
        assert(cpus >= 1);
        jobs = (unsigned long)cpus;
    }

    if (jobs == 1) {

        /* If we're only using a single job, we can just process the list of entries ourself without
         * dealing with pthreads.
         */

        atomic_size_t index = 0;
        thread_state_t ts = {
            .index = &index,
            .entries = entries,
            .entry_len = entry_len,
            .master = master->master,
            .printf_lock = NULL,
        };

        passwand_error_t err = (passwand_error_t)list_loop(&ts);
        if (err != PW_OK)
            DIE("failed to handle entry %zu: %s", ts.err_index, passwand_error(err));

    } else {

        /* A lock that we'll use to synchronise access to stdout. */
        pthread_mutex_t printf_lock;
        if (pthread_mutex_init(&printf_lock, NULL) != 0)
            DIE("failed to create mutex");

        thread_state_t *tses = calloc(jobs, sizeof(*tses));
        if (tses == NULL)
            DIE("out of memory");

        pthread_t *threads = calloc(jobs - 1, sizeof(*threads));
        if (threads == NULL)
            DIE("out of memory");

        /* Initialise and start the threads. */
        atomic_size_t index = 0;
        for (unsigned long i = 0; i < jobs; i++) {
            tses[i].index = &index;
            tses[i].entries = entries;
            tses[i].entry_len = entry_len;
            tses[i].master = master->master;
            tses[i].printf_lock = &printf_lock;

            if (i < jobs - 1) {
                int r = pthread_create(&threads[i], NULL, list_loop, &tses[i]);
                if (r != 0)
                    DIE("failed to create thread %lu", i + 1);
            }
        }

        /* Join the other threads in printing. */
        passwand_error_t err = (passwand_error_t)list_loop(&tses[jobs - 1]);
        if (err != PW_OK)
            DIE("failed to handle entry %zu: %s", tses[jobs - 1].err_index, passwand_error(err));

        /* Collect threads */
        for (unsigned long i = 0; i < jobs - 1; i++) {
            void *ret;
            int r = pthread_join(threads[i], &ret);
            if (r != 0)
                DIE("failed to join thread %lu", i + 1);
            err = (passwand_error_t)ret;
            if (err != PW_OK)
                DIE("failed to handle entry %zu: %s", tses[i].err_index, passwand_error(err));
        }

        free(threads);
        free(tses);

        (void)pthread_mutex_destroy(&printf_lock);
    }

    discard_master(master);
    return EXIT_SUCCESS;
}

typedef struct {
    master_t *master;
    passwand_entry_t *entries;
    size_t index;
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
        size_t entry_len) {

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
    for (size_t i = 0; i < entry_len; i++) {
        passwand_error_t err = passwand_entry_do(master->master, &entries[i], change_master_body,
            &st);
        if (err != PW_OK) {
            discard_master(new_master);
            DIE("failed to process entry %zu: %s\n", i, passwand_error(err));
        }
        if (st.err != PW_OK) {
            discard_master(new_master);
            DIE("failed to process entry %zu: %s\n", i, passwand_error(st.err));
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
        size_t entry_len);

    if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-?") == 0) {
        printf("usage:\n"
               " %s change-master                               Change the master password\n"
               " %s delete --space SPACE --key KEY              Delete an existing entry\n"
               " %s get --space SPACE --key KEY                 Retrieve an existing entry\n"
               " %s list                                        List all entries\n"
               " %s set --space SPACE --key KEY --value VALUE   Set an entry\n"
               "\n"
               "common options:\n"
               " --data DATA            Path to data file (default ~/.passwand.json)\n"
               " --jobs THREADS         Number of threads to use\n"
               " --work-factor FACTOR   Scrypt work factor (default 14)\n",
               argv[0], argv[0], argv[0], argv[0], argv[0]);
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
    else if (strcmp(argv[1], "delete") == 0)
        action = delete;
    else
        DIE("invalid action");

    options_t options;
    if (parse(argc - 1, argv + 1, &options) != 0)
        return EXIT_FAILURE;

    passwand_entry_t *entries = NULL;
    size_t entry_len = 0;
    if (access(options.data, F_OK) == 0) {
        passwand_error_t err = passwand_import(options.data, &entries, &entry_len);
        if (err != PW_OK)
            DIE("failed to load database: %s", passwand_error(err));
    }

    for (size_t i = 0; i < entry_len; i++)
        entries[i].work_factor = options.work_factor;

#define REQUIRED(field) \
    do { \
        if (options.field == NULL) { \
            DIE("missing required argument --" #field); \
        } \
    } while (0)
#define IGNORED(field) \
    do { \
        if (options.field != NULL) { \
            DIE("irrelevant argument --" #field); \
        } \
    } while (0)
    if (action == get) {
        REQUIRED(space);
        REQUIRED(key);
        IGNORED(value);
    } else if (action == set) {
        REQUIRED(space);
        REQUIRED(key);
        REQUIRED(value);
    } else if (action == list) {
        IGNORED(space);
        IGNORED(key);
        IGNORED(value);
    } else if (action == change_master) {
        IGNORED(space);
        IGNORED(key);
        IGNORED(value);
    } else if (action == delete) {
        REQUIRED(space);
        REQUIRED(key);
        IGNORED(value);
    }
#undef IGNORED
#undef REQUIRED

    master = getpassword(NULL);
    if (master == NULL)
        DIE("failed to read master password");

    return action(&options, master, entries, entry_len);
}
