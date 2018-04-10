#include "../common/argparse.h"
#include <assert.h>
#include "change-master.h"
#include "cli.h"
#include "delete.h"
#include "get.h"
#include "list.h"
#include <passwand/passwand.h>
#include <pthread.h>
#include "print.h"
#include "set.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static const struct {
    const char *name;
    const command_t *action;
} COMMANDS[] = {
    { "change-master", &change_master },
    { "delete", &delete_command },
    { "get", &get },
    { "list", &list_command },
    { "set", &set_command },
};

static const command_t *command_for(const char *name) {
    for (size_t i = 0; i < sizeof(COMMANDS) / sizeof(COMMANDS[0]); i++) {
        if (strcmp(name, COMMANDS[i].name) == 0)
            return COMMANDS[i].action;
    }
    return NULL;
}

master_t *getpassword(const char *prompt) {

    static const size_t EXPECTED_PAGE_SIZE = 4096;

    /* Initial allocation size. We only support allocating a page, so clamp it
     * at the expected page size if necessary.
     */
    size_t size = BUFSIZ > EXPECTED_PAGE_SIZE ? EXPECTED_PAGE_SIZE : BUFSIZ;

    char *m;
    if (passwand_secure_malloc((void**)&m, size) != 0) {
        eprint("failed to allocate secure memory\n");
        return NULL;
    }

    print("%s", prompt == NULL ? "master password: " : prompt);
    fflush(stdout);

    struct termios old;
    if (tcgetattr(STDOUT_FILENO, &old) != 0) {
        eprint("failed to get stdout attributes\n");
        passwand_secure_free(m, size);
        return NULL;
    }
    struct termios new = old;
    cfmakeraw(&new);
    if (tcsetattr(STDOUT_FILENO, 0, &new) != 0) {
        eprint("failed to set stdout attributes\n");
        passwand_secure_free(m, size);
        return NULL;
    }

    size_t index = 0;
    for (;;) {
        int c = getchar();

        if (c == EOF) {
            fflush(stdout);
            tcsetattr(STDOUT_FILENO, 0, &old);
            eprint("truncated input\n");
            passwand_secure_free(m, size);
            return NULL;
        }

        if (c == '\n' || c == '\r' || c == '\f')
            break;

        m[index] = c;
        index++;
        if (index >= size) {
            size_t new_size = size + BUFSIZ;
            /* If we're increasing our allocation to more than one page, first
             * clamp to one page for the reasons described above.
             */
            if (size < EXPECTED_PAGE_SIZE && new_size > EXPECTED_PAGE_SIZE)
                new_size = EXPECTED_PAGE_SIZE;
            char *n;
            if (passwand_secure_malloc((void**)&n, new_size) != 0) {
                fflush(stdout);
                tcsetattr(STDOUT_FILENO, 0, &old);
                eprint("failed to reallocate secure memory\n");
                passwand_secure_free(m, size);
                return NULL;
            }
            strncpy(n, m, size);
            passwand_secure_free(m, size);
            m = n;
            size = new_size;
        }
    }

    fflush(stdout);
    tcsetattr(STDOUT_FILENO, 0, &old);
    print("\n");

    m[index] = '\0';

    master_t *master;
    if (passwand_secure_malloc((void**)&master, sizeof(*master)) != 0) {
        eprint("failed to reallocate secure memory\n");
        passwand_secure_free(m, size);
        return NULL;
    }
    master->master = m;
    master->master_len = size;

    return master;
}

void discard_master(master_t *m) {
    if (m == NULL)
        return;
    passwand_secure_free(m->master, m->master_len);
    passwand_secure_free(m, sizeof(*m));
}

typedef struct {
    size_t thread_index;
    atomic_size_t *index;
    passwand_entry_t *entries;
    size_t entry_len;
    const char *master;

    const command_t *command;

    passwand_error_t error;
    size_t error_index;

    bool created;

} thread_state_t;

static void *thread_loop(void *arg) {
    assert(arg != NULL);

    thread_state_t *ts = arg;
    assert(ts->command != NULL);
    const command_t *command = ts->command;

    for (;;) {

        size_t index = atomic_fetch_add(ts->index, 1);
        if (index >= ts->entry_len)
            break;

        if (command->loop_notify != NULL)
            command->loop_notify(ts->thread_index, index);

        if (command->loop_condition != NULL && !command->loop_condition())
            break;

        if (command->loop_body != NULL) {
            passwand_error_t err = passwand_entry_do(ts->master, &ts->entries[index],
                command->loop_body, NULL);
            if (err != PW_OK) {
                ts->error = err;
                ts->error_index = index;
                return (void*)-1;
            }
        }
    }
    return NULL;
}

int main(int argc, char **argv) {

    if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-?") == 0) {
        print("usage:\n"
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
    passwand_entry_t *entries = NULL;
    const command_t *command = NULL;
    bool command_initialized = false;
    thread_state_t *tses = NULL;
    pthread_t *threads = NULL;
    int ret = EXIT_FAILURE;
    unsigned errors = 0;

    /* Figure out which command to run. */
    command = command_for(argv[1]);
    if (command == NULL) {
        eprint("invalid action: %s\n", argv[1]);
        goto done;
    }

    if (parse(argc - 1, argv + 1) != 0)
        goto done;

    size_t entry_len = 0;
    if (access(options.data, F_OK) == 0) {
        passwand_error_t err = passwand_import(options.data, &entries, &entry_len);
        if (err != PW_OK) {
            eprint("failed to load database: %s\n", passwand_error(err));
            goto done;
        }
    }

    for (size_t i = 0; i < entry_len; i++)
        entries[i].work_factor = options.work_factor;

    /* Validate flags. */
#define HANDLE(field) \
    do { \
        if (command->need_ ## field && options.field == NULL) { \
            eprint("missing required argument --" #field "\n"); \
            goto done; \
        } else if (!command->need_ ## field && options.field != NULL) { \
            eprint("irrelevant argument --" #field "\n"); \
            goto done; \
        } \
    } while (0)
    HANDLE(space);
    HANDLE(key);
    HANDLE(value);
#undef HANDLE

    master = getpassword(NULL);
    if (master == NULL) {
        eprint("failed to read master password\n");
        goto done;
    }

    /* Setup command. */
    assert(command->initialize != NULL);
    int r = command->initialize(master, entries, entry_len);
    if (r != 0)
        goto done;
    command_initialized = true;

    /* Allocate thread data */
    tses = calloc(options.jobs, sizeof(tses[0]));
    if (tses == NULL) {
        eprint("out of memory\n");
        goto done;
    }

    /* Setup thread data. */
    atomic_size_t index = 0;
    for (size_t i = 0; i < options.jobs; i++) {
        tses[i].thread_index = i;
        tses[i].index = &index;
        tses[i].entries = entries;
        tses[i].entry_len = entry_len;
        tses[i].master = master->master;
        tses[i].command = command;
        tses[i].error = PW_OK;
        tses[i].error_index = SIZE_MAX;
        tses[i].created = false;
    }

    /* Allocate threads. */
    assert(options.jobs >= 1);
    threads = calloc(options.jobs - 1, sizeof(threads[0]));
    if (threads == NULL) {
        eprint("out of memory\n");
        goto done;
    }

    /* Start threads. */
    for (size_t i = 1; i < options.jobs; i++) {
        r = pthread_create(&threads[i - 1], NULL, thread_loop, &tses[i]);
        if (r == 0) {
            tses[i].created = true;
        } else {
            eprint("warning: failed to create thread %zu\n", i);
        }
    }

    /* Join the other threads. */
    r = (int)(intptr_t)thread_loop(&tses[0]);
    if (r != 0) {
        eprint("failed to handle entry %zu: %s\n", tses[0].error_index,
            passwand_error(tses[0].error));
        errors++;
    }

    /* Collect the secondary threads. */
    for (size_t i = 1; i < options.jobs; i++) {
        if (tses[i].created) {
            void *retu;
            r = pthread_join(threads[i - 1], &retu);
            if (r != 0) {
                eprint("failed to join thread %zu\n", i);
                errors++;
            } else {
                if ((int)(intptr_t)retu != 0) {
                    eprint("failed to handle entry %zu: %s\n", tses[i].error_index,
                        passwand_error(tses[i].error));
                    errors++;
                }
            }
        }
    }

    ret = errors > 0 ? EXIT_FAILURE : EXIT_SUCCESS;

done:
    free(threads);
    free(tses);
    if (command_initialized && command->finalize != NULL) {
        r = command->finalize();
        if (r != 0)
            ret = EXIT_FAILURE;
    }
    discard_master(master);
    free(entries);
    return ret;
}
