#include "../common/argparse.h"
#include "change-master.h"
#include "cli.h"
#include "delete.h"
#include "get.h"
#include "list.h"
#include <passwand/passwand.h>
#include "set.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

master_t *getpassword(const char *prompt) {

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

void discard_master(master_t *m) {
    if (m == NULL)
        return;
    passwand_secure_free(m->master, m->master_len);
    passwand_secure_free(m, sizeof *m);
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
