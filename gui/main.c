#include "../common/argparse.h"
#include <assert.h>
#include "gui.h"
#include <limits.h>
#include <passwand/passwand.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#ifdef __APPLE__
    /* On macOS, assume we are being called by Automator that treats a non-zero
     * exit status as something that warrants a further error dialog. Because
     * we will have already told the user about the error, suppress Automator's
     * warning.
     */
    #define FAILURE_CODE EXIT_SUCCESS
#else
    #define FAILURE_CODE EXIT_FAILURE
#endif

#define DIE(args...) \
    do { \
        char *msg; \
        if (asprintf(&msg, ## args) >= 0) { \
            show_error(msg); \
            free(msg); \
        } \
        if (master != NULL) { \
            passwand_secure_free(master, strlen(master) + 1); \
        } \
        exit(FAILURE_CODE); \
    } while (0)

static atomic_bool done;
static atomic_size_t entry_index;
static passwand_entry_t *entries;
static size_t entry_len;
static char *master;
static char *found_value;
static size_t found_index;

static void check(void *state, const char *space, const char *key, const char *value) {
    char **v = state;

    assert(options.space != NULL);
    assert(space != NULL);
    assert(options.key != NULL);
    assert(key != NULL);
    if (strcmp(options.space, space) == 0 && strcmp(options.key, key) == 0) {
        assert(v != NULL);
        if (passwand_secure_malloc((void**)v, strlen(value) + 1) == PW_OK) {
            assert(*v != NULL);
            strcpy(*v, value);
        }
    }
}

static void *search(void *arg __attribute__((unused))) {

    char *v = NULL;

    for (;;) {

        if (done)
            break;

        /* Get the next entry to check */
        size_t i = atomic_fetch_add(&entry_index, 1);
        if (i >= entry_len)
            break;

        passwand_error_t err = passwand_entry_do(master, &entries[i], check, &v);
        if (err != PW_OK) {
            char *msg;
            if (asprintf(&msg, "error: %s", passwand_error(err)) >= 0)
                return msg;
            return NULL;
        }

        if (v != NULL) {
            /* We found it! */
            bool expected = false;
            if (atomic_compare_exchange_strong(&done, &expected, true)) {
                found_index = i;
                found_value = v;
                return NULL;
            } else {
                passwand_secure_free(v, strlen(v) + 1);
            }
            return NULL;
        }
    }

    return NULL;
}

int main(int argc, char **argv) {

    if (parse(argc, argv) != 0)
        return EXIT_FAILURE;

    if (options.space == NULL)
        options.space = get_text("Passwand", "Name space?", NULL, false);
    if (options.space == NULL)
        return EXIT_SUCCESS;

    if (options.key == NULL)
        options.key = get_text("Passwand", "Key?", "password", false);
    if (options.key == NULL)
        return EXIT_SUCCESS;

    master = get_text("Passwand", "Master passphrase?", NULL, true);
    if (master == NULL)
        return EXIT_SUCCESS;

    flush_state();

    /* Lock database that we're about to access. */
    if (access(options.data, R_OK) == 0) {
        int fd = open(options.data, R_OK);
        if (fd < 0)
            DIE("failed to open database");
        if (flock(fd, LOCK_EX | LOCK_NB) != 0)
            DIE("failed to lock database: %s", strerror(errno));
    }

    /* Import the database. */
    passwand_error_t err = passwand_import(options.data, &entries, &entry_len);
    if (err != PW_OK)
        DIE("failed to import database: %s", passwand_error(err));

    for (size_t i = 0; i < entry_len; i++)
        entries[i].work_factor = options.work_factor;

    /* We now are ready to search for the entry, but let's parallelise it across as many cores as
     * we have to speed it up.
     */

    assert(options.jobs >= 1);

    pthread_t *threads = calloc(options.jobs - 1, sizeof(pthread_t));
    if (threads == NULL)
        DIE("out of memory");

    /* Initialise and start threads. */
    for (size_t i = 0; i < options.jobs; i++) {

        if (i < options.jobs - 1) {
            int r = pthread_create(&threads[i], NULL, search, NULL);
            if (r != 0)
                DIE("failed to create thread %ld", i + 1);
        }
    }

    bool shown_error = false;

    /* Join the other threads in searching. */
    void *ret = search(NULL);
    if (ret != NULL) {
        show_error(ret);
        free(ret);
        shown_error = true;
    }

    /* Collect threads. */
    for (size_t i = 0; i < options.jobs - 1; i++) {
        int r = pthread_join(threads[i], &ret);
        if (r != 0) {
            if (!shown_error) {
                char *msg;
                if (asprintf(&msg, "failed to join thread %ld", i + 1) >= 0) {
                    show_error(msg);
                    free(msg);
                }
            }
            shown_error = true;
        } else if (ret != NULL) {
            if (!shown_error)
                show_error(ret);
            shown_error = true;
            free(ret);
        }
    }

    /* we don't need the master password anymore */
    assert(master != NULL);
    passwand_secure_free(master, strlen(master) + 1);
    master = NULL;

    free(threads);

    if (found_value == NULL && !shown_error)
        DIE("failed to find matching entry");

    if (shown_error) {
        if (found_value != NULL)
            passwand_secure_free(found_value, strlen(found_value) + 1);
        exit(FAILURE_CODE);
    }

    for (size_t i = 0; i < strlen(found_value); i++) {
        if (!(supported_upper(found_value[i]) || supported_lower(found_value[i]))) {
            passwand_secure_free(found_value, strlen(found_value) + 1);
            DIE("unsupported character at index %zu in entry", i);
        }
    }

    int r = send_text(found_value);
    passwand_secure_free(found_value, strlen(found_value) + 1);

    if (r < 0)
        return EXIT_FAILURE;

    /* Move the entry we just retrieved to the front of the list of entries to
     * make future look ups for it faster. The idea is that over time this will
     * result in something like a MRU ordering of entries. Note, we ignore
     * failures during exporting because this is not critical.
     */
    assert(found_index != SIZE_MAX);
    assert(found_index < entry_len);
    if (found_index != 0) {
        passwand_entry_t found = entries[found_index];
        for (size_t i = found_index; i > 0; i--)
            entries[i] = entries[i - 1];
        entries[0] = found;
    }
    (void)passwand_export(options.data, entries, entry_len);

    /* Cleanup to make us Valgrind-free in successful runs. */
    for (size_t i = 0; i < entry_len; i++) {
        free(entries[i].space);
        free(entries[i].key);
        free(entries[i].value);
        free(entries[i].hmac);
        free(entries[i].hmac_salt);
        free(entries[i].salt);
        free(entries[i].iv);
    }
    free(entries);
    free(options.data);
    free(options.space);
    free(options.key);
    free(options.value);

    return EXIT_SUCCESS;
}
