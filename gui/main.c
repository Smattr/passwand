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
        exit(FAILURE_CODE); \
    } while (0)

static atomic_bool done;
static atomic_size_t entry_index;
static passwand_entry_t *entries;
static size_t entry_len;
static const char *master;
static size_t found_index;

static void check(void *state, const char *space, const char *key, const char *value) {
    char *found_value = state;
    if (strcmp(options.space, space) == 0 && strcmp(options.key, key) == 0) {
        if (passwand_secure_malloc((void**)&found_value, strlen(value) + 1) == PW_OK)
            strcpy(found_value, value);
    }
}

static void *search(void *arg __attribute__((unused))) {

    char *found_value = NULL;

    for (;;) {

        if (done)
            break;

        /* Get the next entry to check */
        size_t i = atomic_fetch_add(&entry_index, 1);
        if (i >= entry_len)
            break;

        passwand_error_t err = passwand_entry_do(master, &entries[i], check, &found_value);
        if (err != PW_OK) {
            char *msg;
            if (asprintf(&msg, "error: %s", passwand_error(err)) >= 0) {
                show_error(msg);
                free(msg);
            }
            return NULL;
        }

        if (found_value != NULL) {
            /* We found it! */
            bool expected = false;
            if (atomic_compare_exchange_strong(&done, &expected, true)) {
                found_index = i;
                return found_value;
            } else {
                passwand_secure_free(found_value, strlen(found_value) + 1);
            }
            return NULL;
        }
    }

    return NULL;
}

static void autoclear(void *p) {
    assert(p != NULL);
    char **s = p;
    if (*s != NULL)
        passwand_secure_free(*s, strlen(*s) + 1);
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

    char *m __attribute__((cleanup(autoclear))) = get_text("Passwand", "Master passphrase?", NULL, true);
    if (m == NULL)
        return EXIT_SUCCESS;

    flush_state();

    /* Import the database. */
    passwand_error_t err = passwand_import(options.data, &entries, &entry_len);
    if (err != PW_OK)
        DIE("failed to import database: %s", passwand_error(err));

    for (size_t i = 0; i < entry_len; i++)
        entries[i].work_factor = options.work_factor;

    /* We now are ready to search for the entry, but let's parallelise it across as many cores as
     * we have to speed it up.
     */

    char *value __attribute__((cleanup(autoclear))) = NULL;

    assert(options.jobs >= 1);

    pthread_t *threads = calloc(options.jobs - 1, sizeof(pthread_t));
    if (threads == NULL)
        DIE("out of memory");

    /* Initialise and start threads. */
    master = m;
    for (size_t i = 0; i < options.jobs; i++) {

        if (i < options.jobs - 1) {
            int r = pthread_create(&threads[i], NULL, search, NULL);
            if (r != 0)
                DIE("failed to create thread %ld", i + 1);
        }
    }

    /* Join the other threads in searching. */
    void *ret = search(NULL);
    if (ret != NULL)
        value = ret;

    /* Collect threads. */
    for (size_t i = 0; i < options.jobs - 1; i++) {
        int r = pthread_join(threads[i], &ret);
        if (r != 0)
            DIE("failed to join thread %ld", i + 1);
        if (ret != NULL) {
            assert(value == NULL && "multiple matching entries found");
            value = ret;
        }
    }

    free(threads);

    if (value == NULL)
        DIE("failed to find matching entry");

    for (size_t i = 0; i < strlen(value); i++) {
        if (!(supported_upper(value[i]) || supported_lower(value[i])))
            DIE("unsupported character at index %zu in entry", i);
    }

    if (send_text(value) < 0)
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

    return EXIT_SUCCESS;
}
