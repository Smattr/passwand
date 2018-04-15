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

typedef struct {
    atomic_bool *done;
    atomic_size_t *index;
    const passwand_entry_t *entries;
    size_t entry_len;
    const char *master;
    const char *space;
    const char *key;

    const char *err_message;
    size_t found_index;
} thread_state_t;

static void check(void *state, const char *space, const char *key, const char *value) {
    char *found_value = state;
    if (strcmp(options.space, space) == 0 && strcmp(options.key, key) == 0) {
        if (passwand_secure_malloc((void**)&found_value, strlen(value) + 1) == PW_OK)
            strcpy(found_value, value);
    }
}

static void *search(void *arg) {
    assert(arg != NULL);

    thread_state_t *ts = arg;
    assert(ts->done != NULL);
    assert(ts->index != NULL);
    assert(ts->entries != NULL);
    assert(ts->master != NULL);
    assert(ts->space != NULL);
    assert(ts->key != NULL);
    assert(ts->err_message == NULL);

    char *found_value = NULL;

    for (;;) {

        if (atomic_load(ts->done))
            break;

        /* Get the next entry to check */
        size_t index = atomic_fetch_add(ts->index, 1);
        if (index >= ts->entry_len)
            break;

        passwand_error_t err = passwand_entry_do(ts->master, &ts->entries[index], check,
          &found_value);
        if (err != PW_OK) {
            ts->err_message = passwand_error(err);
            return (void*)-1;
        }

        if (found_value != NULL) {
            /* We found it! */
            atomic_store(ts->done, true);
            ts->found_index = index;
            return found_value;
        }
    }

    return NULL;
}

static void autoclear(void *p) {
    assert(p != NULL);
    char **s = p;
    if (*s != NULL)
        passwand_secure_free(*s, strlen(*s));
}

int main(int argc, char **argv) {

    if (parse(argc, argv) != 0)
        return EXIT_FAILURE;

    char *space;
    if (options.space != NULL)
        space = options.space;
    else
        space = get_text("Passwand", "Name space?", NULL, false);
    if (space == NULL)
        return EXIT_SUCCESS;

    char *key;
    if (options.key != NULL)
        key = options.key;
    else
        key = get_text("Passwand", "Key?", "password", false);
    if (key == NULL)
        return EXIT_SUCCESS;

    char *master __attribute__((cleanup(autoclear))) = get_text("Passwand", "Master passphrase?", NULL, true);
    if (master == NULL)
        return EXIT_SUCCESS;

    flush_state();

    /* Import the database. */
    passwand_entry_t *entries;
    size_t entry_len;
    passwand_error_t err = passwand_import(options.data, &entries, &entry_len);
    if (err != PW_OK)
        DIE("failed to import database: %s", passwand_error(err));

    for (size_t i = 0; i < entry_len; i++)
        entries[i].work_factor = options.work_factor;

    /* We now are ready to search for the entry, but let's parallelise it across as many cores as
     * we have to speed it up.
     */

    char *value = NULL;
    size_t found_index = SIZE_MAX;

    assert(options.jobs >= 1);

    thread_state_t *tses = calloc(options.jobs, sizeof(thread_state_t));
    if (tses == NULL)
        DIE("out of memory");

    pthread_t *threads = calloc(options.jobs - 1, sizeof(pthread_t));
    if (threads == NULL)
        DIE("out of memory");

    atomic_bool done = false;
    atomic_size_t index = 0;

    /* Initialise and start threads. */
    for (size_t i = 0; i < options.jobs; i++) {
        tses[i].done = &done;
        tses[i].index = &index;
        tses[i].entries = entries;
        tses[i].entry_len = entry_len;
        tses[i].master = master;
        tses[i].space = space;
        tses[i].key = key;

        if (i < options.jobs - 1) {
            int r = pthread_create(&threads[i], NULL, search, &tses[i]);
            if (r != 0)
                DIE("failed to create thread %ld", i + 1);
        }
    }

    /* Join the other threads in searching. */
    void *ret = search(&tses[options.jobs - 1]);
    if (ret == (void*)-1) {
        assert(tses[options.jobs - 1].err_message != NULL);
        DIE("error: %s", tses[options.jobs - 1].err_message);
    } else if (ret != NULL) {
        value = ret;
        found_index = tses[options.jobs - 1].found_index;
    }

    /* Collect threads. */
    for (size_t i = 0; i < options.jobs - 1; i++) {
        int r = pthread_join(threads[i], &ret);
        if (r != 0)
            DIE("failed to join thread %ld", i + 1);
        if (ret == (void*)-1) {
            assert(tses[i].err_message != NULL);
            DIE("error: %s", tses[i].err_message);
        } else if (ret != NULL) {
            assert(value == NULL && "multiple matching entries found");
            value = ret;
            assert(found_index == SIZE_MAX && "found_index out of sync with value");
            found_index = tses[i].found_index;
        }
    }

    free(threads);
    free(tses);

    if (value == NULL)
        DIE("failed to find matching entry");
    char *clearer __attribute__((unused, cleanup(autoclear))) = value;

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
