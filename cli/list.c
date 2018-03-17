#include "../common/argparse.h"
#include <assert.h>
#include "cli.h"
#include "list.h"
#include <passwand/passwand.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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

int list(const options_t *options __attribute__((unused)), const master_t *master,
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

    return EXIT_SUCCESS;
}
