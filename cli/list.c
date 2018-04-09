#include "../common/argparse.h"
#include <assert.h>
#include "cli.h"
#include "list.h"
#include <passwand/passwand.h>
#include "print.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

static void pr(void *state __attribute__((unused)), const char *space, const char *key,
        const char *value __attribute__((unused))) {
    assert(space != NULL);
    assert(key != NULL);

    print("%s/%s\n", space, key);
}

typedef struct {
    atomic_size_t *index;
    const passwand_entry_t *entries;
    size_t entry_len;
    const char *master;
    size_t err_index;
    bool created;
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

        passwand_error_t err = passwand_entry_do(ts->master, &ts->entries[index], pr, NULL);
        if (err != PW_OK) {
            static_assert(sizeof(passwand_error_t) <= sizeof(void*),
                "passwand error won't fit in return type");
            ts->err_index = index;
            return (void*)err;
        }

    }

    return (void*)PW_OK;
}

static int list(void **state __attribute__((unused)), const options_t *opts __attribute__((unused)), const master_t *master,
        passwand_entry_t *entries, size_t entry_len) {

    thread_state_t *tses = NULL;
    pthread_t *threads = NULL;
    int ret = -1;
    unsigned errors = 0;

    unsigned long jobs = opts->jobs;
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
        };

        passwand_error_t err = (passwand_error_t)list_loop(&ts);
        if (err != PW_OK) {
            eprint("failed to handle entry %zu: %s\n", ts.err_index, passwand_error(err));
            return -1;
        }

    } else {

        tses = calloc(jobs, sizeof(*tses));
        if (tses == NULL) {
            eprint("out of memory\n");
            goto done;
        }

        threads = calloc(jobs - 1, sizeof(*threads));
        if (threads == NULL) {
            eprint("out of memory\n");
            goto done;
        }

        /* Initialise and start the threads. */
        atomic_size_t index = 0;
        for (unsigned long i = 0; i < jobs; i++) {
            tses[i].index = &index;
            tses[i].entries = entries;
            tses[i].entry_len = entry_len;
            tses[i].master = master->master;
            tses[i].created = false;

            if (i < jobs - 1) {
                int r = pthread_create(&threads[i], NULL, list_loop, &tses[i]);
                if (r == 0) {
                    tses[i].created = true;
                } else {
                    eprint("warning: failed to create thread %lu\n", i + 1);
                }

            }
        }

        /* Join the other threads in printing. */
        passwand_error_t err = (passwand_error_t)list_loop(&tses[jobs - 1]);
        if (err != PW_OK) {
            eprint("failed to handle entry %zu: %s\n", tses[jobs - 1].err_index, passwand_error(err));
            errors++;
        }

        /* Collect threads */
        for (unsigned long i = 0; i < jobs - 1; i++) {
            if (tses[i].created) {
                void *retu;
                int r = pthread_join(threads[i], &retu);
                if (r != 0) {
                    eprint("failed to join thread %lu\n", i + 1);
                    errors++;
                } else {
                    err = (passwand_error_t)retu;
                    if (err != PW_OK) {
                        eprint("failed to handle entry %zu: %s\n", tses[i].err_index, passwand_error(err));
                        errors++;
                    }
                }
            }
        }
    }

    ret = errors > 0 ? EXIT_FAILURE : EXIT_SUCCESS;

done:
    free(threads);
    free(tses);
    return ret;
}

const command_t list_command = {
    .need_space = false,
    .need_key = false,
    .need_value = false,
    .initialize = list,
};
