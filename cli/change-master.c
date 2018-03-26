#include "../common/argparse.h"
#include "change-master.h"
#include "cli.h"
#include <passwand/passwand.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

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

int change_master(const options_t *options, const master_t *master, passwand_entry_t *entries,
        size_t entry_len) {

    master_t *new_master = NULL;
    master_t *confirm_new = NULL;
    passwand_entry_t *new_entries = NULL;
    int ret = 0;

    new_master = getpassword("new master password: ");
    if (new_master == NULL) {
        fprintf(stderr, "failed to read new password\n");
        return -1;
    }

    confirm_new = getpassword("confirm new master password: ");
    if (confirm_new == NULL) {
        fprintf(stderr, "failed to read confirmation of new password\n");
        ret = -1;
        goto done;
    }

    if (strcmp(new_master->master, confirm_new->master) != 0) {
        fprintf(stderr, "passwords do not match\n");
        ret = -1;
        goto done;
    }

    discard_master(confirm_new);
    confirm_new = NULL;

    new_entries = calloc(entry_len, sizeof *new_entries);
    if (new_entries == NULL) {
        fprintf(stderr, "out of memory\n");
        ret = -1;
        goto done;
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
            fprintf(stderr, "failed to process entry %zu: %s\n", i, passwand_error(err));
            ret = -1;
            goto done;
        }
        if (st.err != PW_OK) {
            fprintf(stderr, "failed to process entry %zu: %s\n", i, passwand_error(st.err));
            ret = -1;
            goto done;
        }
    }
    discard_master(new_master);
    new_master = NULL;

    passwand_error_t err = passwand_export(options->data, new_entries, entry_len);
    if (err != PW_OK) {
        fprintf(stderr, "failed to export entries\n");
        ret = -1;
        goto done;
    }

done:
    free(new_entries);
    if (confirm_new != NULL)
        discard_master(confirm_new);
    if (new_master != NULL)
        discard_master(new_master);
    return ret;
}
