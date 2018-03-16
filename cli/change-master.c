#include "../common/argparse.h"
#include "change-master.h"
#include "cli.h"
#include <passwand/passwand.h>
#include <stdlib.h>
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

int change_master(const options_t *options, master_t *master, passwand_entry_t *entries,
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
