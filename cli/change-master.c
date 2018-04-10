#include "../common/argparse.h"
#include "change-master.h"
#include "cli.h"
#include <passwand/passwand.h>
#include "print.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

static master_t *new_master;

static passwand_entry_t *new_entries;
static size_t new_entries_len;
static _Thread_local size_t new_entry_index;

static _Atomic passwand_error_t err;

static void loop_notify(size_t thread_index __attribute__((unused)), size_t entry_index) {
    new_entry_index = entry_index;
}

static bool loop_condition(void) {
    return err == PW_OK;
}

static void loop_body(void *state __attribute__((unused)), const char *space, const char *key,
  const char *value) {

    passwand_error_t e = passwand_entry_new(&new_entries[new_entry_index], new_master->master,
      space, key, value, options.work_factor);
    if (e != PW_OK) {
        passwand_error_t none = PW_OK;
        if (atomic_compare_exchange_strong(&err, &none, e))
            eprint("failed to process entry %zu: %s\n", new_entry_index, passwand_error(e));
    }
}

static int initialize(const master_t *master __attribute__((unused)),
  passwand_entry_t *entries __attribute__((unused)), size_t entry_len) {

    new_master = NULL;
    master_t *confirm_new = NULL;
    new_entries = NULL;
    new_entries_len = entry_len;
    err = PW_OK;
    int ret = -1;

    new_master = getpassword("new master password: ");
    if (new_master == NULL) {
        eprint("failed to read new password\n");
        goto done;
    }

    confirm_new = getpassword("confirm new master password: ");
    if (confirm_new == NULL) {
        eprint("failed to read confirmation of new password\n");
        goto done;
    }

    if (strcmp(new_master->master, confirm_new->master) != 0) {
        eprint("passwords do not match\n");
        goto done;
    }

    discard_master(confirm_new);
    confirm_new = NULL;

    new_entries = calloc(entry_len, sizeof(*new_entries));
    if (new_entries == NULL) {
        eprint("out of memory\n");
        goto done;
    }

    ret = 0;

done:
    if (ret != 0)
        free(new_entries);
    if (confirm_new != NULL)
        discard_master(confirm_new);
    if (ret != 0 && new_master != NULL)
        discard_master(new_master);
    return ret;
}

static int finalize(void) {

    discard_master(new_master);
    new_master = NULL;

    if (err == PW_OK) {
        err = passwand_export(options.data, new_entries, new_entries_len);
        if (err != PW_OK)
            eprint("failed to export entries: %s\n", passwand_error(err));
    }

    free(new_entries);

    return err != PW_OK;
}

const command_t change_master = {
    .need_space = false,
    .need_key = false,
    .need_value = false,
    .initialize = initialize,
    .loop_notify = loop_notify,
    .loop_condition = loop_condition,
    .loop_body = loop_body,
    .finalize = finalize,
};
