#include "change-main.h"
#include "../common/argparse.h"
#include "cli.h"
#include "print.h"
#include <passwand/passwand.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>

static main_t *new_main;

static passwand_entry_t *new_entries;
static size_t new_entries_len;
static _Thread_local size_t new_entry_index;

static _Atomic passwand_error_t err;

static void loop_notify(size_t entry_index) { new_entry_index = entry_index; }

static bool loop_condition(void) { return err == PW_OK; }

static void loop_body(const char *space, const char *key, const char *value) {

  passwand_error_t e =
      passwand_entry_new(&new_entries[new_entry_index], new_main->main, space,
                         key, value, options.db.work_factor);
  if (e != PW_OK) {
    passwand_error_t none = PW_OK;
    if (atomic_compare_exchange_strong(&err, &none, e))
      eprint("failed to process entry %zu: %s\n", new_entry_index,
             passwand_error(e));
  }
}

static int initialize(const main_t *mainpass __attribute__((unused)),
                      passwand_entry_t *entries __attribute__((unused)),
                      size_t entry_len) {

  new_main = NULL;
  main_t *confirm_new = NULL;
  new_entries = NULL;
  new_entries_len = entry_len;
  err = PW_OK;
  int ret = -1;

  new_main = getpassword("new main password: ");
  if (new_main == NULL) {
    eprint("failed to read new password\n");
    goto done;
  }

  confirm_new = getpassword("confirm new main password: ");
  if (confirm_new == NULL) {
    eprint("failed to read confirmation of new password\n");
    goto done;
  }

  if (strcmp(new_main->main, confirm_new->main) != 0) {
    eprint("passwords do not match\n");
    goto done;
  }

  discard_main(&confirm_new);

  new_entries = calloc(entry_len, sizeof(*new_entries));
  if (new_entries == NULL) {
    eprint("out of memory\n");
    goto done;
  }

  ret = 0;

done:
  if (ret != 0)
    free(new_entries);
  discard_main(&confirm_new);
  if (ret != 0)
    discard_main(&new_main);
  return ret;
}

static int finalize(bool failure_pending) {

  discard_main(&new_main);

  if (!failure_pending && err == PW_OK) {
    err = passwand_export(options.db.path, new_entries, new_entries_len);
    if (err != PW_OK)
      eprint("failed to export entries: %s\n", passwand_error(err));
  }

  for (size_t i = 0; i < new_entries_len; i++) {
    free(new_entries[i].space);
    free(new_entries[i].key);
    free(new_entries[i].value);
    free(new_entries[i].hmac);
    free(new_entries[i].hmac_salt);
    free(new_entries[i].salt);
    free(new_entries[i].iv);
  }
  free(new_entries);

  return err != PW_OK;
}

const command_t change_main = {
    .need_space = DISALLOWED,
    .need_key = DISALLOWED,
    .need_value = DISALLOWED,
    .need_length = DISALLOWED,
    .access = LOCK_EX,
    .initialize = initialize,
    .loop_notify = loop_notify,
    .loop_condition = loop_condition,
    .loop_body = loop_body,
    .finalize = finalize,
};
