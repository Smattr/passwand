#include "update.h"
#include "../common/argparse.h"
#include "../common/streq.h"
#include "cli.h"
#include "print.h"
#include <assert.h>
#include <limits.h>
#include <passwand/passwand.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/file.h>

static const main_t *saved_main;
static passwand_entry_t *saved_entries;
static size_t saved_entry_len;
static atomic_bool found;
static size_t found_index;
static _Thread_local size_t candidate_index;

static int initialize(const main_t *mainpass, passwand_entry_t *entries,
                      size_t entry_len) {

  saved_main = mainpass;
  saved_entries = entries;
  saved_entry_len = entry_len;
  found = false;
  found_index = 0;

  if (!mainpass->confirmed) {
    main_t *confirm = getpassword("confirm main password: ");
    if (confirm == NULL) {
      eprint("out of memory\n");
      return -1;
    }
    bool r = streq(mainpass->main, confirm->main);
    discard_main(&confirm);
    if (!r) {
      eprint("passwords do not match\n");
      return -1;
    }
  }

  return 0;
}

static void loop_notify(size_t entry_index) { candidate_index = entry_index; }

static bool loop_condition(void) { return !found; }

static void loop_body(const char *space, const char *key,
                      const char *value __attribute__((unused))) {

  assert(space != NULL);
  assert(key != NULL);

  if (streq(options.space, space) && streq(options.key, key)) {
    // This entry matches the one we are after. Mark it. This cmpxchg should
    // never fail because there should only ever be a single matching entry
    // (this one) but maybe we're operating on a tampered with or corrupted
    // database.
    bool expected = false;
    if (atomic_compare_exchange_strong(&found, &expected, true))
      found_index = candidate_index;
  }
}

static int finalize(bool failure_pending) {

  // There is an inherent race in `update` when running multithreaded or an
  // equivalent deterministic situation when running single threaded wherein we
  // can locate the entry to be updated before encountering later entries that
  // fail to decrypt. To make behaviour more uniform, treat all decryption
  // failures as non-fatal, despite how unorthodox that seems. This is not a
  // security violation because we can only update an entry we _have_ decrypted
  // successfully.
  (void)failure_pending;

  if (!found) {
    eprint("entry not found\n");
    return -1;
  }

  passwand_entry_t e;
  if (passwand_entry_new(&e, saved_main->main, options.space, options.key,
                         options.value, options.db.work_factor) != PW_OK) {
    eprint("failed to create new entry\n");
    return -1;
  }

  // cleanup the entry we are about to overwrite
  free(saved_entries[found_index].space);
  free(saved_entries[found_index].key);
  free(saved_entries[found_index].value);
  free(saved_entries[found_index].hmac);
  free(saved_entries[found_index].hmac_salt);
  free(saved_entries[found_index].salt);
  free(saved_entries[found_index].iv);

  // insert the updated entry at the start of the list, as we assume we will be
  // looking it up in the near future
  for (size_t i = found_index; i > 0; i--) {
    saved_entries[i] = saved_entries[i - 1];
  }
  saved_entries[0] = e;

  passwand_error_t err =
      passwand_export(options.db.path, saved_entries, saved_entry_len);
  if (err != PW_OK) {
    print("failed to export entries: %s\n", passwand_error(err));
    return -1;
  }

  return 0;
}

const command_t update = {
    .need_space = REQUIRED,
    .need_key = REQUIRED,
    .need_value = REQUIRED,
    .need_length = DISALLOWED,
    .access = LOCK_EX,
    .initialize = initialize,
    .loop_notify = loop_notify,
    .loop_condition = loop_condition,
    .loop_body = loop_body,
    .finalize = finalize,
};
