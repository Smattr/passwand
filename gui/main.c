#include "../common/argparse.h"
#include "../common/streq.h"
#include "gui.h"
#include <assert.h>
#include <fcntl.h>
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
// On macOS, assume we are being called by Automator that treats a non-zero
// exit status as something that warrants a further error dialog. Because
// we will have already told the user about the error, suppress Automator’s
// warning.
#define FAILURE_CODE EXIT_SUCCESS
#else
#define FAILURE_CODE EXIT_FAILURE
#endif

#define DIE(...)                                                               \
  do {                                                                         \
    if (mainpass != NULL) {                                                    \
      passwand_secure_free(mainpass, strlen(mainpass) + 1);                    \
    }                                                                          \
    char *msg;                                                                 \
    if (asprintf(&msg, __VA_ARGS__) >= 0) {                                    \
      show_error(msg);                                                         \
      free(msg);                                                               \
    }                                                                          \
    gui_deinit();                                                              \
    cleanup();                                                                 \
    exit(FAILURE_CODE);                                                        \
  } while (0)

static atomic_bool done;
static atomic_size_t entry_index;
static passwand_entry_t *entries;
static size_t entry_len;
static char *mainpass;
static char *found_value;
static size_t found_index;

static void cleanup_entry(passwand_entry_t *e) {
  free(e->space);
  free(e->key);
  free(e->value);
  free(e->hmac);
  free(e->hmac_salt);
  free(e->salt);
  free(e->iv);
}

static void cleanup(void) {
  for (size_t i = 0; i < entry_len; i++)
    cleanup_entry(&entries[i]);
  free(entries);
  free(options.db.path);
  free(options.space);
  free(options.key);
  free(options.value);
  for (size_t i = 0; i < options.chain_len; ++i)
    free(options.chain[i].path);
  free(options.chain);
}

static void check(void *state, const char *space, const char *key,
                  const char *value) {
  char **v = state;

  assert(options.space != NULL);
  assert(space != NULL);
  assert(options.key != NULL);
  assert(key != NULL);
  if (streq(options.space, space) && streq(options.key, key)) {
    assert(v != NULL);
    *v = passwand_secure_malloc(strlen(value) + 1);
    if (*v != NULL)
      strcpy(*v, value);
  }
}

static void *search(void *arg __attribute__((unused))) {

  char *v = NULL;

  for (;;) {

    if (done)
      break;

    // get the next entry to check
    size_t i = atomic_fetch_add(&entry_index, 1);
    if (i >= entry_len)
      break;

    passwand_error_t err = passwand_entry_do(mainpass, &entries[i], check, &v);
    if (err != PW_OK) {
      char *msg;
      if (asprintf(&msg, "error: %s", passwand_error(err)) >= 0)
        return msg;
      return NULL;
    }

    if (v != NULL) {
      // We found it!
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

/** Take a password entry from a chained database and consider it now the new
 * main password
 *
 * @param value The password to update the main password to
 */
static void process_chain_link(void *state __attribute__((unused)),
                               const char *space __attribute__((unused)),
                               const char *key __attribute__((unused)),
                               const char *value) {

  // assume we no longer need the main password
  assert(mainpass != NULL);
  passwand_secure_free(mainpass, strlen(mainpass) + 1);
  mainpass = NULL;

  // strdup() the replacement onto it
  mainpass = passwand_secure_malloc(strlen(value) + 1);
  if (mainpass != NULL)
    strcpy(mainpass, value);
}

int main(int argc, char **argv) {

  if (argc < 2 || streq(argv[1], "--help") || streq(argv[1], "-?")) {
    fprintf(stderr,
            "Passwand GUI, using %s for input and %s for output\n"
            "see `pw-cli --help` for more information\n",
            describe_input(), describe_output());
    cleanup();
    return EXIT_SUCCESS;
  }

  // Initialise the back end. We assume this initialisation is unaffected by any
  // of the command line options and thus can run before they are parsed.
  if (gui_init() != 0)
    return EXIT_FAILURE;

  if (parse(argc, argv) != 0) {
    cleanup();
    return EXIT_FAILURE;
  }

  if (options.length != 0)
    DIE("--length is not accepted by pw-gui");

  if (options.space == NULL)
    options.space = get_text("Passwand", "Name space?", NULL, false);
  if (options.space == NULL) {
    cleanup();
    return EXIT_SUCCESS;
  }

  if (options.key == NULL)
    options.key = get_text("Passwand", "Key?", "password", false);
  if (options.key == NULL) {
    cleanup();
    return EXIT_SUCCESS;
  }

  // how many chained databases to skip
  size_t chain_offset = 0;

  do {
    mainpass = get_text("Passwand", "Main passphrase?", NULL, true);
    if (mainpass == NULL) {
      cleanup();
      return EXIT_SUCCESS;
    }

    // if the user entered an empty string, they want to skip a chained
    // database
    if (streq(mainpass, "")) {
      passwand_secure_free(mainpass, strlen(mainpass) + 1);
      mainpass = NULL;

      ++chain_offset;

      if (chain_offset > options.chain_len)
        DIE("cannot bypass %zu chained databases when there are only %zu",
            chain_offset, options.chain_len);
    }
  } while (mainpass == NULL);

  flush_state();

  // process any chained databases
  for (size_t i = chain_offset; i < options.chain_len; ++i) {

    // lock database that we are about to access
    int fd = -1;
    if (access(options.chain[i].path, R_OK) == 0) {
      fd = open(options.chain[i].path, O_RDONLY);
      if (fd < 0)
        DIE("failed to open database");
      if (flock(fd, LOCK_SH | LOCK_NB) != 0)
        DIE("failed to lock database: %s", strerror(errno));
    }

    // import the database
    {
      passwand_error_t err =
          passwand_import(options.chain[i].path, &entries, &entry_len);
      if (err != PW_OK)
        DIE("failed to import database: %s", passwand_error(err));
    }

    if (entry_len != 1)
      DIE("chained database has more than one entry");

    entries[0].work_factor = options.chain[i].work_factor;

    // extract the password from this database to use as the new main password
    passwand_error_t err =
        passwand_entry_do(mainpass, &entries[0], process_chain_link, NULL);

    // discard this entry we no longer need
    cleanup_entry(&entries[0]);
    free(entries);
    entries = NULL;
    entry_len = 0;

    // did we fail above?
    if (err != PW_OK)
      DIE("failed to process chained database %s: %s", options.chain[i].path,
          passwand_error(err));
    if (mainpass == NULL)
      DIE("out of memory while processing chained database %s",
          options.chain[i].path);

    // unlock the database we no longer need
    (void)flock(fd, LOCK_UN);
    (void)close(fd);
  }

  assert(mainpass != NULL);

  // lock database that we are about to access
  if (access(options.db.path, R_OK) == 0) {
    int fd = open(options.db.path, O_RDONLY);
    if (fd < 0)
      DIE("failed to open database");
    if (flock(fd, LOCK_EX | LOCK_NB) != 0)
      DIE("failed to lock database: %s", strerror(errno));
  }

  // import the database
  passwand_error_t err = passwand_import(options.db.path, &entries, &entry_len);
  if (err != PW_OK)
    DIE("failed to import database: %s", passwand_error(err));

  for (size_t i = 0; i < entry_len; i++)
    entries[i].work_factor = options.db.work_factor;

  // we now are ready to search for the entry, but let us parallelise it across
  // as many cores as we have to speed it up

  assert(options.jobs >= 1);

  pthread_t *threads = calloc(options.jobs - 1, sizeof(pthread_t));
  if (threads == NULL)
    DIE("out of memory");

  // initialise and start threads
  for (size_t i = 0; i < options.jobs; i++) {

    if (i < options.jobs - 1) {
      int r = pthread_create(&threads[i], NULL, search, NULL);
      if (r != 0)
        DIE("failed to create thread %ld", i + 1);
    }
  }

  bool shown_error = false;

  // join the other threads in searching
  void *ret = search(NULL);
  if (ret != NULL) {
    show_error(ret);
    free(ret);
    shown_error = true;
  }

  // collect threads
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

  // we do not need the main password anymore
  assert(mainpass != NULL);
  passwand_secure_free(mainpass, strlen(mainpass) + 1);
  mainpass = NULL;

  free(threads);

  if (found_value == NULL && !shown_error)
    DIE("failed to find matching entry");

  if (shown_error) {
    if (found_value != NULL)
      passwand_secure_free(found_value, strlen(found_value) + 1);
    cleanup();
    return FAILURE_CODE;
  }

  for (size_t i = 0; i < strlen(found_value); i++) {
    if (!(supported_upper(found_value[i]) || supported_lower(found_value[i]))) {
      passwand_secure_free(found_value, strlen(found_value) + 1);
      DIE("unsupported character at index %zu in entry", i);
    }
  }

  int r = send_text(found_value);
  passwand_secure_free(found_value, strlen(found_value) + 1);

  if (r != 0) {
    cleanup();
    return FAILURE_CODE;
  }

  // Move the entry we just retrieved to the front of the list of entries to
  // make future look ups for it faster. The idea is that over time this will
  // result in something like a MRU ordering of entries. Note, we ignore
  // failures during exporting because this is not critical.
  assert(found_index != SIZE_MAX);
  assert(found_index < entry_len);
  if (found_index != 0) {
    passwand_entry_t found = entries[found_index];
    for (size_t i = found_index; i > 0; i--)
      entries[i] = entries[i - 1];
    entries[0] = found;
    (void)passwand_export(options.db.path, entries, entry_len);
  }

  // cleanup to make us Valgrind-free in successful runs
  cleanup();

  // reset the state of the allocator, freeing memory back to the operating
  // system, to pacify tools like Valgrind
  {
    int rc __attribute__((unused)) = passwand_secure_malloc_reset();
    assert(rc == 0 && "allocator leak in gui");
  }

  return EXIT_SUCCESS;
}
