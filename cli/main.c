#include "../common/argparse.h"
#include "../common/privilege.h"
#include "change-main.h"
#include "check.h"
#include "cli.h"
#include "delete.h"
#include "generate.h"
#include "get.h"
#include "help.h"
#include "list.h"
#include "print.h"
#include "set.h"
#include "update.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <passwand/passwand.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <termios.h>
#include <unistd.h>

static const struct {
  const char *name;
  const command_t *action;
} COMMANDS[] = {
    {"change-main", &change_main},
    {"check", &check},
    {"delete", &delete},
    {"generate", &generate},
    {"get", &get},
    {"list", &list},
    {"set", &set},
    {"update", &update},
};

static const command_t *command_for(const char *name) {
  for (size_t i = 0; i < sizeof(COMMANDS) / sizeof(COMMANDS[0]); i++) {
    if (strcmp(name, COMMANDS[i].name) == 0)
      return COMMANDS[i].action;
  }
  return NULL;
}

main_t *getpassword(const char *prompt) {

  static const size_t EXPECTED_PAGE_SIZE = 4096;

  // Initial allocation size. We only support allocating a page, so clamp it
  // at the expected page size if necessary.
  size_t size = BUFSIZ > EXPECTED_PAGE_SIZE ? EXPECTED_PAGE_SIZE : BUFSIZ;

  char *m;
  if (passwand_secure_malloc((void **)&m, size) != 0) {
    eprint("failed to allocate secure memory\n");
    return NULL;
  }

  // open the controlling TTY that we will use to prompt the user, so they see
  // it even when piping pw-cli into something else
  FILE *devtty = fopen("/dev/tty", "w");
  if (devtty == NULL) {
    eprint("failed to open /dev/tty: %s\n", strerror(errno));
    passwand_secure_free(m, size);
    return NULL;
  }

  fprintf(devtty, "%s", prompt == NULL ? "main password: " : prompt);
  fflush(devtty);
  fclose(devtty);

  // similarly use the controlling TTY for reading the password to ensure it
  // comes from the user, not something piped into pw-cli
  devtty = fopen("/dev/tty", "r");
  if (devtty == NULL) {
    eprint("failed to open /dev/tty: %s\n", strerror(errno));
    passwand_secure_free(m, size);
    return NULL;
  }

  struct termios old;
  if (tcgetattr(fileno(devtty), &old) != 0) {
    eprint("failed to get /dev/tty attributes: %s\n", strerror(errno));
    fclose(devtty);
    passwand_secure_free(m, size);
    return NULL;
  }
  struct termios new = old;
  cfmakeraw(&new);
  if (tcsetattr(fileno(devtty), 0, &new) != 0) {
    eprint("failed to set /dev/tty attributes: %s\n", strerror(errno));
    fclose(devtty);
    passwand_secure_free(m, size);
    return NULL;
  }

  size_t index = 0;
  for (;;) {
    int c = getc(devtty);

    if (c == EOF) {
      eprint("truncated input\n");
      tcsetattr(fileno(devtty), 0, &old);
      fclose(devtty);
      passwand_secure_free(m, size);
      return NULL;
    }

    if (c == '\n' || c == '\r' || c == '\f')
      break;

    m[index] = c;
    index++;
    if (index >= size) {
      size_t new_size = size + BUFSIZ;
      // if we are increasing our allocation to more than one page, first clamp
      // to one page for the reasons described above
      if (size < EXPECTED_PAGE_SIZE && new_size > EXPECTED_PAGE_SIZE)
        new_size = EXPECTED_PAGE_SIZE;
      char *n;
      if (passwand_secure_malloc((void **)&n, new_size) != 0) {
        eprint("failed to reallocate secure memory\n");
        tcsetattr(fileno(devtty), 0, &old);
        fclose(devtty);
        passwand_secure_free(m, size);
        return NULL;
      }
      strncpy(n, m, size);
      passwand_secure_free(m, size);
      m = n;
      size = new_size;
    }
  }

  tcsetattr(fileno(devtty), 0, &old);
  fclose(devtty);

  // newline for feedback to the user that they hit enter, but ignore failure
  // because this is non-critical
  devtty = fopen("/dev/tty", "w");
  if (devtty != NULL) {
    fprintf(devtty, "\n");
    fflush(devtty);
    fclose(devtty);
  }

  m[index] = '\0';

  main_t *mainpass;
  if (passwand_secure_malloc((void **)&mainpass, sizeof(*mainpass)) != 0) {
    eprint("failed to reallocate secure memory\n");
    passwand_secure_free(m, size);
    return NULL;
  }
  mainpass->main = m;
  mainpass->main_len = size;

  return mainpass;
}

void discard_main(main_t *m) {
  if (m == NULL)
    return;
  passwand_secure_free(m->main, m->main_len);
  passwand_secure_free(m, sizeof(*m));
}

static void discard_entries(passwand_entry_t **entries, size_t *entry_len) {
  for (size_t i = 0; i < *entry_len; i++) {
    free((*entries)[i].space);
    free((*entries)[i].key);
    free((*entries)[i].value);
    free((*entries)[i].hmac);
    free((*entries)[i].hmac_salt);
    free((*entries)[i].salt);
    free((*entries)[i].iv);
  }
  free(*entries);

  *entries = NULL;
  *entry_len = 0;
}

// juggle the calling convention to a function for processing an entry that does
// not need the state parameter
static void entry_trampoline(void *state, const char *space, const char *key,
                             const char *value) {
  void (*f)(const char *, const char *, const char *) = state;
  f(space, key, value);
}

typedef struct {
  atomic_size_t *index;
  passwand_entry_t *entries;
  size_t entry_len;
  const char *main;

  const command_t *command;

  passwand_error_t error;
  size_t error_index;

  bool created;

} thread_state_t;

static void *thread_loop(void *arg) {
  assert(arg != NULL);

  thread_state_t *ts = arg;
  assert(ts->command != NULL);
  const command_t *command = ts->command;

  for (;;) {

    size_t index = atomic_fetch_add(ts->index, 1);
    if (index >= ts->entry_len)
      break;

    if (command->loop_notify != NULL)
      command->loop_notify(index);

    if (command->loop_condition != NULL && !command->loop_condition())
      break;

    if (command->loop_body != NULL) {
      passwand_error_t err = passwand_entry_do(
          ts->main, &ts->entries[index], entry_trampoline, command->loop_body);
      if (err != PW_OK) {
        ts->error = err;
        ts->error_index = index;
        return (void *)-1;
      }
    }
  }
  return NULL;
}

/** Take a password entry from a chained database and consider it now the new
 * main password
 *
 * @param state Pointer to the preivous `main_t` main password structure
 * @param value The password to update the main password to
 */
static void process_chain_link(void *state,
                               const char *space __attribute__((unused)),
                               const char *key __attribute__((unused)),
                               const char *value) {

  main_t *m = state;
  assert(m != NULL);

  // we know we are only processing a single entry, so we can discard the main
  // password that is no longer needed
  passwand_secure_free(m->main, m->main_len);
  memset(m, 0, sizeof(*m));

  // `strdup` this next chained password into it
  if (passwand_secure_malloc((void**)&m->main, strlen(value) + 1) == PW_OK) {
    assert(m->main != NULL);
    strcpy(m->main, value);
    m->main_len = strlen(value) + 1;
  }
}

int main(int argc, char **argv) {

  // we need to make a network call if we are checking a password
  bool need_network = argc >= 2 && strcmp(argv[1], "check") == 0;

  if (drop_privileges(need_network) != 0) {
    eprint("privilege downgrade failed\n");
    return EXIT_FAILURE;
  }

  if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-?") == 0)
    help();

  main_t *mainpass = NULL;
  passwand_entry_t *entries = NULL;
  size_t entry_len = 0;
  const command_t *command = NULL;
  bool command_initialized = false;
  thread_state_t *tses = NULL;
  pthread_t *threads = NULL;
  int ret = EXIT_FAILURE;
  unsigned errors = 0;

  // figure out which command to run
  command = command_for(argv[1]);
  if (command == NULL) {
    eprint("invalid action: %s\n", argv[1]);
    goto done;
  }

  if (parse(argc - 1, argv + 1) != 0)
    goto done;

    // validate flags
#define HANDLE(field)                                                          \
  do {                                                                         \
    if (command->need_##field == REQUIRED && options.field == NULL) {          \
      eprint("missing required argument --" #field "\n");                      \
      goto done;                                                               \
    } else if (command->need_##field == DISALLOWED && options.field != NULL) { \
      eprint("irrelevant argument --" #field "\n");                            \
      goto done;                                                               \
    }                                                                          \
  } while (0)
  HANDLE(space);
  HANDLE(key);
  HANDLE(value);
#undef HANDLE
  if (command->need_length == REQUIRED && options.length == 0) {
    eprint("missing required argument --length\n");
    goto done;
  } else if (command->need_length == DISALLOWED && options.length != 0) {
    eprint("irrelevant argument --length\n");
    goto done;
  }

  // process any chained databases
  for (size_t i = 0; i < options.chain_len; ++i) {

    // lock database that we are about to access
    int fd = -1;
    if (access(options.chain[i].path, R_OK) == 0) {
      fd = open(options.chain[i].path, O_RDONLY);
      if (fd < 0) {
        eprint("failed to open database\n");
        goto done;
      }
      if (flock(fd, LOCK_SH | LOCK_NB) != 0) {
        eprint("failed to lock database: %s\n", strerror(errno));
        goto done;
      }
    }

    // import the database
    {
      passwand_error_t err =
          passwand_import(options.chain[i].path, &entries, &entry_len);
      if (err != PW_OK) {
        eprint("failed to import database: %s\n", passwand_error(err));
        goto done;
      }
    }

    if (entry_len != 1) {
      eprint("chained database has more than one entry\n");
      goto done;
    }

    entries[0].work_factor = options.chain[i].work_factor;

    // if we do not have the password from a previous chain entry, ask the user
    // for the password to this chain link
    if (mainpass == NULL) {
      mainpass = getpassword(NULL);
      if (mainpass == NULL) {
        eprint("failed to read main password\n");
        goto done;
      } else if (strcmp(mainpass->main, "") == 0) {
        // the user wants to bypass this chain link
        discard_main(mainpass);
        mainpass = NULL;
        discard_entries(&entries, &entry_len);
        continue;
      }
    }

    // extract the password from this database to use as the new main password
    assert(mainpass != NULL);
    assert(mainpass->main != NULL);
    assert(strcmp(mainpass->main, "") != 0);
    passwand_error_t err =
        passwand_entry_do(mainpass->main, &entries[0], process_chain_link, mainpass);

    // discard this entry we no longer need
    discard_entries(&entries, &entry_len);

    // did we fail above?
    if (err != PW_OK) {
      eprint("failed to process chained database %s: %s\n", options.chain[i].path,
          passwand_error(err));
      goto done;
    }
    if (mainpass->main == NULL) {
      eprint("out of memory while processing chained database %s\n",
          options.chain[i].path);
      goto done;
    }

    // unlock the database we no longer need
    (void)flock(fd, LOCK_UN);
    (void)close(fd);
  }

  // take a lock on the database if it exists
  if (access(options.db.path, R_OK) == 0) {
    int fd = open(options.db.path, O_RDONLY);
    if (fd >= 0) {
      if (flock(fd, command->access | LOCK_NB) != 0) {
        eprint("failed to lock database: %s\n", strerror(errno));
        goto done;
      }
    }
  }

  if (access(options.db.path, F_OK) == 0) {
    passwand_error_t err =
        passwand_import(options.db.path, &entries, &entry_len);
    if (err != PW_OK) {
      eprint("failed to load database: %s\n", passwand_error(err));
      goto done;
    }
  }

  for (size_t i = 0; i < entry_len; i++)
    entries[i].work_factor = options.db.work_factor;

  // if we did not get a main password from a previous chained database, ask for
  // one now
  if (mainpass == NULL) {
    mainpass = getpassword(NULL);
    if (mainpass == NULL) {
      eprint("failed to read main password\n");
      goto done;
    }
  } else {
    assert(mainpass->main != NULL);
  }

  // setup command
  assert(command->initialize != NULL);
  int r = command->initialize(mainpass, entries, entry_len);
  if (r != 0)
    goto done;
  command_initialized = true;

  // allocate thread data
  tses = calloc(options.jobs, sizeof(tses[0]));
  if (tses == NULL) {
    eprint("out of memory\n");
    goto done;
  }

  // setup thread data
  atomic_size_t index = 0;
  for (size_t i = 0; i < options.jobs; i++) {
    tses[i].index = &index;
    tses[i].entries = entries;
    tses[i].entry_len = entry_len;
    tses[i].main = mainpass->main;
    tses[i].command = command;
    tses[i].error = PW_OK;
    tses[i].error_index = SIZE_MAX;
    tses[i].created = false;
  }

  // allocate threads
  assert(options.jobs >= 1);
  threads = calloc(options.jobs - 1, sizeof(threads[0]));
  if (threads == NULL) {
    eprint("out of memory\n");
    goto done;
  }

  // start threads
  for (size_t i = 1; i < options.jobs; i++) {
    r = pthread_create(&threads[i - 1], NULL, thread_loop, &tses[i]);
    if (r == 0) {
      tses[i].created = true;
    } else {
      eprint("warning: failed to create thread %zu\n", i);
    }
  }

  // join the other threads
  r = (int)(intptr_t)thread_loop(&tses[0]);
  if (r != 0) {
    eprint("failed to handle entry %zu: %s\n", tses[0].error_index,
           passwand_error(tses[0].error));
    errors++;
  }

  // collect the secondary threads
  for (size_t i = 1; i < options.jobs; i++) {
    if (tses[i].created) {
      void *retu;
      r = pthread_join(threads[i - 1], &retu);
      if (r != 0) {
        eprint("failed to join thread %zu\n", i);
        errors++;
      } else {
        if ((int)(intptr_t)retu != 0) {
          eprint("failed to handle entry %zu: %s\n", tses[i].error_index,
                 passwand_error(tses[i].error));
          errors++;
        }
      }
    }
  }

  ret = errors > 0 ? EXIT_FAILURE : EXIT_SUCCESS;

done:
  free(threads);
  free(tses);
  if (command_initialized && command->finalize != NULL) {
    r = command->finalize();
    if (r != 0)
      ret = EXIT_FAILURE;
  }
  discard_main(mainpass);
  discard_entries(&entries, &entry_len);

  free(options.db.path);
  free(options.space);
  free(options.key);
  free(options.value);
  for (size_t i = 0; i < options.chain_len; ++i)
    free(options.chain[i].path);
  free(options.chain);

  // reset the state of the allocator, freeing memory back to the operating
  // system, to pacify tools like Valgrind
  {
    int rc __attribute__((unused)) = passwand_secure_malloc_reset();
    assert(rc == 0 && "allocator leak in cli");
  }

  return ret;
}
