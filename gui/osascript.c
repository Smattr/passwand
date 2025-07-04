// Implementation of the gui.h API using osascript, the Open Scripting
// Architecture utility for MacOS.
//
// XXX: Shelling out to an interpreter that we then pipe commands into is a very
// odd way of building a GUI work flow. However, I cannot find any proper API
// Apple exposes to C programs. The only official answer seems to be “use
// Objective-C.” Given the fragility of this technique, we should exercise an
// above average level of paranoia in this code.

#include "../common/environ.h"
#include "../common/streq.h"
#include "gui.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <passwand/passwand.h>
#include <pthread.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
  pid_t pid;
  int in;
  int out;
} proc_t;

/// `pipe` that also sets close-on-exec
static int pipe_(int pipefd[2]) {
  assert(pipefd != NULL);

  // macOS does not have `pipe2`, so we need to fall back on `pipe`+`fcntl`.

  // create the pipe
  if (pipe(pipefd) < 0)
    return errno;

  // set close-on-exec
  for (size_t i = 0; i < 2; ++i) {
    const int flags = fcntl(pipefd[i], F_GETFD);
    if (fcntl(pipefd[i], F_SETFD, flags | FD_CLOEXEC) < 0) {
      const int err = errno;
      for (size_t j = 0; j < 2; ++j) {
        (void)close(pipefd[j]);
        pipefd[j] = -1;
      }
      return err;
    }
  }

  return 0;
}

static int osascript_pipe(proc_t *proc) {

  assert(proc != NULL);

  posix_spawn_file_actions_t actions;
  pid_t pid;
  int in[2] = {0};
  int out[2] = {0};
  int rc = 0;

  if ((rc = posix_spawn_file_actions_init(&actions)))
    return rc;

  if ((rc = pipe_(in)))
    goto done;

  if ((rc = pipe_(out)))
    goto done;

  // redirect stdin from the input pipe
  if ((rc = posix_spawn_file_actions_adddup2(&actions, in[0], STDIN_FILENO)))
    goto done;

  // redirect stdout to the output pipe
  if ((rc = posix_spawn_file_actions_adddup2(&actions, out[1], STDOUT_FILENO)))
    goto done;

  // Redirect stderr to /dev/null. You may want to comment this out if you are
  // debugging.
  if ((rc = posix_spawn_file_actions_addopen(
           &actions, STDERR_FILENO, "/dev/null", O_WRONLY,
           S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)))
    goto done;

  static char argv0[] = "osascript";
  static char *const argv[] = {argv0, NULL};
  if ((rc = posix_spawnp(&pid, "osascript", &actions, NULL, argv,
                         get_environ())))
    goto done;

  proc->pid = pid;
  proc->in = in[1];
  proc->out = out[0];

done:
  if (out[1] != 0)
    close(out[1]);
  if (rc != 0 && out[0] != 0)
    close(out[0]);
  if (rc != 0 && in[1] != 0)
    close(in[1]);
  if (in[0] != 0)
    close(in[0]);
  (void)posix_spawn_file_actions_destroy(&actions);
  return rc;
}

static int osascript(const struct iovec *iov, size_t iovcnt, char **out) {

  // Lock that we use to prevent multiple concurrent osascript tasks. It is OK
  // to run osascript multiple times, but the effect may confuse the user.
  static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

  assert(iov != NULL);
  assert(iovcnt > 0);

  if (out != NULL)
    *out = NULL;
  int rc = 0;

  int err __attribute__((unused)) = pthread_mutex_lock(&mutex);
  assert(err == 0);

  proc_t proc;
  if ((rc = osascript_pipe(&proc))) {
    err = pthread_mutex_unlock(&mutex);
    assert(err == 0);
    return rc;
  }

  if (writev(proc.in, iov, iovcnt) < 0)
    rc = errno;
  close(proc.in);

  char *buf = NULL;
  size_t size = 0;

  if (rc != 0)
    goto done;

  FILE *buffer = open_memstream(&buf, &size);
  if (buffer != NULL) {
    // open_memstream succeeded
    ssize_t r;
    do {
      char chunk[BUFSIZ];
      r = read(proc.out, chunk, sizeof(chunk));
      if (r > 0) {
        size_t w = fwrite(chunk, (size_t)r, 1, buffer);
        if (w == 0) // error
          r = -1;
      }
    } while (r > 0 || (r == -1 && errno == EINTR));

    fclose(buffer);

    if (r == -1) {
      // somewhere in the read loop we failed
      (void)passwand_erase(buf, size);
      free(buf);
      buf = NULL;
    }
  }

  int status;
  pid_t r;
  do {
    r = waitpid(proc.pid, &status, 0);
  } while (r == -1 && errno == EINTR);

  err = pthread_mutex_unlock(&mutex);
  assert(err == 0);

  if (WIFEXITED(status)) {
    if (WEXITSTATUS(status) == EXIT_SUCCESS) {
      if (out != NULL) {
        *out = buf;
        buf = NULL;
      }
      (void)passwand_erase(buf, size);
      free(buf);
      return rc;
    }
    rc = WEXITSTATUS(status);
  }

  // If we reached here, we failed. E.g. because the user clicked Cancel.
done:
  (void)passwand_erase(buf, size);
  free(buf);
  return rc;
}

// escape a string that is to be passed to osascript
static char *escape(const char *s) {

  assert(s != NULL);

  char *e = malloc(strlen(s) * 2 + 1);
  if (e == NULL)
    return NULL;

  for (size_t i = 0, j = 0;; i++, j++) {
    if (s[i] == '"' || s[i] == '\\')
      e[j++] = '\\';
    e[j] = s[i];
    if (s[i] == '\0')
      break;
  }

  return e;
}

#define IOV(str)                                                               \
  ((struct iovec){.iov_base = (void *)str, .iov_len = strlen(str)})

char *get_text(const char *title, const char *message, const char *initial,
               bool hidden) {

  assert(title != NULL);
  assert(message != NULL);

  char *t = escape(title);
  char *m = escape(message);
  char *i = initial == NULL ? NULL : escape(initial);

  if (t == NULL || m == NULL || (initial != NULL && i == NULL)) {
    free(i);
    free(m);
    free(t);
    show_error("failed to allocate escaping memory");
    return NULL;
  }

  struct iovec iov[] = {
      IOV("text returned of (display dialog \""),
      IOV(m),
      IOV("\" default answer \""),
      {.iov_base = NULL, .iov_len = 0}, // placeholder
      IOV("\" with title \""),
      IOV(t),
      IOV("\""),
      {.iov_base = NULL, .iov_len = 0}, // placeholder
      IOV(")"),
  };

  assert(iov[3].iov_base == NULL && iov[3].iov_len == 0);
  if (i != NULL)
    iov[3] = IOV(i);

  assert(iov[7].iov_base == NULL && iov[7].iov_len == 0);
  if (hidden)
    iov[7] = IOV(" with hidden answer");

  char *result = NULL;
  // ignore failure, as we will signal it by returning NULL
  (void)osascript(iov, sizeof(iov) / sizeof(iov[0]), &result);

  free(i);
  free(m);
  free(t);

  // we need to strip the tailing newline to avoid confusing our caller
  if (result != NULL && !streq(result, "")) {
    assert(result[strlen(result) - 1] == '\n');
    result[strlen(result) - 1] = '\0';
  }

  if (hidden && result != NULL) {
    char *const r = passwand_secure_malloc(strlen(result) + 1);
    if (r == NULL) {
      (void)passwand_erase(result, strlen(result) + 1);
      free(result);
      result = NULL;
      show_error("failed to allocate secure memory");
    } else {
      strcpy(r, result);
      (void)passwand_erase(result, strlen(result) + 1);
      free(result);
      result = r;
    }
  }

  return result;
}

const char *describe_input(void) { return "osascript"; }

int send_text(const char *text) {

  assert(text != NULL);

  char *t = escape(text);
  if (t == NULL) {
    show_error("failed to allocate escaping memory");
    return ENOMEM;
  }

  struct iovec iov[] = {
      IOV("tell application \"System Events\"\nkeystroke \""),
      IOV(t),
      IOV("\"\nend tell"),
  };

  int rc = osascript(iov, sizeof(iov) / sizeof(iov[0]), NULL);

  free(t);

  if (rc != 0) {
    char *msg = NULL;
    if (asprintf(&msg,
                 "failed to send text to the active program (code "
                 "%d); maybe it needs to be added to the Accessibility list in "
                 "Security & Privacy Settings",
                 rc) >= 0)
      show_error(msg);
    free(msg);
  }

  return rc;
}

const char *describe_output(void) { return "osascript"; }

void flush_state() { /* no-op for osascript */ }

void show_error(const char *message) {

  assert(message != NULL);

  bool m_needs_free = true;
  char *m = escape(message);
  if (m == NULL) {
    m = "failed to allocate escaping memory";
    m_needs_free = false;
  }

  struct iovec iov[] = {
      IOV("display dialog \""),
      IOV(m),
      IOV("\" with title \"Passwand\" buttons \"OK\" default button 1 with "
          "icon stop"),
  };

  (void)osascript(iov, sizeof(iov) / sizeof(iov[0]), NULL);

  if (m_needs_free)
    free(m);
}

int gui_init(void) {
  // nothing required
  return 0;
}

void gui_deinit(void) { /* nothing required */ }
