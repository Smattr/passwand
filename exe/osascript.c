/* Implementation of the gui.h API using osascript, the Open Scripting
 * Architecture utility for MacOS.
 *
 * XXX: Shelling out to an interpreter that we then pipe commands into is a very
 * odd way of building a GUI work flow. However, I can't find any proper API
 * Apple exposes to C programs. The only official answer seems to be "use
 * Objective-C". Given the fragility of this technique, we should exercise an
 * above average level of paranoia in this code.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include "gui.h"
#include <passwand/passwand.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __APPLE__
    #include <crt_externs.h>
#endif

static char **get_environ() {
#if __APPLE__
    /* Bizarrely Apple don't give programs a symbol for environ, but have an
     * indirect way of accessing it.
     */
    return *_NSGetEnviron();
#else
    return environ;
#endif
}

typedef struct {
    pid_t pid;
    int in;
    int out;
} proc_t;

static int osascript_pipe(proc_t *proc) {

    assert(proc != NULL);

    posix_spawn_file_actions_t actions;
    pid_t pid;
    int in[2] = { 0 };
    int out[2] = { 0 };
    int ret = -1;

    if (posix_spawn_file_actions_init(&actions) < 0)
        return -1;

    if (pipe(in) < 0)
        goto done;

    if (pipe(out) < 0)
        goto done;

    /* Close the FDs we don't need. */
    if (posix_spawn_file_actions_addclose(&actions, in[1]) < 0)
        goto done;
    if (posix_spawn_file_actions_addclose(&actions, out[0]) < 0)
        goto done;

    /* Redirect stdin from the input pipe. */
    if (posix_spawn_file_actions_adddup2(&actions, in[0], STDIN_FILENO) < 0)
        goto done;

    /* Redirect stdout to the output pipe. */
    if (posix_spawn_file_actions_adddup2(&actions, out[1], STDOUT_FILENO) < 0)
        goto done;

    /* Redirect stderr to /dev/null. You may want to comment this out if you are
     * debugging.
     */
    if (posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY,
      S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH) < 0)
        goto done;

    static char argv0[] = "osascript";
    static char *const argv[] = { argv0, NULL };
    if (posix_spawnp(&pid, "osascript", &actions, NULL, argv, get_environ()) != 0)
        goto done;

    ret = 0;
    proc->pid = pid;
    proc->in = in[1];
    proc->out = out[0];

done:
    if (out[1] != 0)
        close(out[1]);
    if (ret < 0 && out[0] != 0)
        close(out[0]);
    if (ret < 0 && in[1] != 0)
        close(in[1]);
    if (in[0] != 0)
        close(in[0]);
    (void)posix_spawn_file_actions_destroy(&actions);
    return ret;
}

static char *osascript(const struct iovec *iov, size_t iovcnt) {

    assert(iov != NULL);
    assert(iovcnt > 0);

    proc_t proc;
    if (osascript_pipe(&proc) < 0)
        return NULL;

    (void)writev(proc.in, iov, iovcnt);
    close(proc.in);

    char *buf = NULL;
    size_t size;
    FILE *buffer = open_memstream(&buf, &size);
    if (buffer != NULL) {
        /* open_memstream succeeded. */
        ssize_t r;
        do {
            char chunk[1024];
            r = read(proc.out, chunk, sizeof(chunk));
            if (r > 0) {
                size_t w = fwrite(chunk, (size_t)r, 1, buffer);
                if (w == 0) /* Error */
                    r = -1;
            }
        } while (r > 0 || (r == -1 && errno == EINTR));

        fclose(buffer);

        if (r == -1) {
            /* Somewhere in the read loop we failed. */
            free(buf);
            buf = NULL;
        }
    }

    int status;
    (void)waitpid(proc.pid, &status, 0);

    return buf;
}

#define IOV(str) ((struct iovec){ .iov_base = (void*)str, .iov_len = strlen(str) })

char *get_text(const char *title, const char *message, const char *initial, bool hidden) {

    assert(title != NULL);
    assert(message != NULL);

    struct iovec iov[] = {
        IOV("text returned of (display dialog \""),
        IOV(message),
        IOV("\" default answer \""),
        { .iov_base = NULL, .iov_len = 0 }, // placeholder
        IOV("\" with title \""),
        IOV(title),
        IOV("\""),
        { .iov_base = NULL, .iov_len = 0 }, // placeholder
        IOV(")"),
    };

    assert(iov[3].iov_base == NULL && iov[3].iov_len == 0);
    if (initial != NULL)
        iov[3] = IOV(initial);

    assert(iov[7].iov_base == NULL && iov[7].iov_len == 0);
    if (hidden)
        iov[7] = IOV(" with hidden answer");

    char *result = osascript(iov, sizeof(iov) / sizeof(iov[0]));

    /* We need to strip the tailing newline to avoid confusing our caller. */
    if (result != NULL) {
        if (strcmp(result, "") == 0) {
            free(result);
            result = NULL;
        } else {
            assert(result[strlen(result) - 1] == '\n');
            result[strlen(result) - 1] = '\0';
        }
    }

    if (hidden && result != NULL) {
        char *r;
        if (passwand_secure_malloc((void**)&r, strlen(result) + 1) != PW_OK) {
            free(result);
            result = NULL;
        } else {
            strcpy(r, result);
            free(result);
            result = r;
        }
    }

    return result;
}

int send_text(const char *text) {

    assert(text != NULL);

    struct iovec iov[] = {
        IOV("tell application \"System Events\"\nkeystroke \""),
        IOV(text),
        IOV("\"\nend tell"),
    };

    char *result = osascript(iov, sizeof(iov) / sizeof(iov[0]));
    free(result);

    return result == NULL ? -1 : 0;
}

void flush_state() {
    /* no-op for osascript */
}

void show_error(const char *message) {

    assert(message != NULL);

    struct iovec iov[] = {
        IOV("display dialog \""),
        IOV(message),
        IOV("\" with title \"Passwand\" buttons \"OK\" default button 1 with icon stop"),
    };

    char *result = osascript(iov, sizeof(iov) / sizeof(iov[0]));
    free(result);
}
