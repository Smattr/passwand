#include "argparse.h"
#include <assert.h>
#include "getenv.h"
#include <gtk/gtk.h>
#include <passwand/passwand.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <X11/Xlib.h>

#define DIE(args...) \
    do { \
        GtkWidget *dialog = gtk_message_dialog_new(NULL, 0, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, ## args); \
        gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK); \
        gtk_widget_show_all(dialog); \
        gtk_dialog_run(GTK_DIALOG(dialog)); \
        exit(EXIT_FAILURE); \
    } while (0)

static char *get_text(const char *title, const char *message, const char *initial, bool hidden) {

    assert(title != NULL);
    assert(message != NULL);

    /* Create dialog box. */
    GtkWidget *dialog = gtk_dialog_new_with_buttons(title, NULL, 0, "OK", GTK_RESPONSE_OK, "Cancel",
        GTK_RESPONSE_CANCEL, NULL);
    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);

    /* Add the text prompt. */
    GtkWidget *label = gtk_label_new(message);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_container_add(GTK_CONTAINER(content), label);

    /* Add the input field. */
    GtkWidget *textbox = gtk_entry_new();
    gtk_entry_set_activates_default(GTK_ENTRY(textbox), true);
    if (initial != NULL)
        gtk_entry_set_text(GTK_ENTRY(textbox), initial);
    if (hidden)
        gtk_entry_set_visibility(GTK_ENTRY(textbox), false);
    gtk_container_add(GTK_CONTAINER(content), textbox);

    /* Display the dialog. */
    gtk_widget_show_all(dialog);
    gint result = gtk_dialog_run(GTK_DIALOG(dialog));

    char *r;
    if (result == GTK_RESPONSE_OK) {
        const char *text = gtk_entry_get_text(GTK_ENTRY(textbox));
        if (hidden) {
            if (passwand_secure_malloc((void**)&r, strlen(text) + 1) != PW_OK) {
                r = NULL;
            } else {
                strcpy(r, text);
            }
        } else {
            r = strdup(text);
        }
    } else {
        /* Cancel or dialog was closed. */
        r = NULL;
    }

    gtk_widget_destroy(dialog);

    return r;
}

static bool supported_lower(char c) {
    switch (c) {
        case 'a' ... 'z':
        case '`':
        case '0' ... '9':
        case '-':
        case '=':
        case '[':
        case ']':
        case '\\':
        case ';':
        case '\'':
        case ',':
        case '.':
        case '/':
            return true;
    }
    return false;
}

static bool supported_upper(char c) {
    switch (c) {
        case 'A' ... 'Z':
        case '~':
        case '!':
        case '@':
        case '#':
        case '$':
        case '%':
        case '^':
        case '&':
        case '*':
        case '(':
        case ')':
        case '_':
        case '+':
        case '{':
        case '}':
        case '|':
        case ':':
        case '"':
        case '<':
        case '>':
        case '?':
            return true;
    }
    return false;
}

static void send_char(Display *display, Window window, char c) {

    assert(supported_upper(c) || supported_lower(c));

    XKeyEvent e = {
        .display = display,
        .window = window,
        .root = RootWindow(display, DefaultScreen(display)),
        .subwindow = None,
        .time = CurrentTime,
        .x = 1,
        .y = 1,
        .x_root = 1,
        .y_root = 1,
        .same_screen = True,
        .type = KeyPress,
        .state = supported_upper(c) ? ShiftMask : 0,
        .keycode = XKeysymToKeycode(display, c),
    };
    XSendEvent(display, window, True, KeyPressMask, (XEvent*)&e);
    e.type = KeyRelease;
    XSendEvent(display, window, True, KeyReleaseMask, (XEvent*)&e);
}

typedef struct {
    atomic_bool *done;
    atomic_size_t *index;
    const passwand_entry_t *entries;
    size_t entry_len;
    const char *master;
    const char *space;
    const char *key;

    const char *err_message;
} thread_state_t;

/* State for the search we'll perform. */
typedef struct {
    const char *space;
    const char *key;
    char *value;
} check_state_t;

static void check(void *state, const char *space, const char *key, const char *value) {
    check_state_t *st = state;
    if (strcmp(st->space, space) == 0 && strcmp(st->key, key) == 0) {
        if (passwand_secure_malloc((void**)&st->value, strlen(value) + 1) == PW_OK)
            strcpy(st->value, value);
    }
}

static void *search(void *arg) {
    assert(arg != NULL);

    thread_state_t *ts = arg;
    assert(ts->done != NULL);
    assert(ts->index != NULL);
    assert(ts->entries != NULL);
    assert(ts->master != NULL);
    assert(ts->space != NULL);
    assert(ts->key != NULL);
    assert(ts->err_message == NULL);

    check_state_t st = {
        .space = ts->space,
        .key = ts->key,
    };

    for (;;) {

        if (atomic_load(ts->done))
            break;

        /* Get the next entry to check */
        size_t index = atomic_fetch_add(ts->index, 1);
        if (index >= ts->entry_len)
            break;

        passwand_error_t err = passwand_entry_do(ts->master, &ts->entries[index], check, &st);
        if (err != PW_OK) {
            ts->err_message = passwand_error(err);
            return (void*)-1;
        }

        if (st.value != NULL) {
            /* We found it! */
            atomic_store(ts->done, true);
            return st.value;
        }
    }

    return NULL;
}

static void autoclear(void *p) {
    assert(p != NULL);
    char **s = p;
    if (*s != NULL)
        passwand_secure_free(*s, strlen(*s));
}

int main(int argc, char **argv) {

    gtk_init(&argc, &argv);

    options_t options;
    if (parse(argc, argv, &options) != 0)
        return EXIT_FAILURE;

    char *space;
    if (options.space != NULL)
        space = options.space;
    else
        space = get_text("Passwand", "Name space?", NULL, false);
    if (space == NULL)
        return EXIT_FAILURE;

    char *key;
    if (options.key != NULL)
        key = options.key;
    else
        key = get_text("Passwand", "Key?", "password", false);
    if (key == NULL)
        return EXIT_FAILURE;

    char *master __attribute__((cleanup(autoclear))) = get_text("Passwand", "Master passphrase?", NULL, true);
    if (master == NULL)
        return EXIT_FAILURE;

    /* Make sure we flush all GTK operations so we don't detect ourselves as the active window
     * later.
     */
    while (gtk_events_pending())
        gtk_main_iteration();

    /* Import the database. */
    passwand_entry_t *entries;
    size_t entry_len;
    passwand_error_t err = passwand_import(options.data, &entries, &entry_len);
    if (err != PW_OK)
        DIE("failed to import database: %s", passwand_error(err));

    for (size_t i = 0; i < entry_len; i++)
        entries[i].work_factor = options.work_factor;

    /* We now are ready to search for the entry, but let's parallelise it across as many cores as
     * we have to speed it up.
     */

    char *value = NULL;

    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    assert(cpus >= 1);

    thread_state_t *tses = calloc(cpus, sizeof(thread_state_t));
    if (tses == NULL)
        DIE("out of memory");

    pthread_t *threads = calloc(cpus - 1, sizeof(pthread_t));
    if (threads == NULL)
        DIE("out of memory");

    atomic_bool done = false;
    atomic_size_t index = 0;

    /* Initialise and start threads. */
    for (long i = 0; i < cpus; i++) {
        tses[i].done = &done;
        tses[i].index = &index;
        tses[i].entries = entries;
        tses[i].entry_len = entry_len;
        tses[i].master = master;
        tses[i].space = space;
        tses[i].key = key;

        if (i < cpus - 1) {
            int r = pthread_create(&threads[i], NULL, search, &tses[i]);
            if (r != 0)
                DIE("failed to create thread %ld", i + 1);
        }
    }

    /* Join the other threads in searching. */
    void *ret = search(&tses[cpus - 1]);
    if (ret == (void*)-1) {
        assert(tses[cpus - 1].err_message != NULL);
        DIE("error: %s", tses[cpus - 1].err_message);
    } else if (ret != NULL) {
        value = ret;
    }

    /* Collect threads. */
    for (long i = 0; i < cpus - 1; i++) {
        int r = pthread_join(threads[i], &ret);
        if (r != 0)
            DIE("failed to join thread %ld", i + 1);
        if (ret == (void*)-1) {
            assert(tses[i].err_message != NULL);
            DIE("error: %s", tses[i].err_message);
        } else if (ret != NULL) {
            assert(value == NULL && "multiple matching entries found");
            value = ret;
        }
    }

    free(threads);
    free(tses);

    if (value == NULL)
        DIE("failed to find matching entry");
    char *clearer __attribute__((unused, cleanup(autoclear))) = value;

    /* Find the current display. */
    const char *display = getenv_("DISPLAY");
    if (display == NULL)
        display = ":0";
    Display *d = XOpenDisplay(display);
    if (d == NULL)
        DIE("failed to open X11 display");

    /* Find the active window. */
    Window win;
    int state;
    XGetInputFocus(d, &win, &state);
    if (win == None)
        DIE("no window focused");

    for (size_t i = 0; i < strlen(value); i++) {
        if (!(supported_upper(value[i]) || supported_lower(value[i])))
            DIE("unsupported character at index %zu in entry", i);
    }

    for (size_t i = 0; i < strlen(value); i++)
        send_char(d, win, value[i]);

    XCloseDisplay(d);

    return EXIT_SUCCESS;
}
