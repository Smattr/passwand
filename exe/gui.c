#include "argparse.h"
#include <assert.h>
#include <gtk/gtk.h>
#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <X11/Xlib.h>

#define DIE(args...) \
    do { \
        GtkWidget *dialog = gtk_message_dialog_new(NULL, 0, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, ## args); \
        gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK); \
        gtk_widget_show_all(dialog); \
        gtk_dialog_run(GTK_DIALOG(dialog)); \
        exit(EXIT_FAILURE); \
    } while (0)

char *get_text(const char *title, const char *message, const char *initial, bool hidden) {

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
        const char *text = strdup(gtk_entry_get_text(GTK_ENTRY(textbox)));
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

static int send_char(Display *display, Window window, char c) {

    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
           c == ' ' || c == '_'))
        return -1;

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
        .state = ((c >= 'A' && c <= 'Z') || c == '_') ? ShiftMask : 0,
        .keycode = XKeysymToKeycode(display, c),
    };
    XSendEvent(display, window, True, KeyPressMask, (XEvent*)&e);
    e.type = KeyRelease;
    XSendEvent(display, window, True, KeyReleaseMask, (XEvent*)&e);

    return 0;
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

    void autoclear(void *p) {
        assert(p != NULL);
        char **s = p;
        if (*s != NULL)
            passwand_secure_free(*s, strlen(*s));
    }
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
    unsigned entry_len;
    passwand_error_t err = passwand_import(options.data, &entries, &entry_len);
    if (err != PW_OK)
        DIE("failed to import database: %s", passwand_error(err));

    /* State for the search we'll perform. */
    typedef struct {
        const char *space;
        const char *key;
        char *value;
    } state_t;

    void search(void *state, const char *space, const char *key, const char *value) {
        state_t *st = state;
        if (strcmp(st->space, space) == 0 && strcmp(st->key, key) == 0) {
            if (passwand_secure_malloc((void**)&st->value, strlen(value) + 1) == PW_OK)
                strcpy(st->value, value);
        }
    }

    state_t st = {
        .space = space,
        .key = key,
        .value = NULL,
    };

    for (unsigned i = 0; i < entry_len && st.value == NULL; i++) {
        entries[i].work_factor = options.work_factor;
        err = passwand_entry_do(master, &entries[i], search, &st);
        if (err != PW_OK)
            DIE("failed to decrypt entry %u: %s", i, passwand_error(err));
    }

    if (st.value == NULL)
        DIE("failed to find matching entry");
    char *clearer __attribute__((cleanup(autoclear))) = st.value;

    /* Find the current display. */
    char *display = secure_getenv("DISPLAY");
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

    for (unsigned i = 0; i < strlen(st.value); i++) {
        if (send_char(d, win, st.value[i]) != 0)
            DIE("failed to send character \"%c\"", st.value[i]);
    }

    XCloseDisplay(d);

    return EXIT_SUCCESS;
}
