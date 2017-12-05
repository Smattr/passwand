/* Implementation of the API described in gui.h using GTK 2/3. */

#include <assert.h>
#include "getenv.h"
#include <gtk/gtk.h>
#include "gui.h"
#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <X11/Xlib.h>

static bool inited;

static void init() {
    gtk_init(NULL, NULL);
    inited = true;
}

char *get_text(const char *title, const char *message, const char *initial, bool hidden) {

    assert(title != NULL);
    assert(message != NULL);

    if (!inited)
        init();

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

static void send_char(Display *display, Window window, char c) {

    assert(supported_upper(c) || supported_lower(c));
    assert(inited);

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

void flush_state(void) {
    /* Make sure we flush all GTK operations to clear remaining dialog windows. */
    while (gtk_events_pending())
        gtk_main_iteration();
}

int send_text(const char *text) {

    assert(text != NULL);

    if (!inited)
        init();

    /* Find the current display. */
    const char *display = getenv_("DISPLAY");
    if (display == NULL)
        display = ":0";
    Display *d = XOpenDisplay(display);
    if (d == NULL) {
        show_error("failed to open X11 display");
        return -1;
    }

    /* Find the active window. */
    Window win;
    int state;
    XGetInputFocus(d, &win, &state);
    if (win == None) {
        XCloseDisplay(d);
        show_error("no window focused");
        return -1;
    }

    for (size_t i = 0; i < strlen(text); i++) {
        assert(supported_upper(text[i]) || supported_lower(text[i]));
        send_char(d, win, text[i]);
    }

    XCloseDisplay(d);

    return 0;
}

void show_error(const char *fmt, ...) {

    if (!inited)
        init();

    va_list ap;
    va_start(ap, fmt);
    char *msg;
    int r = vasprintf(&msg, fmt, ap);
    va_end(ap);
    if (r < 0)
        return;
    GtkWidget *dialog = gtk_message_dialog_new(NULL, 0, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "%s", msg);
    free(msg);
    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
    gtk_widget_show_all(dialog);
    gtk_dialog_run(GTK_DIALOG(dialog));
}
