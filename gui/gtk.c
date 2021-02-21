/* Implementation of the API described in gui.h using GTK 2/3. */

#include "../common/getenv.h"
#include "gui.h"
#include <X11/Xlib.h>
#include <assert.h>
#include <gtk/gtk.h>
#include <passwand/passwand.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A lock to ensure we prevent multiple concurrent calls to GTK or X11 APIs. */
static pthread_mutex_t gtk_lock = PTHREAD_MUTEX_INITIALIZER;

static bool inited;

static void init() {
  gtk_init(NULL, NULL);
  inited = true;
}

/* The inner logic of `show_error`. This function assumes the caller has already
 * taken `gtk_lock`.
 */
static void show_error_core(const char *message) {
  GtkWidget *dialog = gtk_message_dialog_new(NULL, 0, GTK_MESSAGE_ERROR,
                                             GTK_BUTTONS_OK, "%s", message);
  gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
  gtk_widget_show_all(dialog);
  gtk_dialog_run(GTK_DIALOG(dialog));
}

char *get_text(const char *title, const char *message, const char *initial,
               bool hidden) {

  assert(title != NULL);
  assert(message != NULL);

  int err __attribute__((unused)) = pthread_mutex_lock(&gtk_lock);
  assert(err == 0);

  if (!inited)
    init();

  /* Create dialog box. */
  GtkWidget *dialog =
      gtk_dialog_new_with_buttons(title, NULL, 0, "OK", GTK_RESPONSE_OK,
                                  "Cancel", GTK_RESPONSE_CANCEL, NULL);
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
      if (passwand_secure_malloc((void **)&r, strlen(text) + 1) != PW_OK) {
        r = NULL;
        show_error_core("failed to allocate secure memory");
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

  err = pthread_mutex_unlock(&gtk_lock);
  assert(err == 0);

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
  XSendEvent(display, window, True, KeyPressMask, (XEvent *)&e);
  e.type = KeyRelease;
  XSendEvent(display, window, True, KeyReleaseMask, (XEvent *)&e);
}

void flush_state(void) {

  int err __attribute__((unused)) = pthread_mutex_lock(&gtk_lock);
  assert(err == 0);

  /* Make sure we flush all GTK operations to clear remaining dialog windows. */
  while (gtk_events_pending())
    gtk_main_iteration();

  err = pthread_mutex_unlock(&gtk_lock);
  assert(err == 0);
}

int send_text(const char *text) {

  assert(text != NULL);

  int err __attribute__((unused)) = pthread_mutex_lock(&gtk_lock);
  assert(err == 0);

  int ret = -1;

  if (!inited)
    init();

  /* Find the current display. */
  const char *display = getenv_("DISPLAY");
  if (display == NULL)
    display = ":0";
  Display *d = XOpenDisplay(display);
  if (d == NULL) {
    show_error_core("failed to open X11 display");
    goto done;
  }

  /* Find the active window. */
  Window win;
  int state;
  XGetInputFocus(d, &win, &state);
  if (win == None) {
    show_error_core("no window focused");
    goto done;
  }

  for (size_t i = 0; i < strlen(text); i++) {
    assert(supported_upper(text[i]) || supported_lower(text[i]));
    send_char(d, win, text[i]);
  }

  ret = 0;

done:
  XCloseDisplay(d);
  err = pthread_mutex_unlock(&gtk_lock);
  assert(err == 0);
  return ret;
}

void show_error(const char *message) {

  int err __attribute__((unused)) = pthread_mutex_lock(&gtk_lock);
  assert(err == 0);

  if (!inited)
    init();

  show_error_core(message);

  err = pthread_mutex_unlock(&gtk_lock);
  assert(err == 0);
}
