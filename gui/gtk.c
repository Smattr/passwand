// implementation of part of the API described in gui.h using GTK 2/3

#include "gtk.h"
#include "../common/getenv.h"
#include "gui.h"
#include <assert.h>
#include <gtk/gtk.h>
#include <passwand/passwand.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// a lock to ensure we prevent multiple concurrent calls to GTK or X11 APIs
pthread_mutex_t gtk_lock = PTHREAD_MUTEX_INITIALIZER;

static bool inited;

void gui_gtk_init(void) {
  if (!inited) {
    if (getenv_("DISPLAY") == NULL)
      fprintf(stderr, "warning: $DISPLAY not set so GTK may fail\n");
    if (getenv_("XAUTHORITY") == NULL)
      fprintf(stderr, "warning: $XAUTHORITY not set so GTK may fail\n");

    gtk_init(NULL, NULL);
  }
  inited = true;
}

// The inner logic of `show_error`. This function assumes the caller has already
// taken `gtk_lock`.
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

  gui_gtk_init();

  // create dialog box
  GtkWidget *dialog =
      gtk_dialog_new_with_buttons(title, NULL, 0, "OK", GTK_RESPONSE_OK,
                                  "Cancel", GTK_RESPONSE_CANCEL, NULL);
  gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);

  // add the text prompt
  GtkWidget *label = gtk_label_new(message);
  GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
  gtk_container_add(GTK_CONTAINER(content), label);

  // add the input field
  GtkWidget *textbox = gtk_entry_new();
  gtk_entry_set_activates_default(GTK_ENTRY(textbox), true);
  if (initial != NULL)
    gtk_entry_set_text(GTK_ENTRY(textbox), initial);
  if (hidden) {
    gtk_entry_set_visibility(GTK_ENTRY(textbox), false);
#if GTK_CHECK_VERSION(3, 6, 0)
    gtk_entry_set_input_purpose(GTK_ENTRY(textbox), GTK_INPUT_PURPOSE_PASSWORD);
#endif
  }
  gtk_container_add(GTK_CONTAINER(content), textbox);

  // display the dialog
  gtk_widget_show_all(dialog);
  gint result = gtk_dialog_run(GTK_DIALOG(dialog));

  char *r;
  if (result == GTK_RESPONSE_OK) {
    const char *text = gtk_entry_get_text(GTK_ENTRY(textbox));
    if (hidden) {
      r = passwand_secure_malloc(strlen(text) + 1);
      if (r == NULL) {
        show_error_core("failed to allocate secure memory");
      } else {
        strcpy(r, text);
      }
    } else {
      r = strdup(text);
    }
  } else {
    // cancel or dialog was closed
    r = NULL;
  }

  gtk_widget_destroy(dialog);

  err = pthread_mutex_unlock(&gtk_lock);
  assert(err == 0);

  return r;
}

const char *describe_input(void) {
#if GTK_MAJOR_VERSION == 2
  return "GTK 2";
#elif GTK_MAJOR_VERSION == 3
  return "GTK 3";
#else
#error "unsupported configuration"
#endif
}

void flush_state(void) {

  int err __attribute__((unused)) = pthread_mutex_lock(&gtk_lock);
  assert(err == 0);

  // make sure we flush all GTK operations to clear remaining dialog windows
  while (gtk_events_pending())
    gtk_main_iteration();

  err = pthread_mutex_unlock(&gtk_lock);
  assert(err == 0);
}

void show_error(const char *message) {

  int err __attribute__((unused)) = pthread_mutex_lock(&gtk_lock);
  assert(err == 0);

  gui_gtk_init();

  show_error_core(message);

  err = pthread_mutex_unlock(&gtk_lock);
  assert(err == 0);
}
