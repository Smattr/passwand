#include "argparse.h"
#include <assert.h>
#include <gtk/gtk.h>
#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

    char *master = get_text("Passwand", "Master passphrase?", NULL, true);
    if (master == NULL)
        return EXIT_FAILURE;

    passwand_entry_t *entries;
    unsigned entry_len;
    passwand_error_t err = passwand_import(options.data, &entries, &entry_len);
    if (err != PW_OK)
        DIE("failed to import database: %s\n", passwand_error(err));

    return EXIT_SUCCESS;
}
