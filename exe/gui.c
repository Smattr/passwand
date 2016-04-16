#include <assert.h>
#include <gtk/gtk.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

char *get_text(const char *title, const char *message) {
    assert(title != NULL);
    assert(message != NULL);

    /* Create dialog box. */
    GtkWidget *dialog = gtk_dialog_new_with_buttons(title, NULL, 0, "OK",
        GTK_RESPONSE_OK, "Cancel", GTK_RESPONSE_CANCEL, NULL);
    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);

    /* Add the text prompt. */
    GtkWidget *label = gtk_label_new(message);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_container_add(GTK_CONTAINER(content), label);

    /* Add the input field. */
    GtkWidget *textbox = gtk_entry_new();
    gtk_entry_set_activates_default(GTK_ENTRY(textbox), true);
    gtk_container_add(GTK_CONTAINER(content), textbox);

    /* Display the dialog. */
    gtk_widget_show_all(dialog);
    gint result = gtk_dialog_run(GTK_DIALOG(dialog));

    char *r;
    if (result == GTK_RESPONSE_OK) {
        r = strdup(gtk_entry_get_text(GTK_ENTRY(textbox)));
    } else {
        /* Cancel or dialog was closed. */
        r = NULL;
    }

    gtk_widget_destroy(dialog);

    return r;
}

int main(int argc, char **argv) {

    gtk_init(&argc, &argv);

    char *space = get_text("Passwand", "Name space?");
    printf("Received: %s\n", space == NULL ? "(nil)" : space);

    return 0;
}
