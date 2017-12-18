/* Implementation of the ../exe/gui.h API for the purposes of command line testing. */

#include <assert.h>
#include "../exe/gui.h"
#include <passwand/passwand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *get_text(const char *title __attribute__((unused)),
        const char *message __attribute__((unused)), const char *initial __attribute__((unused)),
        bool hidden) {

    static const size_t buffer_size = 4096;
    char *buffer = malloc(buffer_size);
    if (fgets(buffer, buffer_size, stdin) == NULL) {
        free(buffer);
        return NULL;
    }

    if (buffer[strlen(buffer) - 1] == '\n')
        buffer[strlen(buffer) - 1] = '\0';

    char *r;
    if (hidden) {
        if (passwand_secure_malloc((void**)&r, strlen(buffer) + 1) != PW_OK) {
            r = NULL;
        } else {
            strcpy(r, buffer);
            free(buffer);
        }
    } else {
        r = buffer;
    }

    return r;
}

int send_text(const char *text) {
    assert(text != NULL);
    printf("%s\n", text);
    return 0;
}

void flush_state(void) {
    fflush(stdout);
    fflush(stderr);
}

void show_error(const char *message) {
    fprintf(stderr, "%s\n", message);
}
