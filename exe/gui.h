#pragma once

#include <stdbool.h>

static inline bool supported_lower(char c) {
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

static inline bool supported_upper(char c) {
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

/** Prompt the user to enter some text
 *
 * @param title Window title to display
 * @param message Prompt text to display
 * @param initial Initial value of input field
 * @param hidden Whether to mask input characters
 * @return Entered text or NULL if the user cancelled.
 */
char *get_text(const char *title, const char *message, const char *initial, bool hidden);

/** Type text into the active window
 *
 * @param text String of characters to type
 * @return 0 on success
 */
int send_text(const char *text);

/** Flush current GUI state
 *
 * You should call this after completing a sequence of GUI actions before moving
 * on to a non-GUI task. This synchronises window state. Window artefacts that
 * should be cleared may remain visible if you fail to call this. This may be a
 * no-op in environments that do not need it.
 */
void flush_state(void);

/** Display an error message dialog
 *
 * @param fmt... Message provided in the style of printf
 */
void show_error(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
