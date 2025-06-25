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
  case ' ':
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

/** Setup GUI for use
 *
 * This function will be called on startup by the main program. Back ends
 * implementing the API in this header must be prepared to receive `show_error`
 * calls before this function is called and/or after it is called and has
 * returned failure. In these scenarios, if the back end has no way to show the
 * error itself, it can do nothing.
 *
 * If this function encounters an error, it is suggested that it present this to
 * the user somehow (e.g. `show_error`). The caller does not notify the user of
 * the error other than exiting with non-zero.
 *
 * @return 0 on success
 */
int gui_init(void);

/** Prompt the user to enter some text
 *
 * @param title Window title to display
 * @param message Prompt text to display
 * @param initial Initial value of input field
 * @param hidden Whether to mask input characters
 * @return Entered text or NULL if the user cancelled.
 */
char *get_text(const char *title, const char *message, const char *initial,
               bool hidden);

/** get a string describing the mechanism used to back `get_text`
 *
 * This function may be called at any time, regardless of whether `gui_init` has
 * been called.
 *
 * @return A human-readable description of the input transport
 */
const char *describe_input(void);

/** Type text into the active window
 *
 * @param text String of characters to type
 * @return 0 on success
 */
int send_text(const char *text);

/** get a string describing the mechanism used to back `send_text`
 *
 * This function may be called at any time, regardless of whether `gui_init` has
 * been called.
 *
 * @return A human-readable description of the output transport
 */
const char *describe_output(void);

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
 * @param message Message to show
 */
void show_error(const char *message);

/** Undo GUI setup
 *
 * Back ends implementing the API in this header must be prepared for this
 * function to be called at any time, including before `gui_init` has been
 * called.
 */
void gui_deinit(void);
