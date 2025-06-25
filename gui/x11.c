// implementation of part of the API described in gui.h using X11

#include "../common/getenv.h"
#include "gtk.h"
#include "gui.h"
#include <X11/XKBlib.h>
#include <X11/Xlib.h>
#include <X11/extensions/XTest.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <string.h>

typedef enum { KEYUP = False, KEYDOWN = True } keypress_t;

static int send_shift(Display *display, keypress_t keypress) {

  XModifierKeymap *modifiers = XGetModifierMapping(display);
  if (modifiers == NULL)
    return ENOMEM;

  XTestFakeKeyEvent(display, modifiers->modifiermap[ShiftMapIndex], keypress,
                    CurrentTime);
  XSync(display, False);

  XFreeModifiermap(modifiers);

  return 0;
}

static int send_char(Display *display, char c) {

  assert(supported_upper(c) || supported_lower(c));

  // optionally press Shift
  if (supported_upper(c)) {
    int r = send_shift(display, KEYDOWN);
    if (r != 0)
      return r;
  }

  // press the key
  KeyCode code = XKeysymToKeycode(display, c);
  XTestFakeKeyEvent(display, code, True, CurrentTime);
  XSync(display, False);

  // depress the key
  XTestFakeKeyEvent(display, code, False, CurrentTime);
  XSync(display, False);

  // optionally depress Shift
  if (supported_upper(c)) {
    int r = send_shift(display, KEYUP);
    if (r != 0)
      return r;
  }

  return 0;
}

int send_text(const char *text) {

  assert(text != NULL);

  {
    int err __attribute__((unused)) = pthread_mutex_lock(&gtk_lock);
    assert(err == 0);
  }

  // find the current display
  const char *display = getenv_("DISPLAY");
  if (display == NULL)
    display = ":0";
  Display *d = XOpenDisplay(display);
  if (d == NULL) {
    {
      int err __attribute__((unused)) = pthread_mutex_unlock(&gtk_lock);
      assert(err == 0);
    }
    show_error("failed to open X11 display");
    return -1;
  }

  int rc = 0;

  for (size_t i = 0; i < strlen(text); i++) {
    assert(supported_upper(text[i]) || supported_lower(text[i]));
    rc = send_char(d, text[i]);
    if (rc != 0)
      goto done;
  }

done:
  XCloseDisplay(d);

  {
    int err __attribute__((unused)) = pthread_mutex_unlock(&gtk_lock);
    assert(err == 0);
  }

  if (rc != 0) {
    assert(rc == ENOMEM);
    show_error("failed to type text: out of memory");
  }

  return rc;
}

const char *describe_output(void) { return "x11"; }

// This back end is expected to be paired with gtk.c. The `gui_init` and
// `gui_deinit` functions are implemented here rather than in gtk.c to have only
// x11.c aware of gtk.c and not the other way around. This fits the N-to-1
// ({x11.c|wayland.c}-to-gtk.c) relationship here.

int gui_init(void) {

  {
    int err __attribute__((unused)) = pthread_mutex_lock(&gtk_lock);
    assert(err == 0);
  }

  gui_gtk_init();

  {
    int err = pthread_mutex_unlock(&gtk_lock);
    assert(err == 0);
  }

  return 0;
}

void gui_deinit(void) { /* nothing required */ }
