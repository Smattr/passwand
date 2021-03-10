// implementation of part of the API described in gui.h using X11

#include "../common/getenv.h"
#include "gtk_lock.h"
#include "gui.h"
#include <X11/Xlib.h>
#include <assert.h>
#include <pthread.h>
#include <stddef.h>
#include <string.h>

static void send_char(Display *display, Window window, char c) {

  assert(supported_upper(c) || supported_lower(c));

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

int send_text(const char *text) {

  assert(text != NULL);

  int err __attribute__((unused)) = pthread_mutex_lock(&gtk_lock);
  assert(err == 0);

  // find the current display
  const char *display = getenv_("DISPLAY");
  if (display == NULL)
    display = ":0";
  Display *d = XOpenDisplay(display);
  if (d == NULL) {
    err = pthread_mutex_unlock(&gtk_lock);
    assert(err == 0);
    show_error("failed to open X11 display");
    return -1;
  }

  // find the active window
  Window win;
  int state;
  XGetInputFocus(d, &win, &state);
  if (win == None) {
    XCloseDisplay(d);
    err = pthread_mutex_unlock(&gtk_lock);
    assert(err == 0);
    show_error("no window focused");
    return -1;
  }

  for (size_t i = 0; i < strlen(text); i++) {
    assert(supported_upper(text[i]) || supported_lower(text[i]));
    send_char(d, win, text[i]);
  }

  XCloseDisplay(d);

  err = pthread_mutex_unlock(&gtk_lock);
  assert(err == 0);

  return 0;
}
