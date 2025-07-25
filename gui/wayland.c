/** implementation of part of the API described in gui.h using Wayland uinput
 *
 * This is based on https://www.kernel.org/doc/html/v4.12/input/uinput.html.
 *
 * To configure your environment to use this back end without friction, you will
 * want to do something like:
 *   1. Install Passwand to a path, e.g. /foo/bar
 *   2. Remember (or script) to run as root:
 *        pkexec /usr/bin/env DISPLAY=${DISPLAY} XAUTHORITY=${XAUTHORITY} \
 *          XDG_SESSION_TYPE=${XDG_SESSION_TYPE} pw-gui
 * The reason this is necessary is that Wayland makes it very hard to mimic a
 * keyboard. There are good reasons for this, but it results in poor user
 * experience. The documented techniques for securely creating a virtual
 * keyboard The Right Way™ effectively breach your security as much as
 * temporarily running as root, so we choose the latter for simplicity.
 */

#include "../common/getenv.h"
#include "../common/streq.h"
#include "gtk.h"
#include "gui.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/uinput.h>
#include <pthread.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

static __attribute__((format(printf, 1, 2))) void error(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
#ifdef TEST_WAYLAND
  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
#else
  char *msg;
  if (vasprintf(&msg, fmt, ap) < 0) {
    show_error("out of memory");
  } else {
    show_error(msg);
    free(msg);
  }
#endif
  va_end(ap);
}

// all the keys this program may wish to type, with mapping to a US keyboard
// clang-format off
static const struct { char key; int code; bool shift; } keys[] = {
  { '\t', KEY_TAB,        false },
  { '\r', KEY_ENTER,      false },
  { ' ',  KEY_SPACE,      false },
  { '!',  KEY_1,          true  },
  { '"',  KEY_APOSTROPHE, true  },
  { '#',  KEY_3,          true  },
  { '$',  KEY_4,          true  },
  { '%',  KEY_5,          true  },
  { '&',  KEY_7,          true  },
  { '\'', KEY_APOSTROPHE, false },
  { '(',  KEY_9,          true  },
  { ')',  KEY_0,          true  },
  { '*',  KEY_8,          true  },
  { '+',  KEY_EQUAL,      true  },
  { ',',  KEY_COMMA,      false },
  { '-',  KEY_MINUS,      false },
  { '.',  KEY_DOT,        false },
  { '/',  KEY_SLASH,      false },
  { '0',  KEY_0,          false },
  { '1',  KEY_1,          false },
  { '2',  KEY_2,          false },
  { '3',  KEY_3,          false },
  { '4',  KEY_4,          false },
  { '5',  KEY_5,          false },
  { '6',  KEY_6,          false },
  { '7',  KEY_7,          false },
  { '8',  KEY_8,          false },
  { '9',  KEY_9,          false },
  { ':',  KEY_SEMICOLON,  true  },
  { ';',  KEY_SEMICOLON,  false },
  { '<',  KEY_COMMA,      true  },
  { '=',  KEY_EQUAL,      false },
  { '>',  KEY_DOT,        true  },
  { '?',  KEY_SLASH,      true  },
  { '@',  KEY_2,          true  },
  { 'A',  KEY_A,          true  },
  { 'B',  KEY_B,          true  },
  { 'C',  KEY_C,          true  },
  { 'D',  KEY_D,          true  },
  { 'E',  KEY_E,          true  },
  { 'F',  KEY_F,          true  },
  { 'G',  KEY_G,          true  },
  { 'H',  KEY_H,          true  },
  { 'I',  KEY_I,          true  },
  { 'J',  KEY_J,          true  },
  { 'K',  KEY_K,          true  },
  { 'L',  KEY_L,          true  },
  { 'M',  KEY_M,          true  },
  { 'N',  KEY_N,          true  },
  { 'O',  KEY_O,          true  },
  { 'P',  KEY_P,          true  },
  { 'Q',  KEY_Q,          true  },
  { 'R',  KEY_R,          true  },
  { 'S',  KEY_S,          true  },
  { 'T',  KEY_T,          true  },
  { 'U',  KEY_U,          true  },
  { 'V',  KEY_V,          true  },
  { 'W',  KEY_W,          true  },
  { 'X',  KEY_X,          true  },
  { 'Y',  KEY_Y,          true  },
  { 'Z',  KEY_Z,          true  },
  { '[',  KEY_LEFTBRACE,  false },
  { '\\', KEY_BACKSLASH,  false },
  { ']',  KEY_RIGHTBRACE, false },
  { '^',  KEY_6,          true  },
  { '_',  KEY_MINUS,      true  },
  { '`',  KEY_GRAVE,      false },
  { 'a',  KEY_A,          false },
  { 'b',  KEY_B,          false },
  { 'c',  KEY_C,          false },
  { 'd',  KEY_D,          false },
  { 'e',  KEY_E,          false },
  { 'f',  KEY_F,          false },
  { 'g',  KEY_G,          false },
  { 'h',  KEY_H,          false },
  { 'i',  KEY_I,          false },
  { 'j',  KEY_J,          false },
  { 'k',  KEY_K,          false },
  { 'l',  KEY_L,          false },
  { 'm',  KEY_M,          false },
  { 'n',  KEY_N,          false },
  { 'o',  KEY_O,          false },
  { 'p',  KEY_P,          false },
  { 'q',  KEY_Q,          false },
  { 'r',  KEY_R,          false },
  { 's',  KEY_S,          false },
  { 't',  KEY_T,          false },
  { 'u',  KEY_U,          false },
  { 'v',  KEY_V,          false },
  { 'w',  KEY_W,          false },
  { 'x',  KEY_X,          false },
  { 'y',  KEY_Y,          false },
  { 'z',  KEY_Z,          false },
  { '{',  KEY_LEFTBRACE,  true  },
  { '|',  KEY_BACKSLASH,  true  },
  { '}',  KEY_RIGHTBRACE, true  },
  { '~',  KEY_GRAVE,      true  },
};
// clang-format on

// send a key event
static void emit(int fd, int category, int code, int value) {

  struct input_event ev;

  ev.type = category;
  ev.code = code;
  ev.value = value;

  // timestamps ignored
  ev.time.tv_sec = 0;
  ev.time.tv_usec = 0;

  write(fd, &ev, sizeof(ev));
}

// type a single character
static void type(int uinput, char c) {
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
    if (keys[i].key == c) {

      // do we need to hold Shift while pressing this key?
      if (keys[i].shift) {
        emit(uinput, EV_KEY, KEY_LEFTSHIFT, 1);
        emit(uinput, EV_SYN, SYN_REPORT, 0);
      }

      // press the key itself
      emit(uinput, EV_KEY, keys[i].code, 1);
      emit(uinput, EV_SYN, SYN_REPORT, 0);

      // ensure the key press is registered
      usleep(100);

      // release the key
      emit(uinput, EV_KEY, keys[i].code, 0);
      emit(uinput, EV_SYN, SYN_REPORT, 0);

      // release shift if we have it held
      if (keys[i].shift) {
        emit(uinput, EV_KEY, KEY_LEFTSHIFT, 0);
        emit(uinput, EV_SYN, SYN_REPORT, 0);
      }

      // ensure the key release is registered
      usleep(100);

      return;
    }
  }
}

static int make_dev(void) {

  // connect to uinput
  int fd = open("/dev/uinput", O_WRONLY | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0) {
    error("failed to open /dev/uinput: %s", strerror(errno));
    return -1;
  }

  // enable key press events
  if (ioctl(fd, UI_SET_EVBIT, EV_KEY) < 0) {
    close(fd);
    error("failed to enable key events: %s", strerror(errno));
    return -1;
  }

  // enable all the keys we may wish to type
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
    if (ioctl(fd, UI_SET_KEYBIT, keys[i].code) < 0) {
      close(fd);
      error("failed to enable key '%c': %s", keys[i].key, strerror(errno));
      return -1;
    }
  }
  if (ioctl(fd, UI_SET_KEYBIT, KEY_LEFTSHIFT) < 0) {
    close(fd);
    error("failed to enable key shift: %s", strerror(errno));
    return -1;
  }

  // describe a virtual keyboard
  struct uinput_setup config;
  memset(&config, 0, sizeof(config));
  config.id.bustype = BUS_USB;
  config.id.vendor = 0x7770; // "pw"
  config.id.product = 0x7770;
  _Static_assert(sizeof("passwand virtual keyboard") <= sizeof(config.name));
  strcpy(config.name, "passwand virtual keyboard");

  // create the device
  if (ioctl(fd, UI_DEV_SETUP, &config) < 0 || ioctl(fd, UI_DEV_CREATE) < 0) {
    close(fd);
    error("failed to create virtual device: %s", strerror(errno));
    return -1;
  }

  return fd;
}

static void destroy_dev(int dev) {
  // stall to drain the event queue
  sleep(1);

  // destroy the device
  (void)ioctl(dev, UI_DEV_DESTROY);
  close(dev);
}

#ifdef TEST_WAYLAND
int main(int argc, char **argv) {

  if (argc != 2 || streq(argv[1], "-?") || streq(argv[1], "--help")) {
    error("usage: %s string\n"
          "  test utility for typing on Wayland",
          argv[0]);
    return EXIT_FAILURE;
  }

  // sanity check that our key table makes sense
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
    for (size_t j = i + 1; j < sizeof(keys) / sizeof(keys[0]); ++j) {
      if (keys[i].key == keys[j].key ||
          (keys[i].code == keys[j].code && keys[i].shift == keys[j].shift)) {
        error("duplicate key table entry, '%c': [%zu] and [%zu]", keys[i].key,
              i, j);
        return EXIT_FAILURE;
      }
    }
  }

  // check we were not passed anything we do not know how to type
  for (const char *p = argv[1]; *p != '\0'; ++p) {
    bool ok = false;
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
      if (keys[i].key == *p) {
        ok = true;
        break;
      }
    }
    if (!ok) {
      error("I do not know how to type '%c'", *p);
      return EXIT_FAILURE;
    }
  }

  // create a uinput device
  int fd = make_dev();
  if (fd < 0)
    return EXIT_FAILURE;

  // stall to give userspace a chance to detect and initialise the device
  sleep(1);

  // type the user’s text
  for (const char *p = argv[1]; *p != '\0'; ++p)
    type(fd, *p);

  // remove the uinput device
  destroy_dev(fd);

  return EXIT_SUCCESS;
}

#else
/// a uinput-based device we will use to type characters
static int virtual_keyboard;

int send_text(const char *text) {

  assert(text != NULL);

  // check we were not passed anything we do not know how to type
  for (const char *p = text; *p != '\0'; ++p) {
    bool ok = false;
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
      if (keys[i].key == *p) {
        ok = true;
        break;
      }
    }
    if (!ok) {
      // we deliberately do not echo the failing character in the error message
      // in case the thing being typed is something sensitive like a password
      error("unsupported character in output text");
      return -1;
    }
  }

  if (virtual_keyboard <= 0) {
    error("virtual keyboard was not initialised");
    return -1;
  }

  int err __attribute__((unused)) = pthread_mutex_lock(&gtk_lock);
  assert(err == 0);

  // type the user’s text
  for (const char *p = text; *p != '\0'; ++p)
    type(virtual_keyboard, *p);

  err = pthread_mutex_unlock(&gtk_lock);
  assert(err == 0);

  return 0;
}

const char *describe_output(void) { return "wayland"; }

/// if running under `sudo` or `pkexec`, drop privileges
static int demote_me(void) {

  // are we root?
  if (getuid() != 0)
    return 0;

  // are we `sudo`ing?
  const char *uid_s = getenv_("SUDO_UID");
  // are we `pkexec`-ing?
  if (uid_s == NULL)
    uid_s = getenv_("PKEXEC_UID");
  if (uid_s == NULL)
    return EACCES;

  // decode numeric ID
  const int uid = atoi(uid_s);
  if (uid == 0)
    return EINVAL;

  // get full user information
  errno = 0;
  const struct passwd *const pw = getpwuid(uid);
  if (pw == NULL) {
    if (errno == 0)
      return ENOENT;
    return errno;
  }

  // become the original user
  if (setgid(pw->pw_gid) < 0)
    return errno;
  if (setuid(pw->pw_uid) < 0)
    return errno;

  // As a nicety, try to reset the some commonly used environment variables.
  // This avoids, e.g., confusing IBUS warnings.
  (void)setenv("USER", pw->pw_name, 1);
  (void)setenv("HOME", pw->pw_dir, 1);

  return 0;
}

// This back end is expected to be paired with gtk.c. The `gui_init` and
// `gui_deinit` functions are implemented here rather than in gtk.c to have only
// wayland.c aware of gtk.c and not the other way around. This fits the N-to-1
// ({x11.c|wayland.c}-to-gtk.c) relationship here.

int gui_init(void) {

  int rc = 0;

  assert(virtual_keyboard <= 0);
  virtual_keyboard = make_dev();
  if (virtual_keyboard < 0) {
    rc = -1;
    goto done;
  }

  // if we were started as root (in order to be able to open /dev/uinput)
  // de-escalate our privileges now
  if ((rc = demote_me())) {
    error("failed to drop privileges: %s", strerror(rc));
    goto done;
  }

  if ((rc = pthread_mutex_lock(&gtk_lock)))
    goto done;

  gui_gtk_init();

  if ((rc = pthread_mutex_unlock(&gtk_lock)))
    goto done;

done:
  return rc;
}

void gui_deinit(void) {
  if (virtual_keyboard > 0)
    destroy_dev(virtual_keyboard);
  virtual_keyboard = 0;
}
#endif
