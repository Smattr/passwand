#include "help.h"
#include "../common/environ.h"
#include "../common/getenv.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

// man page data that is generated and compiled into our image
extern unsigned char passwand_1[];
extern int passwand_1_len;

void help(void) {

  int rc = 0;

  // find temporary storage space
  const char *TMPDIR = getenv_("TMPDIR");
  if (TMPDIR == NULL)
    TMPDIR = "/tmp";

  // create a temporary file
  int fd = -1;
  size_t s = strlen(TMPDIR) + strlen("/tmp.XXXXXX") + 1;
  char *path = malloc(s);
  if (path == NULL) {
    rc = ENOMEM;
    fprintf(stderr, "out of memory\n");
    goto done;
  }
  snprintf(path, s, "%s/tmp.XXXXXX", TMPDIR);
  fd = mkostemp(path, O_CLOEXEC);
  if (fd == -1) {
    rc = errno;
    fprintf(stderr, "failed to create temporary file\n");
    free(path);
    path = NULL;
    goto done;
  }

  // write the manpage to the temporary file
  for (size_t offset = 0; offset < (size_t)passwand_1_len;) {
    const ssize_t r =
        write(fd, &passwand_1[offset], (size_t)passwand_1_len - offset);
    if (r < 0) {
      if (errno == EINTR)
        continue;
      rc = errno;
      goto done;
    }
    assert((size_t)r <= (size_t)passwand_1_len - offset);
    offset += (size_t)r;
  }

  // close our file handle and mark it as invalid
  close(fd);
  fd = -1;

  // run man to display the help text
  pid_t man = 0;
  {
    char argv0[] = "man";
    char local[] __attribute__((unused)) = "--local-file";
    char prompt[] __attribute__((unused)) =
        "--prompt= Manual page passwand(1) ?ltline %lt?L/%L.:byte %bB?s/%s..? "
        "(END):?pB %pB\\%.. (press h for help or q to quit)";
    char *const argv[] = {argv0,
#ifdef __linux__
                          local, prompt,
#endif
                          path, NULL};
    if ((rc = posix_spawnp(&man, argv0, NULL, NULL, argv, get_environ())))
      goto done;
  }

  // wait for man to finish
  (void)waitpid(man, &(int){0}, 0);

  // cleanup
done:
  if (fd >= 0)
    close(fd);
  if (path != NULL)
    (void)unlink(path);
  free(path);

  exit(rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
