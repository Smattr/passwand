#include "../common/getenv.h"
#include "help.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// man page data that is generated and compiled into our image
extern unsigned char passwand_1[];
extern int passwand_1_len;

void help(void) {

    int rc = EXIT_FAILURE;

    // find temporary storage space
    const char *TMPDIR = getenv_("TMPDIR");
    if (TMPDIR == NULL)
        TMPDIR = "/tmp";

    // create a temporary file
    int fd = -1;
    size_t s = strlen(TMPDIR) + strlen("/tmp.XXXXXX") + 1;
    char *path = malloc(s);
    if (path == NULL) {
        fprintf(stderr, "out of memory\n");
        goto done;
    }
    snprintf(path, s, "%s/tmp.XXXXXX", TMPDIR);
    fd = mkstemp(path);
    if (fd == -1) {
        perror("failed to create temporary file");
        goto done;
    }

    // write the man page to the temporary file
    {
        ssize_t r = write(fd, passwand_1, (size_t)passwand_1_len);
        if (r < 0 || (size_t)r != (size_t)passwand_1_len) {
            perror("failed to write temporary file");
            goto done;
        }
    }

    // close our file handle and mark it as invalid
    close(fd);
    fd = -1;

    // run man to display the help text
    {
        size_t as = strlen("man ") + strlen(path) + 1;
#ifdef __linux__
        as += strlen("--local-file ");
#endif
        char *argv = malloc(as);
        if (argv == NULL) {
            fprintf(stderr, "out of memory\n");
            goto done;
        }
        snprintf(argv, as, "man "
#ifdef __linux__
          "--local-file "
#endif
          "%s", path);
        rc = system(argv);
        free(argv);
    }

    // cleanup
done:
    if (fd >= 0)
        close(fd);
    if (access(path, F_OK) == 0)
        (void)unlink(path);
    free(path);
    exit(rc);
}
