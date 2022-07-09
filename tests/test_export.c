#include "test.h"
#include <passwand/passwand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

TEST("export: 0 entries") {

  // create a temporary path
  char tmp[sizeof("/tmp/tmp.XXXXXX")];
  strcpy(tmp, "/tmp/tmp.XXXXXX");
  int fd = mkstemp(tmp);
  ASSERT_NE(fd, -1);
  close(fd);

  // export to this path
  int r = passwand_export(tmp, NULL, 0);
  if (r != 0)
    unlink(tmp);
  ASSERT_EQ(r, 0);

  // read back in the exported data
  FILE *f = fopen(tmp, "r");
  if (f == NULL)
    unlink(tmp);
  ASSERT_NOT_NULL(f);
  char buffer[100];
  char *p = fgets(buffer, sizeof(buffer), f);
  fclose(f);
  unlink(tmp);

  // check we got what we expect
  ASSERT_NOT_NULL(p);
  ASSERT_STREQ(buffer, "[]");
}

TEST("export: basic functionality") {

  // create a temporary path
  char tmp[sizeof("/tmp/tmp.XXXXXX")];
  strcpy(tmp, "/tmp/tmp.XXXXXX");
  int fd = mkstemp(tmp);
  ASSERT_NE(fd, -1);
  close(fd);

  // create an entry to export
  passwand_entry_t entries[] = {
      {
          .space = (uint8_t *)"hello world",
          .space_len = strlen("hello world"),
          .key = (uint8_t *)"hello world",
          .key_len = strlen("hello world"),
          .value = (uint8_t *)"hello world",
          .value_len = strlen("hello world"),
          .hmac = (uint8_t *)"hello world",
          .hmac_len = strlen("hello world"),
          .hmac_salt = (uint8_t *)"hello world",
          .hmac_salt_len = strlen("hello world"),
          .salt = (uint8_t *)"hello world",
          .salt_len = strlen("hello world"),
          .iv = (uint8_t *)"hello world",
          .iv_len = strlen("hello world"),
          .work_factor = 0,
      },
  };

  // export to this path
  int r = passwand_export(tmp, entries, sizeof(entries) / sizeof(entries[0]));
  unlink(tmp);
  ASSERT_EQ(r, 0);
}
