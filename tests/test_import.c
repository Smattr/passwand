#include "test.h"
#include <passwand/passwand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

TEST("import: import(\"[]\")") {

  // create a temporary file
  char tmp[] = "/tmp/tmp.XXXXXX";
  int fd = mkstemp(tmp);
  ASSERT_NE(fd, -1);
  ssize_t written = write(fd, "[]", strlen("[]"));
  if (written != strlen("[]"))
    unlink(tmp);
  ASSERT_EQ((size_t)written, strlen("[]"));

  // now read in the entries
  passwand_entry_t *entries = NULL;
  size_t entry_len = 0;
  int r = passwand_import(tmp, &entries, &entry_len);
  unlink(tmp);
  ASSERT_EQ(r, 0);

  // check we got nothing
  ASSERT_EQ(entry_len, 0ul);

  // clean up
  free(entries);
}

TEST("import: with a missing field") {
  const char *data =
      "[{\"space\":\"aGVsbG8gd29ybGQ=\", \"key\":\"aGVsbG8gd29ybGQ=\", "
      "\"value\":\"aGVsbG8gd29ybGQ=\", \"hmac\":\"aGVsbG8gd29ybGQ=\", "
      "\"hmac_salt\":\"aGVsbG8gd29ybGQ=\", \"salt\":\"aGVsbG8gd29ybGQ=\"}]";

  // create a temporary file
  char tmp[] = "/tmp/tmp.XXXXXX";
  int fd = mkstemp(tmp);
  ASSERT_NE(fd, -1);
  ssize_t written = write(fd, data, strlen(data));
  if (written != (ssize_t)strlen(data))
    unlink(tmp);
  ASSERT_EQ((size_t)written, strlen(data));

  // now read in the entries
  passwand_entry_t *entries;
  size_t entry_len;
  int r = passwand_import(tmp, &entries, &entry_len);
  unlink(tmp);
  ASSERT_NE(r, 0);
}

TEST("import: basic functionality") {
  const char *data =
      "[{\"space\":\"aGVsbG8gd29ybGQ=\", \"key\":\"aGVsbG8gd29ybGQ=\", "
      "\"value\":\"aGVsbG8gd29ybGQ=\", \"hmac\":\"aGVsbG8gd29ybGQ=\", "
      "\"hmac_salt\":\"aGVsbG8gd29ybGQ=\", \"salt\":\"aGVsbG8gd29ybGQ=\", "
      "\"iv\":\"aGVsbG8gd29ybGQ=\"}]";

  // create a temporary file
  char tmp[] = "/tmp/tmp.XXXXXX";
  int fd = mkstemp(tmp);
  ASSERT_NE(fd, -1);
  ssize_t written = write(fd, data, strlen(data));
  if (written != (ssize_t)strlen(data))
    unlink(tmp);
  ASSERT_EQ((size_t)written, strlen(data));

  // now read in the entries
  passwand_entry_t *entries = NULL;
  size_t entry_len = 0;
  int r = passwand_import(tmp, &entries, &entry_len);
  unlink(tmp);
  ASSERT_EQ(r, 0);

  // check we got an entry
  ASSERT_EQ(entry_len, 1ul);
  ASSERT_EQ(entries[0].space_len, strlen("hello world"));
  ASSERT_EQ(strncmp((const char *)entries[0].space, "hello world",
                    entries[0].space_len),
            0);
  ASSERT_EQ(entries[0].key_len, strlen("hello world"));
  ASSERT_EQ(
      strncmp((const char *)entries[0].key, "hello world", entries[0].key_len),
      0);
  ASSERT_EQ(entries[0].value_len, strlen("hello world"));
  ASSERT_EQ(strncmp((const char *)entries[0].value, "hello world",
                    entries[0].value_len),
            0);
  ASSERT_EQ(entries[0].hmac_len, strlen("hello world"));
  ASSERT_EQ(strncmp((const char *)entries[0].hmac, "hello world",
                    entries[0].hmac_len),
            0);
  ASSERT_EQ(entries[0].hmac_salt_len, strlen("hello world"));
  ASSERT_EQ(strncmp((const char *)entries[0].hmac_salt, "hello world",
                    entries[0].hmac_salt_len),
            0);
  ASSERT_EQ(entries[0].salt_len, strlen("hello world"));
  ASSERT_EQ(strncmp((const char *)entries[0].salt, "hello world",
                    entries[0].salt_len),
            0);
  ASSERT_EQ(entries[0].iv_len, strlen("hello world"));
  ASSERT_EQ(
      strncmp((const char *)entries[0].iv, "hello world", entries[0].iv_len),
      0);

  // clean up
  for (size_t i = 0; i < entry_len; i++) {
    free(entries[i].space);
    free(entries[i].key);
    free(entries[i].value);
    free(entries[i].hmac);
    free(entries[i].hmac_salt);
    free(entries[i].salt);
    free(entries[i].iv);
  }
  free(entries);
}

TEST("import: with an extra field") {
  const char *data =
      "[{\"space\":\"aGVsbG8gd29ybGQ=\", \"key\":\"aGVsbG8gd29ybGQ=\", "
      "\"value\":\"aGVsbG8gd29ybGQ=\", \"hmac\":\"aGVsbG8gd29ybGQ=\", "
      "\"hmac_salt\":\"aGVsbG8gd29ybGQ=\", \"salt\":\"aGVsbG8gd29ybGQ=\", "
      "\"iv\":\"aGVsbG8gd29ybGQ=\",\"extra\":\"blah blah\"}]";

  // create a temporary file
  char tmp[] = "/tmp/tmp.XXXXXX";
  int fd = mkstemp(tmp);
  ASSERT_NE(fd, -1);
  ssize_t written = write(fd, data, strlen(data));
  if (written != (ssize_t)strlen(data))
    unlink(tmp);
  ASSERT_EQ((size_t)written, strlen(data));

  // now read in the entries
  passwand_entry_t *entries = NULL;
  size_t entry_len = 0;
  int r = passwand_import(tmp, &entries, &entry_len);
  unlink(tmp);
  ASSERT_EQ(r, 0);

  // check we got an entry
  ASSERT_EQ(entry_len, 1ul);
  ASSERT_EQ(entries[0].space_len, strlen("hello world"));
  ASSERT_EQ(strncmp((const char *)entries[0].space, "hello world",
                    entries[0].space_len),
            0);
  ASSERT_EQ(entries[0].key_len, strlen("hello world"));
  ASSERT_EQ(
      strncmp((const char *)entries[0].key, "hello world", entries[0].key_len),
      0);
  ASSERT_EQ(entries[0].value_len, strlen("hello world"));
  ASSERT_EQ(strncmp((const char *)entries[0].value, "hello world",
                    entries[0].value_len),
            0);
  ASSERT_EQ(entries[0].hmac_len, strlen("hello world"));
  ASSERT_EQ(strncmp((const char *)entries[0].hmac, "hello world",
                    entries[0].hmac_len),
            0);
  ASSERT_EQ(entries[0].hmac_salt_len, strlen("hello world"));
  ASSERT_EQ(strncmp((const char *)entries[0].hmac_salt, "hello world",
                    entries[0].hmac_salt_len),
            0);
  ASSERT_EQ(entries[0].salt_len, strlen("hello world"));
  ASSERT_EQ(strncmp((const char *)entries[0].salt, "hello world",
                    entries[0].salt_len),
            0);
  ASSERT_EQ(entries[0].iv_len, strlen("hello world"));
  ASSERT_EQ(
      strncmp((const char *)entries[0].iv, "hello world", entries[0].iv_len),
      0);

  // clean up
  for (size_t i = 0; i < entry_len; i++) {
    free(entries[i].space);
    free(entries[i].key);
    free(entries[i].value);
    free(entries[i].hmac);
    free(entries[i].hmac_salt);
    free(entries[i].salt);
    free(entries[i].iv);
  }
  free(entries);
}

TEST("import: import(export(x)) == x") {

  // first create a couple of entries that we are going to export
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
          .work_factor = 14,
      },
      {
          .space = (uint8_t *)"foo bar",
          .space_len = strlen("foo bar"),
          .key = (uint8_t *)"foo bar",
          .key_len = strlen("foo bar"),
          .value = (uint8_t *)"foo bar",
          .value_len = strlen("foo bar"),
          .hmac = (uint8_t *)"foo bar",
          .hmac_len = strlen("foo bar"),
          .hmac_salt = (uint8_t *)"foo bar",
          .hmac_salt_len = strlen("foo bar"),
          .salt = (uint8_t *)"foo bar",
          .salt_len = strlen("foo bar"),
          .iv = (uint8_t *)"foo bar",
          .iv_len = strlen("foo bar"),
          .work_factor = 15,
      },
  };
  size_t entry_len = sizeof(entries) / sizeof(entries[0]);

  // create a temporary file to export to
  char tmp[] = "/tmp/tmp.XXXXXX";
  int fd = mkstemp(tmp);
  ASSERT_NE(fd, -1);
  close(fd);

  // perform the export
  int err = passwand_export(tmp, entries, entry_len);
  if (err != PW_OK)
    unlink(tmp);
  ASSERT_EQ(err, PW_OK);

  // now let us import them back in
  passwand_entry_t *new_entries;
  size_t new_entry_len;
  err = passwand_import(tmp, &new_entries, &new_entry_len);
  unlink(tmp);
  ASSERT_EQ(err, PW_OK);

  // now check we got back what we exported
  ASSERT_EQ(entry_len, new_entry_len);
  for (size_t i = 0; i < entry_len; i++) {
    ASSERT_EQ(entries[i].space_len, new_entries[i].space_len);
    ASSERT_EQ(strncmp((const char *)entries[i].space,
                      (const char *)new_entries[i].space, entries[i].space_len),
              0);
    ASSERT_EQ(entries[i].key_len, new_entries[i].key_len);
    ASSERT_EQ(strncmp((const char *)entries[i].key,
                      (const char *)new_entries[i].key, entries[i].key_len),
              0);
    ASSERT_EQ(entries[i].value_len, new_entries[i].value_len);
    ASSERT_EQ(strncmp((const char *)entries[i].value,
                      (const char *)new_entries[i].value, entries[i].value_len),
              0);
    ASSERT_EQ(entries[i].hmac_len, new_entries[i].hmac_len);
    ASSERT_EQ(strncmp((const char *)entries[i].hmac,
                      (const char *)new_entries[i].hmac, entries[i].hmac_len),
              0);
    ASSERT_EQ(entries[i].hmac_salt_len, new_entries[i].hmac_salt_len);
    ASSERT_EQ(strncmp((const char *)entries[i].hmac_salt,
                      (const char *)new_entries[i].hmac_salt,
                      entries[i].hmac_salt_len),
              0);
    ASSERT_EQ(entries[i].salt_len, new_entries[i].salt_len);
    ASSERT_EQ(strncmp((const char *)entries[i].salt,
                      (const char *)new_entries[i].salt, entries[i].salt_len),
              0);
    ASSERT_EQ(entries[i].iv_len, new_entries[i].iv_len);
    ASSERT_EQ(strncmp((const char *)entries[i].iv,
                      (const char *)new_entries[i].iv, entries[i].iv_len),
              0);
  }

  // clean up
  for (size_t i = 0; i < new_entry_len; i++) {
    free(new_entries[i].space);
    free(new_entries[i].key);
    free(new_entries[i].value);
    free(new_entries[i].hmac);
    free(new_entries[i].hmac_salt);
    free(new_entries[i].salt);
    free(new_entries[i].iv);
  }
  free(new_entries);
}
