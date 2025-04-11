#include "../src/internal.h"
#include "../src/types.h"
#include "test.h"
#include <assert.h>
#include <openssl/evp.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static jmp_buf env;

static bool is_expected_signal(int signum) {
  if (signum == SIGSEGV)
    return true;
#ifdef __APPLE__
  // on MacOS, accesses to PROT_NONE mmaped regions are reported to userspace
  // as SIGBUS, not SIGSEGV
  if (signum == SIGBUS)
    return true;
#endif
  return false;
}

static void handler(int signum) {
  assert(is_expected_signal(signum));
  longjmp(env, is_expected_signal(signum) ? 1 : -1);
}

static int deregister_handler(void) {
  const struct sigaction sa = {
      .sa_handler = SIG_DFL,
  };
  int r = sigaction(SIGSEGV, &sa, NULL);
#ifdef __APPLE__
  r |= sigaction(SIGBUS, &sa, NULL);
#endif
  return r;
}

static int register_handler(void) {
  const struct sigaction sa = {
      .sa_handler = handler,
      .sa_flags = SA_NODEFER,
  };
  if (sigaction(SIGSEGV, &sa, NULL))
    return -1;
#ifdef __APPLE__
  if (sigaction(SIGBUS, &sa, NULL)) {
    (void)deregister_handler();
    return -1;
  }
#endif
  return 0;
}

TEST("AES128 reads at most 128 bits of a supplied key") {

  // This test is not probing the behaviour of Passwand’s encryption
  // functionality, but rather AES128. A previous version of Passwand used a
  // 256-bit key with this algorithm, which I believe is excessive. AES128
  // should only need a 128-bit key. This test validates that AES128 encryption
  // only reads the first 128 bits of a key given to it.

  // use a dummy initialisation vector because we do not care about the strength
  // of this test encryption
  unsigned char iv[16] = {0};

  // Create a 128-bit key where accessing memory immediately following the key
  // will cause a trap. The purpose of this is to detect if the AES algorithm
  // reads more than 128 bits.
  int pagesize = sysconf(_SC_PAGESIZE);
  assert(pagesize >= 16 && "AES key does not fit in a page");
  unsigned char *p = aligned_alloc(pagesize, pagesize * 2);
  ASSERT_NOT_NULL(p);
  // make the second page inaccessible
  int r = mprotect(p + pagesize, pagesize, PROT_NONE);
  ASSERT_EQ(r, 0);
  // write a dummy key into the end of the first page
  unsigned char *key = p + pagesize - 16;
  memset(key, 0, 16);

  // setup a context for encryption
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ASSERT_NOT_NULL(ctx);

  // operations from here on may cause a SIGSEGV if we have got AES wrong, so
  // setup a signal handler so we can recover
  r = register_handler();
  ASSERT_EQ(r, 0);
  int j = setjmp(env);
  if (j == 0) {

    // do a dummy encryption to force use of the key

    r = EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
    ASSERT_EQ(r, 1);

    unsigned char in[sizeof("hello world")];
    strcpy((char *)in, "hello world");

    unsigned char out[sizeof(in) + 16 - 1];

    r = EVP_EncryptUpdate(ctx, out, &(int){0}, in, sizeof(in));
    ASSERT_EQ(r, 1);

  } else if (j == 1) {

    // we unexpectedly triggered a SIGSEGV; fail
    FAIL("overread 128-bit buffer");
  }

  // If we reached here, then we did not trigger a SIGSEGV. Yay!

  r = deregister_handler();
  ASSERT_EQ(r, 0);

  EVP_CIPHER_CTX_free(ctx);

  // we need to unprotect the page we previously protected because we are about
  // to give it back to the heap
  r = mprotect(p + pagesize, pagesize, PROT_READ | PROT_WRITE);
  ASSERT_EQ(r, 0);

  free(p);
}

TEST("AES128 reads at least 128 bits of a supplied key") {

  // This test is the companion to the previous, and tests that AES128 does read
  // 128 bits of the key, not less. Where code is similar, see the comments in
  // the previous function.

  unsigned char iv[16] = {0};

  // Create a 128-bit key where accessing its last byte will cause a trap. This
  // should allow us to detect if AES128 does not read to the end of the key.
  int pagesize = sysconf(_SC_PAGESIZE);
  assert(pagesize >= 16 && "AES key does not fit in a page");
  unsigned char *p = aligned_alloc(pagesize, pagesize * 2);
  ASSERT_NOT_NULL(p);
  // write a dummy key into the end of the first page and first byte of second
  unsigned char *key = p + pagesize - 15;
  memset(key, 0, 16);
  // make the second page inaccessible
  int r = mprotect(p + pagesize, pagesize, PROT_NONE);
  ASSERT_EQ(r, 0);

  // setup a context for encryption
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ASSERT_NOT_NULL(ctx);

  // operations from here on should cause a SIGSEGV if we understand AES, so
  // setup a signal handler so we can recover
  r = register_handler();
  ASSERT_EQ(r, 0);
  int j = setjmp(env);
  if (j == 0) {

    // do a dummy encryption to force use of the key

    r = EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
    ASSERT_EQ(r, 1);

    unsigned char in[sizeof("hello world")];
    strcpy((char *)in, "hello world");

    unsigned char out[sizeof(in) + 16 - 1];

    r = EVP_EncryptUpdate(ctx, out, &(int){0}, in, sizeof(in));
    ASSERT_EQ(r, 1);

    // if we reached here then we did not trigger SIGSEGV :(
    FAIL("failed to read to the end of 128-bit key");
  }

  // if we reached here, then we should have triggered a SIGSEGV
  ASSERT_EQ(j, 1);

  r = deregister_handler();
  ASSERT_EQ(r, 0);

  EVP_CIPHER_CTX_free(ctx);

  // we need to unprotect the page we previously protected because we are about
  // to give it back to the heap
  r = mprotect(p + pagesize, pagesize, PROT_READ | PROT_WRITE);
  ASSERT_EQ(r, 0);

  free(p);
}

TEST("AES128 reads at most 16 bytes of a supplied initialisation vector") {

  // Similar to the previous cases, a previous version of Passwand incorrectly
  // created a short initialisation vector of only 8 bytes. This test case and
  // the next ensure that we have the initialisation vector size correct at 16
  // bytes.

  // create a dummy key
  unsigned char key[16] = {0};

  // Create a 16 byte IV where accessing memory immediately following the IV
  // will cause a trap. The purpose of this is to detect if the AES algorithm
  // reads more than 16 bytes.
  int pagesize = sysconf(_SC_PAGESIZE);
  assert(pagesize >= 16 && "AES IV does not fit in a page");
  unsigned char *p = aligned_alloc(pagesize, pagesize * 2);
  ASSERT_NOT_NULL(p);
  // make the second page inaccessible
  int r = mprotect(p + pagesize, pagesize, PROT_NONE);
  ASSERT_EQ(r, 0);
  // write a dummy IV into the end of the first page
  unsigned char *iv = p + pagesize - 16;
  memset(iv, 0, 16);

  // setup a context for encryption
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ASSERT_NOT_NULL(ctx);

  // operations from here on may cause a SIGSEGV if we have got AES wrong, so
  // setup a signal handler so we can recover
  r = register_handler();
  ASSERT_EQ(r, 0);
  int j = setjmp(env);
  if (j == 0) {

    // do a dummy encryption to force use of the IV

    r = EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
    ASSERT_EQ(r, 1);

    unsigned char in[sizeof("hello world")];
    strcpy((char *)in, "hello world");

    unsigned char out[sizeof(in) + 16 - 1];

    r = EVP_EncryptUpdate(ctx, out, &(int){0}, in, sizeof(in));
    ASSERT_EQ(r, 1);

  } else if (j == 1) {

    // we unexpectedly triggered a SIGSEGV; fail
    FAIL("overread 16 byte IV");
  }

  // If we reached here, then we did not trigger a SIGSEGV. Yay!

  r = deregister_handler();
  ASSERT_EQ(r, 0);

  EVP_CIPHER_CTX_free(ctx);

  // we need to unprotect the page we previously protected because we are about
  // to give it back to the heap
  r = mprotect(p + pagesize, pagesize, PROT_READ | PROT_WRITE);
  ASSERT_EQ(r, 0);

  free(p);
}

TEST("AES128 reads at least 16 bytes of a supplied initialisation vector") {

  // create a dummy key
  unsigned char key[16] = {0};

  // Create a 16 byte IV where accessing the last byte will cause a trap. The
  // purpose of this is to detect if the AES algorithm reads less than 16 bytes.
  int pagesize = sysconf(_SC_PAGESIZE);
  assert(pagesize >= 16 && "AES IV does not fit in a page");
  unsigned char *p = aligned_alloc(pagesize, pagesize * 2);
  ASSERT_NOT_NULL(p);
  // write a dummy IV into the end of the first page
  unsigned char *iv = p + pagesize - 15;
  memset(iv, 0, 16);
  // make the second page inaccessible
  int r = mprotect(p + pagesize, pagesize, PROT_NONE);
  ASSERT_EQ(r, 0);

  // setup a context for encryption
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ASSERT_NOT_NULL(ctx);

  // operations from here on should cause a SIGSEGV if we understand AES, so
  // setup a signal handler so we can recover
  r = register_handler();
  ASSERT_EQ(r, 0);
  int j = setjmp(env);
  if (j == 0) {

    // do a dummy encryption to force use of the IV

    r = EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
    ASSERT_EQ(r, 1);

    unsigned char in[sizeof("hello world")];
    strcpy((char *)in, "hello world");

    unsigned char out[sizeof(in) + 16 - 1];

    r = EVP_EncryptUpdate(ctx, out, &(int){0}, in, sizeof(in));
    ASSERT_EQ(r, 1);

    // if we reached here then we did not trigger SIGSEGV :(
    FAIL("failed to read to the end of 16 byte IV");
  }

  // if we reached here, then we should have triggered a SIGSEGV
  ASSERT_EQ(j, 1);

  r = deregister_handler();
  ASSERT_EQ(r, 0);

  EVP_CIPHER_CTX_free(ctx);

  // we need to unprotect the page we previously protected because we are about
  // to give it back to the heap
  r = mprotect(p + pagesize, pagesize, PROT_READ | PROT_WRITE);
  ASSERT_EQ(r, 0);

  free(p);
}

// similar tests to the above follow, but for AES256

TEST("AES256 reads at most 256 bits of a supplied key") {

  // use a dummy initialisation vector because we do not care about the strength
  // of this test encryption
  unsigned char iv[16] = {0};

  // Create a 256-bit key where accessing memory immediately following the key
  // will cause a trap. The purpose of this is to detect if the AES algorithm
  // reads more than 256 bits.
  int pagesize = sysconf(_SC_PAGESIZE);
  assert(pagesize >= 32 && "AES key does not fit in a page");
  unsigned char *p = aligned_alloc(pagesize, pagesize * 2);
  ASSERT_NOT_NULL(p);
  // make the second page inaccessible
  int r = mprotect(p + pagesize, pagesize, PROT_NONE);
  ASSERT_EQ(r, 0);
  // write a dummy key into the end of the first page
  unsigned char *key = p + pagesize - 32;
  memset(key, 0, 32);

  // setup a context for encryption
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ASSERT_NOT_NULL(ctx);

  // operations from here on may cause a SIGSEGV if we have got AES wrong, so
  // setup a signal handler so we can recover
  r = register_handler();
  ASSERT_EQ(r, 0);
  int j = setjmp(env);
  if (j == 0) {

    // do a dummy encryption to force use of the key

    r = EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
    ASSERT_EQ(r, 1);

    unsigned char in[sizeof("hello world")];
    strcpy((char *)in, "hello world");

    unsigned char out[sizeof(in) + 16 - 1];

    r = EVP_EncryptUpdate(ctx, out, &(int){0}, in, sizeof(in));
    ASSERT_EQ(r, 1);

  } else if (j == 1) {

    // we unexpectedly triggered a SIGSEGV; fail
    FAIL("overread 256-bit buffer");
  }

  // If we reached here, then we did not trigger a SIGSEGV. Yay!

  r = deregister_handler();
  ASSERT_EQ(r, 0);

  EVP_CIPHER_CTX_free(ctx);

  // we need to unprotect the page we previously protected because we are about
  // to give it back to the heap
  r = mprotect(p + pagesize, pagesize, PROT_READ | PROT_WRITE);
  ASSERT_EQ(r, 0);

  free(p);
}

TEST("AES256 reads at least 256 bits of a supplied key") {

  unsigned char iv[16] = {0};

  // Create a 256-bit key where accessing its last byte will cause a trap. This
  // should allow us to detect if AES256 does not read to the end of the key.
  int pagesize = sysconf(_SC_PAGESIZE);
  assert(pagesize >= 32 && "AES key does not fit in a page");
  unsigned char *p = aligned_alloc(pagesize, pagesize * 2);
  ASSERT_NOT_NULL(p);
  // write a dummy key into the end of the first page and first byte of second
  unsigned char *key = p + pagesize - 31;
  memset(key, 0, 32);
  // make the second page inaccessible
  int r = mprotect(p + pagesize, pagesize, PROT_NONE);
  ASSERT_EQ(r, 0);

  // setup a context for encryption
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ASSERT_NOT_NULL(ctx);

  // operations from here on should cause a SIGSEGV if we understand AES, so
  // setup a signal handler so we can recover
  r = register_handler();
  ASSERT_EQ(r, 0);
  int j = setjmp(env);
  if (j == 0) {

    // do a dummy encryption to force use of the key

    r = EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
    ASSERT_EQ(r, 1);

    unsigned char in[sizeof("hello world")];
    strcpy((char *)in, "hello world");

    unsigned char out[sizeof(in) + 16 - 1];

    r = EVP_EncryptUpdate(ctx, out, &(int){0}, in, sizeof(in));
    ASSERT_EQ(r, 1);

    // if we reached here then we did not trigger SIGSEGV :(
    FAIL("failed to read to the end of 256-bit key");
  }

  // if we reached here, then we should have triggered a SIGSEGV
  ASSERT_EQ(j, 1);

  r = deregister_handler();
  ASSERT_EQ(r, 0);

  EVP_CIPHER_CTX_free(ctx);

  // we need to unprotect the page we previously protected because we are about
  // to give it back to the heap
  r = mprotect(p + pagesize, pagesize, PROT_READ | PROT_WRITE);
  ASSERT_EQ(r, 0);

  free(p);
}

TEST("AES256 reads at most 16 bytes of a supplied initialisation vector") {

  // Similar to the previous cases, a previous version of Passwand incorrectly
  // created a short initialisation vector of only 8 bytes. This test case and
  // the next ensure that we have the initialisation vector size correct at 16
  // bytes.

  // create a dummy key
  unsigned char key[32] = {0};

  // Create a 16 byte IV where accessing memory immediately following the IV
  // will cause a trap. The purpose of this is to detect if the AES algorithm
  // reads more than 16 bytes.
  int pagesize = sysconf(_SC_PAGESIZE);
  assert(pagesize >= 16 && "AES IV does not fit in a page");
  unsigned char *p = aligned_alloc(pagesize, pagesize * 2);
  ASSERT_NOT_NULL(p);
  // make the second page inaccessible
  int r = mprotect(p + pagesize, pagesize, PROT_NONE);
  ASSERT_EQ(r, 0);
  // write a dummy IV into the end of the first page
  unsigned char *iv = p + pagesize - 16;
  memset(iv, 0, 16);

  // setup a context for encryption
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ASSERT_NOT_NULL(ctx);

  // operations from here on may cause a SIGSEGV if we have got AES wrong, so
  // setup a signal handler so we can recover
  r = register_handler();
  ASSERT_EQ(r, 0);
  int j = setjmp(env);
  if (j == 0) {

    // do a dummy encryption to force use of the IV

    r = EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
    ASSERT_EQ(r, 1);

    unsigned char in[sizeof("hello world")];
    strcpy((char *)in, "hello world");

    unsigned char out[sizeof(in) + 16 - 1];

    r = EVP_EncryptUpdate(ctx, out, &(int){0}, in, sizeof(in));
    ASSERT_EQ(r, 1);

  } else if (j == 1) {

    // we unexpectedly triggered a SIGSEGV; fail
    FAIL("overread 16 byte IV");
  }

  // If we reached here, then we did not trigger a SIGSEGV. Yay!

  r = deregister_handler();
  ASSERT_EQ(r, 0);

  EVP_CIPHER_CTX_free(ctx);

  // we need to unprotect the page we previously protected because we are about
  // to give it back to the heap
  r = mprotect(p + pagesize, pagesize, PROT_READ | PROT_WRITE);
  ASSERT_EQ(r, 0);

  free(p);
}

TEST("AES256 reads at least 16 bytes of a supplied initialisation vector") {

  // create a dummy key
  unsigned char key[32] = {0};

  // Create a 16 byte IV where accessing the last byte will cause a trap. The
  // purpose of this is to detect if the AES algorithm reads less than 16 bytes.
  int pagesize = sysconf(_SC_PAGESIZE);
  assert(pagesize >= 16 && "AES IV does not fit in a page");
  unsigned char *p = aligned_alloc(pagesize, pagesize * 2);
  ASSERT_NOT_NULL(p);
  // write a dummy IV into the end of the first page
  unsigned char *iv = p + pagesize - 15;
  memset(iv, 0, 16);
  // make the second page inaccessible
  int r = mprotect(p + pagesize, pagesize, PROT_NONE);
  ASSERT_EQ(r, 0);

  // setup a context for encryption
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ASSERT_NOT_NULL(ctx);

  // operations from here on should cause a SIGSEGV if we understand AES, so
  // setup a signal handler so we can recover
  r = register_handler();
  ASSERT_EQ(r, 0);
  int j = setjmp(env);
  if (j == 0) {

    // do a dummy encryption to force use of the IV

    r = EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
    ASSERT_EQ(r, 1);

    unsigned char in[sizeof("hello world")];
    strcpy((char *)in, "hello world");

    unsigned char out[sizeof(in) + 16 - 1];

    r = EVP_EncryptUpdate(ctx, out, &(int){0}, in, sizeof(in));
    ASSERT_EQ(r, 1);

    // if we reached here then we did not trigger SIGSEGV :(
    FAIL("failed to read to the end of 16 byte IV");
  }

  // if we reached here, then we should have triggered a SIGSEGV
  ASSERT_EQ(j, 1);

  r = deregister_handler();
  ASSERT_EQ(r, 0);

  EVP_CIPHER_CTX_free(ctx);

  // we need to unprotect the page we previously protected because we are about
  // to give it back to the heap
  r = mprotect(p + pagesize, pagesize, PROT_READ | PROT_WRITE);
  ASSERT_EQ(r, 0);

  free(p);
}

TEST("encrypt: encrypt(\"\")") {
  const k_t key = {0};
  const iv_t iv = {0};
  uint8_t _pp[1] = {0};
  const ppt_t pp = {
      .data = _pp,
      .length = 0,
  };

  ct_t c;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ASSERT_NOT_NULL(ctx);

  int err = aes_encrypt_init(key, iv, ctx);
  ASSERT_EQ(err, PW_OK);

  err = aes_encrypt(ctx, &pp, &c);
  ASSERT_EQ(err, PW_OK);

  err = aes_encrypt_deinit(ctx);
  ASSERT_EQ(err, PW_OK);

  EVP_CIPHER_CTX_free(ctx);
  free(c.data);
}

TEST("encrypt: basic functionality") {
  const k_t key = {0};
  const iv_t iv = {0};
  uint8_t _pp[16] = {0};
  ppt_t pp = {
      .data = _pp,
      .length = sizeof(_pp),
  };
  memcpy(pp.data, "hello world", strlen("hello world"));

  ct_t c;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ASSERT_NOT_NULL(ctx);

  int err = aes_encrypt_init(key, iv, ctx);
  ASSERT_EQ(err, PW_OK);

  err = aes_encrypt(ctx, &pp, &c);
  ASSERT_EQ(err, PW_OK);
  ASSERT_GT(c.length, 0ul);

  err = aes_encrypt_deinit(ctx);
  ASSERT_EQ(err, PW_OK);

  EVP_CIPHER_CTX_free(ctx);
  free(c.data);
}

TEST("encrypt: with unaligned data") {
  const k_t key = {0};
  const iv_t iv = {0};
  uint8_t _pp[16] = {0};
  ppt_t pp = {
      .data = _pp,
      .length = strlen("hello world"),
  };
  memcpy(pp.data, "hello world", strlen("hello world"));

  ct_t c;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ASSERT_NOT_NULL(ctx);

  int err = aes_encrypt_init(key, iv, ctx);
  ASSERT_EQ(err, PW_OK);

  err = aes_encrypt(ctx, &pp, &c);
  ASSERT_NE(err, PW_OK);

  EVP_CIPHER_CTX_free(ctx);
}
