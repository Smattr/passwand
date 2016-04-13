#include <assert.h>
#include <CUnit/CUnit.h>
#include <openssl/evp.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "test.h"
#include <unistd.h>

static jmp_buf env;

static void handler(int signum) {
    assert(signum == SIGSEGV);
    longjmp(env, signum == SIGSEGV ? 1 : -1);
}

static int register_handler(void) {
    const struct sigaction sa = {
        .sa_handler = handler,
        .sa_flags = SA_NODEFER,
    };
    return sigaction(SIGSEGV, &sa, NULL);
}

static int deregister_handler(void) {
    const struct sigaction sa = {
        .sa_handler = SIG_DFL,
    };
    return sigaction(SIGSEGV, &sa, NULL);
}

TEST(aes_key_size1, "test AES128 reads only 128 bits of a supplied key") {

    /* This test is not probing the behaviour of Passwand's encryption
     * functionality, but rather AES128. A previous version of Passwand used a
     * 256-bit key with this algorithm, which I believe is excessive. AES128
     * should only need a 128-bit key. This test validates that AES128
     * encryption only reads the first 128 bits of a key given to it.
     */

    /* Use a dummy initialisation vector because we don't care about the
     * strength of this test encryption.
     */
    unsigned char iv[16] = { 0 };

    /* Create a 128-bit key where accessing memory immediately following the
     * key will cause a trap. The purpose of this is to detect if the AES
     * algorithm reads more than 128 bits.
     */
    int pagesize = sysconf(_SC_PAGESIZE);
    assert(pagesize >= 16 && "AES key does not fit in a page");
    void *p;
    int r = posix_memalign(&p, pagesize, pagesize * 2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    /* Make the second page inaccessible. */
    r = mprotect(p + pagesize, pagesize, PROT_NONE);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    /* Write a dummy key into the end of the first page. */
    unsigned char *key = p + pagesize - 16;
    memset(key, 0, 16);

    /* Setup a context for encryption. */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    CU_ASSERT_PTR_NOT_NULL_FATAL(ctx);

    /* Operations from here on may cause a SIGSEGV if we've got AES wrong, so
     * setup a signal handler so we can recover.
     */
    r = register_handler();
    CU_ASSERT_EQUAL_FATAL(r, 0);
    int j = setjmp(env);
    if (j == 0) {

        /* Do a dummy encryption to force use of the key. */

        r = EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
        CU_ASSERT_EQUAL_FATAL(r, 1);

        unsigned char in[sizeof "hello world"];
        strcpy((char*)in, "hello world");

        unsigned char out[sizeof(in) + 16 - 1];

        int len;
        r = EVP_EncryptUpdate(ctx, out, &len, in, sizeof(in));
        CU_ASSERT_EQUAL_FATAL(r, 1);

    } else if (j == 1) {

        /* We unexpectedly triggered a SIGSEGV; fail. */
        CU_FAIL("overread 128-bit buffer");

    }

    /* If we reached here, then we didn't trigger a SIGSEGV. Yay! */

    r = deregister_handler();
    CU_ASSERT_EQUAL_FATAL(r, 0);

    EVP_CIPHER_CTX_free(ctx);

    /* We need to unprotect the page we previously protected because we're
     * about to give it back to the heap.
     */
    r = mprotect(p + pagesize, pagesize, PROT_READ|PROT_WRITE);
    CU_ASSERT_EQUAL_FATAL(r, 0);

    free(p);
}

TEST(aes_key_size2, "test AES128 reads 128 bits of a supplied key") {

    /* This test is the companion to aes_key_size1, and tests that AES128 does
     * read 128 bits of the key, not less. Where code is similar, see the
     * comments in aes_key_size1.
     */

    unsigned char iv[16] = { 0 };

    /* Create a 128-bit key where accessing its last byte will cause a trap.
     * This should allow us to detect if AES128 does not read to the end of the
     * key.
     */
    int pagesize = sysconf(_SC_PAGESIZE);
    assert(pagesize >= 16 && "AES key does not fit in a page");
    void *p;
    int r = posix_memalign(&p, pagesize, pagesize * 2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    /* Write a dummy key into the end of the first page and first byte of second. */
    unsigned char *key = p + pagesize - 15;
    memset(key, 0, 16);
    /* Make the second page inaccessible. */
    r = mprotect(p + pagesize, pagesize, PROT_NONE);
    CU_ASSERT_EQUAL_FATAL(r, 0);

    /* Setup a context for encryption. */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    CU_ASSERT_PTR_NOT_NULL_FATAL(ctx);

    /* Operations from here on should cause a SIGSEGV if we understand AES, so
     * setup a signal handler so we can recover.
     */
    r = register_handler();
    CU_ASSERT_EQUAL_FATAL(r, 0);
    int j = setjmp(env);
    if (j == 0) {

        /* Do a dummy encryption to force use of the key. */

        r = EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
        CU_ASSERT_EQUAL_FATAL(r, 1);

        unsigned char in[sizeof "hello world"];
        strcpy((char*)in, "hello world");

        unsigned char out[sizeof(in) + 16 - 1];

        int len;
        r = EVP_EncryptUpdate(ctx, out, &len, in, sizeof(in));
        CU_ASSERT_EQUAL_FATAL(r, 1);

        /* If we reached here then we didn't trigger SIGSEGV :( */
        CU_FAIL("failed to read to the end of 128-bit key");

    }

    /* If we reached here, then we should have triggered a SIGSEGV. */
    CU_ASSERT_EQUAL_FATAL(j, 1);

    r = deregister_handler();
    CU_ASSERT_EQUAL_FATAL(r, 0);

    EVP_CIPHER_CTX_free(ctx);

    /* We need to unprotect the page we previously protected because we're
     * about to give it back to the heap.
     */
    r = mprotect(p + pagesize, pagesize, PROT_READ|PROT_WRITE);
    CU_ASSERT_EQUAL_FATAL(r, 0);

    free(p);
}
