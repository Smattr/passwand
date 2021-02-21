#include "check.h"
#include "../common/argparse.h"
#include "cli.h"
#include "print.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static atomic_bool found_weak;

static int initialize(const main_t *mainpass __attribute__((unused)),
                      passwand_entry_t *entries __attribute__((unused)),
                      size_t entry_len __attribute__((unused))) {

  // initialize OpenSSL
  SSL_load_error_strings();
  SSL_library_init();

  return 0;
}

static bool in_dictionary(const char *s) {

  // open the system dictionary
  FILE *f = fopen("/usr/share/dict/words", "r");
  if (f == NULL) {
    // failed; perhaps the file doesn't exist
    return false;
  }

  bool result = false;

  char *line = NULL;
  size_t size = 0;
  for (;;) {
    ssize_t r = getline(&line, &size, f);
    if (r < 0) {
      // done or error
      break;
    }

    if (r > 0) {
      // delete the trailing \n
      if (line[strlen(line) - 1] == '\n')
        line[strlen(line) - 1] = '\0';

      if (strcmp(s, line) == 0) {
        result = true;
        break;
      }
    }
  }

  free(line);
  fclose(f);

  return result;
}

static void hash(const char *s, char hex[static SHA_DIGEST_LENGTH * 2 + 1]) {

  assert(hex != NULL);

  // calculate the SHA1 hash of the input
  unsigned char digest[SHA_DIGEST_LENGTH];
  SHA1((const unsigned char *)s, strlen(s), digest);

  // convert the digest to hex digits
  for (size_t i = 0; i < sizeof(digest); i++)
    sprintf(&hex[i * 2], "%02X", (int)digest[i]);
}

static const char *get_ssl_error(const SSL *ssl, int ret) {
  switch (SSL_get_error(ssl, ret)) {
  case SSL_ERROR_ZERO_RETURN:
    return "SSL_ERROR_ZERO_RETURN (see man SSL_get_error)";
  case SSL_ERROR_WANT_READ:
    return "SSL_ERROR_WANT_READ (see man SSL_get_error)";
  case SSL_ERROR_WANT_WRITE:
    return "SSL_ERROR_WANT_WRITE (see man SSL_get_error)";
  case SSL_ERROR_WANT_CONNECT:
    return "SSL_ERROR_WANT_CONNECT (see man SSL_get_error)";
  case SSL_ERROR_WANT_ACCEPT:
    return "SSL_ERROR_WANT_ACCEPT (see man SSL_get_error)";
  case SSL_ERROR_WANT_X509_LOOKUP:
    return "SSL_ERROR_WANT_X509_LOOKUP (see man SSL_get_error)";
  case SSL_ERROR_SYSCALL:
    return "SSL_ERROR_SYSCALL (see man SSL_get_error)";
  case SSL_ERROR_SSL:
    return "SSL_ERROR_SSL (see man SSL_get_error)";
  default:
    return "unknown";
  }
}

static void skip_over(const char **p, char c) {
  while (**p == c)
    (*p)++;
}

static void skip_until(const char **p, char c) {
  while (**p != '\0' && **p != c)
    (*p)++;
}

static void skip_past(const char **p, char c) {
  skip_until(p, c);
  skip_over(p, c);
}

// HIBP's DNS records. Access is protected by dns_lock below.
static struct addrinfo *dns_info;
static bool dns_looked_up;

static char *hibp_data(const char *hex, const char **error) {

  assert(hex != NULL);
  assert(strlen(hex) >= 5 && "hash value not long enough for HIBP SHA1 prefix");
  assert(isxdigit(hex[0]) && isxdigit(hex[1]) && isxdigit(hex[2]) &&
         isxdigit(hex[3]) && isxdigit(hex[4]) && "non hex prefix of hash");

  static pthread_mutex_t dns_lock = PTHREAD_MUTEX_INITIALIZER;

  {
    int res __attribute__((unused)) = pthread_mutex_lock(&dns_lock);
    assert(res == 0);
  }

  // wrap the DNS lookup to ensure we only do it once across threads
  int r = 0;
  if (!dns_looked_up) {
    assert(dns_info == NULL);

    // lookup HIBP's IP address(es)
    const struct addrinfo hints = {.ai_family = AF_UNSPEC,
                                   .ai_socktype = SOCK_STREAM,
                                   .ai_protocol = IPPROTO_TCP};
    r = getaddrinfo("api.pwnedpasswords.com", "https", &hints, &dns_info);

    dns_looked_up = true;
  }

  const struct addrinfo *ai = dns_info;

  {
    int res __attribute__((unused)) = pthread_mutex_unlock(&dns_lock);
    assert(res == 0);
  }

  if (r != 0) {
    if (error != NULL)
      *error = gai_strerror(r);
    return NULL;
  }

  // open a TCP socket
  int fd = -1;
  for (const struct addrinfo *i = ai; i != NULL; i = i->ai_next) {

    fd = socket(i->ai_family, i->ai_socktype, i->ai_protocol);
    if (fd < 0)
      continue;

    if (connect(fd, i->ai_addr, i->ai_addrlen) != 0) {
      close(fd);
      continue;
    }

    break;
  }

  if (fd < 0) {
    // failed to connect to any returned IPs
    if (error != NULL)
      *error =
          "failed to find a reachable IP address for api.pwnedpasswords.com";
    return NULL;
  }

  // setup an SSL context
  SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
  if (ctx == NULL) {
    close(fd);
    if (error != NULL)
      *error = "creation of SSL context failed";
    return NULL;
  }

  // attach an SSL connection to the socket
  SSL *ssl = SSL_new(ctx);
  if (ssl == NULL) {
    SSL_CTX_free(ctx);
    close(fd);
    if (error != NULL)
      *error = "creating SSL object failed";
    return NULL;
  }
  if (SSL_set_fd(ssl, fd) != 1) {
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    if (error != NULL)
      *error = "associating SSL object with socket file descriptor failed";
    return NULL;
  }

  // negotiate the SSL handshake
  if (SSL_connect(ssl) != 1) {
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    if (error != NULL)
      *error = "SSL negotiation failed";
    return NULL;
  }

  // send the request
  {
    char buffer[sizeof(
        "GET /range/XXXXX HTTP/1.0\r\n"
        "Host: api.pwnedpasswords.com\r\n"
        "User-Agent: passwand <https://github.com/Smattr/passwand>\r\n"
        "\r\n")];
    sprintf(buffer,
            "GET /range/%.5s HTTP/1.0\r\n"
            "Host: api.pwnedpasswords.com\r\n"
            "User-Agent: passwand <https://github.com/Smattr/passwand>\r\n"
            "\r\n",
            hex);

    size_t len = strlen(buffer);
    size_t sent = 0;
    while (sent < len) {
      int b = SSL_write(ssl, buffer + sent, len - sent);
      if (b < 0) {
        if (error != NULL)
          *error = get_ssl_error(ssl, b);
        (void)SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        return NULL;
      }
      sent += b;
    }
  }

  // receive the response
  char *data = NULL;
  {
    char *response = malloc(BUFSIZ);
    if (response == NULL) {
      (void)SSL_shutdown(ssl);
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      close(fd);
      if (error != NULL)
        *error = "out of memory";
      return NULL;
    }
    size_t size = BUFSIZ / sizeof(char);
    size_t received = 0;
    for (;;) {
      int b = SSL_read(ssl, response + received, size - received - 1);
      if (b == 0) {
        response[received] = '\0';
        data = response;
        break;
      } else if (b < 0) {
        if (error != NULL)
          *error = get_ssl_error(ssl, b);
        free(response);
        (void)SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        return NULL;
      }
      received += b;
      if (received == size - 1) {
        char *p = realloc(response, size * 2);
        if (p == NULL) {
          free(response);
          (void)SSL_shutdown(ssl);
          SSL_free(ssl);
          SSL_CTX_free(ctx);
          close(fd);
          if (error != NULL)
            *error = "out of memory";
          return NULL;
        }
        response = p;
        size *= 2;
      }
    }
  }

  (void)SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  close(fd);

  // read the response line, skipping over the HTTP version
  const char *p = data;
  skip_past(&p, ' ');
  if (strncmp(p, "200 ", sizeof("200 ") - 1) != 0) {
    free(data);
    if (error != NULL)
      *error = "HTTP response was not 200 OK";
    return NULL;
  }

  // skip over the header to the response body
  bool empty_line = false;
  while (!empty_line && *p != '\0') {
    empty_line = true;
    if (*p != '\0' && *p != '\r')
      empty_line = false;
    skip_past(&p, '\r');
    skip_over(&p, '\n');
  }

  // shuffle the content so the caller gets only the body
  memmove(data, p, strlen(p) + 1);

  return data;
}

static void loop_body(const char *space, const char *key, const char *value) {
  assert(space != NULL);
  assert(key != NULL);
  assert(value != NULL);

  // if we were given a space, check that this entry is within it
  if (options.space != NULL && strcmp(options.space, space) != 0)
    return;

  // if we were given a key, check that this entry matches it
  if (options.key != NULL && strcmp(options.key, key) != 0)
    return;

  if (in_dictionary(value)) {
    print("%s/%s: weak password (dictionary word)\n", space, key);
    found_weak = true;
  } else {

    // hash the password
    char h[SHA_DIGEST_LENGTH * 2 + 1];
    hash(value, h);

    // ask what Have I Been Pwned knows about this hash
    const char *error = NULL;
    char *data = hibp_data(h, &error);

    if (data == NULL) {
      print("%s/%s: skipped (%s)\n", space, key,
            error == NULL ? "unknown cause" : error);
      return;
    }

    // check if the suffix of our hash was in the HIBP data
    size_t candidates = 0;
    bool found = false;
    unsigned long count = ULONG_MAX;
    for (const char *p = data; *p != '\0';) {
      candidates++;
      if (!found && strncmp(&h[5], p, sizeof(h) - 1 - 5) == 0) {
        found = true;
        skip_past(&p, ':');
        count = strtoul(p, NULL, 10);
      }
      skip_past(&p, '\n');
    }

    if (found) {
      print("%s/%s: weak password (found in password breaches %lu times)\n",
            space, key, count);
      found_weak = true;
    } else {
      print("%s/%s: OK (searched %zu candidate breached password hashes)\n",
            space, key, candidates);
    }

    free(data);
  }
}

static int finalize(void) {
  if (dns_info != NULL)
    freeaddrinfo(dns_info);

  return found_weak ? -1 : 0;
}

const command_t check = {
    .need_space = OPTIONAL,
    .need_key = OPTIONAL,
    .need_value = DISALLOWED,
    .access = LOCK_SH,
    .initialize = initialize,
    .loop_body = loop_body,
    .finalize = finalize,
};
