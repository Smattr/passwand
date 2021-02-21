#pragma once

// print to stdout thread-safely
void print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

// print to stderr thread-safely
void eprint(const char *fmt, ...) __attribute((format(printf, 1, 2)));
