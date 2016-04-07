#pragma once

/** Securely erase the memory backing a password.
 *
 * If input is the NULL pointer, this function is a no-op.
 *
 * @param s A NUL-terminated string
 * @return 0 on success
 */
int passwand_erase(char *s);
