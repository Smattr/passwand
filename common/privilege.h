#pragma once

#include <stdbool.h>

/** Drop any privileges that are not required for future operation
 *
 * This is supporting a defence-in-depth and/or Principal of Least Privilege
 * approach. On platforms with no privilege restriction APIs this is a no-op.
 *
 * @param need_network Whether the caller will be needed to make network
 *   accesses.
 * @return 0 on success. For most situations, the right way to handle a non-zero
 *   return value is to exit immediately.
 */
int drop_privileges(bool need_network);
