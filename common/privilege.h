#pragma once

/** Drop any privileges that are not required for future operation
 *
 * This is supporting a defence-in-depth and/or Principal of Least Privilege
 * approach. On platforms with no privilege restriction APIs this is a no-op.
 *
 * @return 0 on success. For most situations, the right way to handle a non-zero
 *   return value is to exit immediately.
 */
int drop_privileges(void);
