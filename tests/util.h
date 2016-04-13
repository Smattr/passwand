#pragma once

/** Run the given command, capturing its output.
 *
 * @param command Command to run
 * @param output Output argument to write stdout to
 * @return 0 on success
 */
int run(const char *command, char **output);
