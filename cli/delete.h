#pragma once

#include "../common/argparse.h"
#include "cli.h"
#include <passwand/passwand.h>
#include <stddef.h>

int delete(const options_t *options __attribute__((unused)), const master_t *master,
    passwand_entry_t *entries, size_t entry_len);
