#pragma once

#include "../common/argparse.h"
#include "cli.h"
#include <passwand/passwand.h>
#include <stddef.h>

int get(const options_t *options, master_t *master, passwand_entry_t *entries,
    size_t entry_len);
