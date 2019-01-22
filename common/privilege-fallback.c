#include "privilege.h"

int drop_privileges(bool need_network __attribute__((unused))) {
    /* No-op */
    return 0;
}
