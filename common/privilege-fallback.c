#include "privilege.h"

int drop_privileges(bool need_network __attribute__((unused))) {
  // no-op
  return 0;
}
