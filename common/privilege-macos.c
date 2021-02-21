#include "privilege.h"
#include <sandbox.h>

// Apple claim sandbox_init() and friends are deprecated, but I don't see how to
// apply its successor, App Sandbox, to a C application.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

int drop_privileges(bool need_network) {

  if (need_network) {
    // there's no ready made sandbox profile on macOS that suits our needs, so
    // don't sandbox this case
    return 0;
  }

  // Tell the OS we don't plan to do any networking.
  char *err;
  int r = sandbox_init(kSBXProfileNoNetwork, SANDBOX_NAMED, &err);

  if (r != 0)
    sandbox_free_error(err);

  return r;
}

#pragma clang diagnostic pop
