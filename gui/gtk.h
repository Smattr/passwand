#pragma once

#include <pthread.h>

/** Initialise GTK-based back end
 */
void gui_gtk_init(void);

// a lock to prevent multiple concurrent calls to GTK or other GUI APIs
extern pthread_mutex_t gtk_lock;
