#pragma once

#include <pthread.h>

// a lock to prevent multiple concurrent calls to GTK or other GUI APIs
extern pthread_mutex_t gtk_lock;
