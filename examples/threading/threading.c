#include "threading.h"
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>   // usleep
#include <stdlib.h>
#include <stdio.h>

#define DEBUG_LOG(msg,...)
// #define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

/*
 * Private extension that embeds the public struct as the FIRST member.
 * This guarantees that the pointer value to the whole allocation is the same
 * as the pointer to the embedded public struct (&ext->pub == (void*)ext).
 * The unit tests can treat it as `struct thread_data*`, read the flag,
 * and `free()` it safely.
 */
struct thread_data_ext {
    struct thread_data pub;            // MUST be first
    pthread_mutex_t *mutex;
    int wait_to_obtain_ms;
    int wait_to_release_ms;
};

/* Thread: wait_to_obtain -> lock -> wait_to_release -> unlock -> mark success */
static void* threadfunc(void* thread_param)
{
    if (thread_param == NULL) return NULL;

    struct thread_data_ext* ext = (struct thread_data_ext*)thread_param;

    // default to failure; flip to true only on successful lock/hold/unlock
    ext->pub.thread_complete_success = false;

    if (ext->wait_to_obtain_ms > 0)
        usleep((useconds_t)ext->wait_to_obtain_ms * 1000U);

    if (pthread_mutex_lock(ext->mutex) != 0) {
        ERROR_LOG("pthread_mutex_lock failed");
        return ext; // tests will free this pointer
    }

    if (ext->wait_to_release_ms > 0)
        usleep((useconds_t)ext->wait_to_release_ms * 1000U);

    if (pthread_mutex_unlock(ext->mutex) != 0) {
        ERROR_LOG("pthread_mutex_unlock failed");
        return ext;
    }

    ext->pub.thread_complete_success = true;
    return ext;  // IMPORTANT: return the allocation start
}

bool start_thread_obtaining_mutex(pthread_t *thread,
                                  pthread_mutex_t *mutex,
                                  int wait_to_obtain_ms,
                                  int wait_to_release_ms)
{
    if (thread == NULL || mutex == NULL) return false;

    struct thread_data_ext *ext = (struct thread_data_ext*)malloc(sizeof(*ext));
    if (ext == NULL) {
        ERROR_LOG("malloc failed");
        return false;
    }

    // initialize extended fields
    ext->mutex = mutex;
    ext->wait_to_obtain_ms  = wait_to_obtain_ms;
    ext->wait_to_release_ms = wait_to_release_ms;
    ext->pub.thread_complete_success = false;

    int rc = pthread_create(thread, NULL, threadfunc, ext);
    if (rc != 0) {
        ERROR_LOG("pthread_create failed");
        free(ext);
        return false;
    }
    return true;
}

