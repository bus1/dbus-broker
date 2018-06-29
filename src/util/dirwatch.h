#pragma once

/*
 * Directory Watch
 */

#include <c-macro.h>
#include <stdlib.h>

typedef struct Dirwatch Dirwatch;

enum {
        _DIRWATCH_E_SUCCESS,

        DIRWATCH_E_TRIGGERED,
};

struct Dirwatch {
        int inotify_fd;
};

#define DIRWATCH_NULL(_x) {                                                     \
                .inotify_fd = -1,                                               \
        }

/* dirwatch */

int dirwatch_new(Dirwatch **dwp);
Dirwatch *dirwatch_free(Dirwatch *dw);

int dirwatch_get_fd(Dirwatch *dw);
int dirwatch_dispatch(Dirwatch *dw);
int dirwatch_add(Dirwatch *dw, const char *path);

/* inline helpers */

static inline void dirwatch_freep(Dirwatch **dw) {
        if (*dw)
                dirwatch_free(*dw);
}
