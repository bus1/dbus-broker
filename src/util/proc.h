#pragma once

/*
 * Proc Helpers
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include <unistd.h>

#define PROC_PID_SELF ((pid_t)0)

enum {
        _PROC_E_SUCCESS,

        PROC_E_NOT_FOUND,
};

int proc_field(const char *data, const char *key, char **valuep);

int proc_get_seclabel(pid_t pid, char **labelp, size_t *n_labelp);
