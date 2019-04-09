#pragma once

/*
 * Proc Helpers
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include <unistd.h>

#define PROC_SELF ((pid_t)0)

int proc_get_seclabel(pid_t pid, char **labelp, size_t *n_labelp);
