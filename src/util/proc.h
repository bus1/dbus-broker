#pragma once

/*
 * Proc Helpers
 */

#include <c-macro.h>
#include <stdlib.h>

int proc_get_seclabel(char **labelp, size_t *lenp);
