#pragma once

/*
 * Systemd Utilities
 */

#include <c-stdaux.h>
#include <stdlib.h>

int systemd_escape_unit(char **escapedp, const char *unescaped);
