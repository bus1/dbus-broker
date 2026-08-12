#pragma once

/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: D-Bus Broker Developers */

/*
 * Systemd Utilities
 */

#include <c-stdaux.h>
#include <stdlib.h>

int systemd_escape_unit(char **escapedp, const char *unescaped);
