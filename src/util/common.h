#pragma once

/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: D-Bus Broker Developers */

/**
 * Common definitions and helpers.
 */

#include <stdlib.h>

enum {
        UTIL_TRISTATE_UNSET,
        UTIL_TRISTATE_YES,
        UTIL_TRISTATE_NO,

        _UTIL_TRISTATE_N,
};

