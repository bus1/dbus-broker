#pragma once

/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: D-Bus Broker Developers */

/*
 * D-Bus Broker Main Entry
 */

#include <c-stdaux.h>
#include <stdlib.h>

enum {
        _MAIN_SUCCESS,
        MAIN_EXIT,
        MAIN_FAILED,
};

extern int main_arg_controller;
