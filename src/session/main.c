/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: D-Bus Broker Developers */

/*
 * D-Bus Session Initiator Main Entry
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include "session/main.h"

int main(int argc, char **argv) {
        return session_run((int32_t)argc, (uint8_t **)argv);
}
