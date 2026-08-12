#pragma once

/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: D-Bus Broker Developers */

/*
 * Bus Diagnostics
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include "util/log.h"

typedef struct MatchRule MatchRule;
typedef struct Message Message;
typedef struct Peer Peer;

int diag_quota_queue_reply(Peer *sender, Peer *receiver, Message *m, LogProvenance prov);
int diag_quota_dequeue(Peer *peer, LogProvenance prov);

int diag_dispatch_stats(Bus *bus, LogProvenance prov);

int diag_match_without_sender(Peer *peer, MatchRule *rule, LogProvenance prov);
