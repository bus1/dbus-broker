#pragma once

/*
 * Bus Diagnostics
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include "util/log.h"

typedef struct Message Message;
typedef struct Peer Peer;

int diag_quota_queue_reply(Peer *sender, Peer *receiver, Message *m, LogProvenance prov);
int diag_quota_dequeue(Peer *peer, LogProvenance prov);
