#pragma once

/*
 * DBus Driver
 */

#include <stdlib.h>

typedef struct Message Message;
typedef struct Peer Peer;

int driver_handle_message(Peer *peer, Message *message);

void driver_notify_name_owner_change(const char *name, Peer *old_peer, Peer *new_peer);
