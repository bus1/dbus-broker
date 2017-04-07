#pragma once

/*
 * DBus Driver
 */

#include <stdlib.h>

typedef struct Message Message;
typedef struct Peer Peer;

int driver_dispatch_interface(Peer *peer,
                              uint32_t serial,
                              const char *interface,
                              const char *member,
                              const char *path,
                              const char *signature,
                              Message *message);

void driver_notify_name_owner_change(const char *name, Peer *old_peer, Peer *new_peer);
