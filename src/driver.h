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
int driver_goodbye(Peer *peer, bool silent);
