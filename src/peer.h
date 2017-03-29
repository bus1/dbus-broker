#pragma once

/*
 * Peers
 */

#include <c-macro.h>
#include <c-rbtree.h>
#include <stdlib.h>
#include <sys/types.h>
#include "dbus-sasl.h"
#include "dispatch.h"

typedef struct Bus Bus;
typedef struct DBusSocket DBusSocket;
typedef struct Peer Peer;
typedef struct UserEntry UserEntry;

struct Peer {
        DBusSASL sasl;
        bool authenticated : 1;
        DispatchFile dispatch_file;
        DBusSocket *socket;
        UserEntry *user;
        pid_t pid;
        char *seclabel;
        size_t n_seclabel;
        CList matches;
        CRBTree names;
        CRBNode rb;
        uint64_t id;
};

int peer_new(Peer **peerp,
             Bus *bus,
             int fd);
Peer *peer_free(Peer *peer);

int peer_dispatch(DispatchFile *file, uint32_t mask);

int peer_start(Peer *peer);
void peer_stop(Peer *peer);

C_DEFINE_CLEANUP(Peer *, peer_free);
