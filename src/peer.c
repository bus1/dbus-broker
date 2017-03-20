/*
 * Peers
 */

#include <c-macro.h>
#include <stdlib.h>
#include "peer.h"
#include "user.h"

/**
 * peer_new() - XXX
 */
int peer_new(Peer **peerp, UserEntry *user) {
        _c_cleanup_(peer_freep) Peer *peer = NULL;

        peer = calloc(1, sizeof(*peer));
        if (!peer)
                return -ENOMEM;

        peer->user = user_entry_ref(user);

        *peerp = peer;
        peer = NULL;
        return 0;
}

/**
 * peer_free() - XXX
 */
Peer *peer_free(Peer *peer) {
        if (!peer)
                return NULL;

        user_entry_unref(peer->user);
        free(peer);

        return NULL;
}
