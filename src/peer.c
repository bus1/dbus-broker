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
int peer_new(Peer **peerp, uint64_t id, UserEntry *user) {
        _c_cleanup_(peer_freep) Peer *peer = NULL;

        if (user->n_peers < 1)
                return -EDQUOT;

        peer = calloc(1, sizeof(*peer));
        if (!peer)
                return -ENOMEM;

        user->n_peers --;

        peer->id = id;
        peer->user = user_entry_ref(user);
        c_rbnode_init(&peer->rb);

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

        assert(!peer->names.root);
        assert(!c_rbnode_is_linked(&peer->rb));

        peer->user->n_peers ++;

        user_entry_unref(peer->user);
        free(peer);

        return NULL;
}
