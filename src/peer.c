/*
 * Peers
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/types.h>
#include "bus.h"
#include "peer.h"
#include "user.h"

/**
 * peer_new() - XXX
 */
int peer_new(Bus *bus, Peer **peerp, uid_t uid) {
        _c_cleanup_(peer_freep) Peer *peer = NULL;
        _c_cleanup_(user_entry_unrefp) UserEntry *user = NULL;
        int r;

        r = user_entry_ref_by_uid(bus->users, &user, uid);
        if (r < 0)
                return r;

        if (user->n_peers < 1)
                return -EDQUOT;

        peer = calloc(1, sizeof(*peer));
        if (!peer)
                return -ENOMEM;

        user->n_peers --;

        peer->id = bus->ids ++;
        c_rbnode_init(&peer->rb);
        peer->user = user;
        user = NULL;

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
