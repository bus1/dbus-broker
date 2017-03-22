#pragma once

/*
 * DBus Driver
 */

#include <stdlib.h>
#include "peer.h"

static inline void dbus_driver_notify_name_owner_change(const char *name,
                                                        Peer *old_peer,
                                                        Peer *new_peer) {
        assert(old_peer || new_peer);
        assert(!old_peer || c_rbnode_is_linked(&old_peer->rb));
        assert(!new_peer || c_rbnode_is_linked(&new_peer->rb));
        assert(name || !old_peer || !new_peer);
}

