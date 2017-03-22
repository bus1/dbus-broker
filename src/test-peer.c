/*
 * Test Peer
 */

#include <c-macro.h>
#include <stdlib.h>
#include "bus.h"
#include "peer.h"
#include "user.h"

static void test_setup(void) {
        _c_cleanup_(bus_freep) Bus *bus = NULL;
        UserEntry *user;
        Peer *peer;
        int r;

        r = bus_new(&bus, 1024, 1024, 1024);
        assert(r >= 0);
        r = user_entry_ref_by_uid(bus->users, &user, 1);
        assert(r >= 0);
        r = peer_new(&peer, bus->ids ++, user);
        assert(r >= 0);

        peer_free(peer);
        user_entry_unref(user);
}

int main(int argc, char **argv) {
        test_setup();
        return 0;
}
