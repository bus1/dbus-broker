/*
 * Test Peer
 */

#include <c-macro.h>
#include <stdlib.h>
#include "peer.h"
#include "user.h"

static void test_setup(void) {
        UserRegistry *registry;
        UserEntry *user;
        Peer *peer;
        int r;

        assert(user_registry_new(&registry, 1024, 1024, 1024) >= 0);
        assert(user_entry_ref_by_uid(registry, &user, 1) >= 0);

        r = peer_new(&peer, user);
        assert(r >= 0);

        peer_free(peer);
        user_entry_unref(user);
        user_registry_free(registry);
}

int main(int argc, char **argv) {
        test_setup();
        return 0;
}
