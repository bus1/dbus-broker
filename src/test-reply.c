/*
 * Test Reply Tracking
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "bus.h"
#include "reply.h"
#include "peer.h"

static void test_basic(Peer *peer1, Peer *peer2) {
        ReplyRegistry registry;
        ReplySlot *slot1, *slot2;
        int r;

        reply_registry_init(&registry);

        r = reply_slot_new(&slot1, &registry, peer1, 1);
        assert(!r);

        r = reply_slot_new(&slot1, &registry, peer1, 1);
        assert(r == REPLY_E_EXISTS);

        slot2 = reply_slot_get_by_id(&registry, peer1->id, 1);
        assert(slot2 == slot1);

        slot2 = reply_slot_get_by_id(&registry, peer1->id, 2);
        assert(!slot2);

        slot2 = reply_slot_get_by_id(&registry, peer2->id, 1);
        assert(!slot2);

        reply_slot_free(slot1);
        reply_registry_deinit(&registry);
}

int main(int argc, char **argv) {
        DispatchContext dispatcher = DISPATCH_CONTEXT_NULL(dispatcher);
        _c_cleanup_(bus_freep) Bus *bus = NULL;
        Peer *peer1, *peer2;
        int pair[2], r;

        r = dispatch_context_init(&dispatcher);
        assert(r >= 0);

        r = bus_new(&bus, 1024, 1024, 1024, 1024, 1024);
        assert(r >= 0);

        r = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
        assert(r >= 0);

        r = peer_new_with_fd(&peer1, bus, &dispatcher, pair[0]);
        assert(r >= 0);

        r = peer_new_with_fd(&peer2, bus, &dispatcher, pair[1]);
        assert(r >= 0);

        test_basic(peer1, peer2);

        peer_free(peer1);
        peer_free(peer2);
        dispatch_context_deinit(&dispatcher);
        return 0;
}
