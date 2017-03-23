/*
 * Test Peer
 */

#include <c-macro.h>
#include <stdlib.h>
#include "bus.h"
#include "peer.h"

static void test_setup(void) {
        _c_cleanup_(bus_freep) Bus *bus = NULL;
        _c_cleanup_(peer_freep) Peer *peer = NULL;
        int r;

        r = bus_new(&bus, 1024, 1024, 1024, 1024);
        assert(r >= 0);

        r = peer_new(bus, &peer, 1);
        assert(r >= 0);
}

int main(int argc, char **argv) {
        test_setup();
        return 0;
}
