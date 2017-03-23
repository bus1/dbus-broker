/*
 * Test Name Registry
 */

#include <c-macro.h>
#include <stdlib.h>
#include "bus.h"
#include "name.h"
#include "peer.h"
#include "user.h"

static void test_setup(void) {
        _c_cleanup_(bus_freep) Bus *bus = NULL;
        _c_cleanup_(peer_freep) Peer *peer = NULL;
        Peer *p;
        uint32_t reply;
        int r;

        r = bus_new(&bus, 1024, 1024, 1024, 1024);
        assert(r >= 0);

        r = peer_new(bus, &peer, 1);
        assert(r >= 0);

        bus_register_peer(bus, peer);
        p = bus_find_peer(bus, 0);
        assert(p == peer);

        r = name_registry_request_name(bus->names, peer, "foobar", 0, &reply);
        assert(r >= 0);
        p = name_registry_resolve_name(bus->names, "foobar");
        assert(p == peer);
        assert(reply == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);
        name_registry_release_name(bus->names, peer, "foobar", &reply);
        assert(reply == DBUS_RELEASE_NAME_REPLY_RELEASED);
        p = name_registry_resolve_name(bus->names, "foobar");
        assert(p == NULL);

        name_registry_release_all_names(bus->names, peer);
        p = bus_find_peer(bus, 0);
        assert(p == peer);
        bus_unregister_peer(bus, peer);
        p = bus_find_peer(bus, 0);
        assert(p == NULL);
}

static void test_release(void) {
        _c_cleanup_(bus_freep) Bus *bus = NULL;
        _c_cleanup_(peer_freep) Peer *peer1 = NULL, *peer2 = NULL;
        uint32_t reply;
        int r;

        r = bus_new(&bus, 1024, 1024, 1024, 1024);
        assert(r >= 0);

        r = peer_new(bus, &peer1, 1);
        assert(r >= 0);
        r = peer_new(bus, &peer2, 1);
        assert(r >= 0);
        bus_register_peer(bus, peer1);
        bus_register_peer(bus, peer2);

        r = name_registry_request_name(bus->names, peer1, "foobar", 0, &reply);
        assert(r >= 0);

        name_registry_release_name(bus->names, peer1, "baz", &reply);
        assert(reply == DBUS_RELEASE_NAME_REPLY_NON_EXISTENT);
        name_registry_release_name(bus->names, peer2, "foobar", &reply);
        assert(reply == DBUS_RELEASE_NAME_REPLY_NOT_OWNER);
        name_registry_release_name(bus->names, peer1, "foobar", &reply);
        assert(reply == DBUS_RELEASE_NAME_REPLY_RELEASED);

        name_registry_release_all_names(bus->names, peer2);
        bus_unregister_peer(bus, peer2);
        name_registry_release_all_names(bus->names, peer1);
        bus_unregister_peer(bus, peer1);
}

static void test_queue(void) {
        _c_cleanup_(bus_freep) Bus *bus = NULL;
        _c_cleanup_(peer_freep) Peer *peer1 = NULL, *peer2 = NULL;
        Peer *peer;
        uint32_t reply;
        int r;

        r = bus_new(&bus, 1024, 1024, 1024, 1024);
        assert(r >= 0);

        r = peer_new(bus, &peer1, 1);
        assert(r >= 0);
        r = peer_new(bus, &peer2, 1);
        assert(r >= 0);
        bus_register_peer(bus, peer1);
        bus_register_peer(bus, peer2);

        /* first to request */
        r = name_registry_request_name(bus->names, peer1, "foobar", 0, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);
        /* verify the primary owner */
        peer = name_registry_resolve_name(bus->names, "foobar");
        assert(peer == peer1);
        /* already the owner */
        r = name_registry_request_name(bus->names, peer1, "foobar", 0, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER);
        /* refuse to queue */
        r = name_registry_request_name(bus->names, peer2, "foobar",
                                       DBUS_NAME_FLAG_DO_NOT_QUEUE, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_EXISTS);
        /* try to overtake, but owner won't allow it */
        r = name_registry_request_name(bus->names, peer2, "foobar",
                                       DBUS_NAME_FLAG_DO_NOT_QUEUE |
                                       DBUS_NAME_FLAG_REPLACE_EXISTING, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_EXISTS);
        /* queue */
        r = name_registry_request_name(bus->names, peer2, "foobar", 0, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_IN_QUEUE);
        /* verify that the primary owner was untouched */
        peer = name_registry_resolve_name(bus->names, "foobar");
        assert(peer == peer1);
        /* dequeu again */
        name_registry_release_name(bus->names, peer2, "foobar", &reply);
        assert(reply == DBUS_RELEASE_NAME_REPLY_RELEASED);
        /* verify that the primary owner was untouched */
        peer = name_registry_resolve_name(bus->names, "foobar");
        assert(peer == peer1);
        /* try to overtake, but wait in queue if it fails */
        r = name_registry_request_name(bus->names, peer2, "foobar",
                                       DBUS_NAME_FLAG_REPLACE_EXISTING, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_IN_QUEUE);
        /* again */
        r = name_registry_request_name(bus->names, peer2, "foobar",
                                       DBUS_NAME_FLAG_REPLACE_EXISTING, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_IN_QUEUE);
        /* update primary owner to allow replacement */
        r = name_registry_request_name(bus->names, peer1, "foobar",
                                       DBUS_NAME_FLAG_ALLOW_REPLACEMENT,
                                       &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER);
        /* queue again, but do not attempt to overtake */
        r = name_registry_request_name(bus->names, peer2, "foobar", 0, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_IN_QUEUE);
        /* verify that the primary owner was untouched */
        peer = name_registry_resolve_name(bus->names, "foobar");
        assert(peer == peer1);
        /* overtake primary owner, allow to be replaced ourselves and refuse to
         * queue */
        r = name_registry_request_name(bus->names, peer2, "foobar",
                                       DBUS_NAME_FLAG_REPLACE_EXISTING |
                                       DBUS_NAME_FLAG_ALLOW_REPLACEMENT |
                                       DBUS_NAME_FLAG_DO_NOT_QUEUE,
                                       &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);
        /* verify that the primary owner was changed */
        peer = name_registry_resolve_name(bus->names, "foobar");
        assert(peer == peer2);
        /* overtake again */
        r = name_registry_request_name(bus->names, peer1, "foobar",
                                       DBUS_NAME_FLAG_REPLACE_EXISTING, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);
        /* verify that the primary owner was reverted to the original */
        peer = name_registry_resolve_name(bus->names, "foobar");
        assert(peer == peer1);
        /* verify that the old primary owner is no longer on queue */
        name_registry_release_name(bus->names, peer2, "foobar", &reply);
        assert(reply == DBUS_RELEASE_NAME_REPLY_NOT_OWNER);

        name_registry_release_name(bus->names, peer1, "foobar", &reply);
        assert(reply == DBUS_RELEASE_NAME_REPLY_RELEASED);
        name_registry_release_all_names(bus->names, peer2);
        bus_unregister_peer(bus, peer2);
        name_registry_release_all_names(bus->names, peer1);
        bus_unregister_peer(bus, peer1);
}

int main(int argc, char **argv) {
        test_setup();
        test_release();
        test_queue();
        return 0;
}
