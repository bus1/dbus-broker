/*
 * Test Name Registry
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "bus.h"
#include "dbus-protocol.h"
#include "name.h"
#include "peer.h"
#include "user.h"

static void test_setup(void) {
        _c_cleanup_(bus_freep) Bus *bus = NULL;
        _c_cleanup_(peer_freep) Peer *peer = NULL;
        NameChange change;
        Peer *p;
        uint32_t reply;
        int r, pair[2];

        name_change_init(&change);

        r = bus_new(&bus, 0, 1024, 1024, 1024, 1024, 1024);
        assert(r >= 0);

        r = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
        assert(r >= 0);

        r = peer_new(&peer, bus, pair[0]);
        assert(r >= 0);

        peer_register(peer);
        p = peer_registry_find_peer(&bus->peers, 0);
        assert(p == peer);

        r = name_registry_request_name(&bus->names, peer, "foobar", 0, &change, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);
        assert(strcmp(change.name->name, "foobar") == 0);
        assert(change.old_owner == NULL);
        assert(change.new_owner == peer);
        name_change_deinit(&change);
        p = name_registry_resolve_name(&bus->names, "foobar");
        assert(p == peer);
        name_registry_release_name(&bus->names, peer, "foobar", &change, &reply);
        assert(reply == DBUS_RELEASE_NAME_REPLY_RELEASED);
        assert(strcmp(change.name->name, "foobar") == 0);
        assert(change.old_owner == peer);
        assert(change.new_owner == NULL);
        name_change_deinit(&change);
        p = name_registry_resolve_name(&bus->names, "foobar");
        assert(p == NULL);

        p = peer_registry_find_peer(&bus->peers, 0);
        assert(p == peer);
        peer_unregister(peer);
        p = peer_registry_find_peer(&bus->peers, 0);
        assert(p == NULL);
        close(pair[1]);
}

static void test_release(void) {
        _c_cleanup_(bus_freep) Bus *bus = NULL;
        _c_cleanup_(peer_freep) Peer *peer1 = NULL, *peer2 = NULL;
        NameChange change;
        uint32_t reply;
        int r, pair[2];

        name_change_init(&change);

        r = bus_new(&bus, 0, 1024, 1024, 1024, 1024, 1024);
        assert(r >= 0);

        r = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
        assert(r >= 0);

        r = peer_new(&peer1, bus, pair[0]);
        assert(r >= 0);
        r = peer_new(&peer2, bus, pair[1]);
        assert(r >= 0);
        peer_register(peer1);
        peer_register(peer2);

        r = name_registry_request_name(&bus->names, peer1, "foobar", 0, &change, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);
        assert(strcmp(change.name->name, "foobar") == 0);
        assert(change.old_owner == NULL);
        assert(change.new_owner == peer1);
        name_change_deinit(&change);

        name_registry_release_name(&bus->names, peer1, "baz", &change, &reply);
        assert(reply == DBUS_RELEASE_NAME_REPLY_NON_EXISTENT);
        assert(change.name == NULL);
        assert(change.old_owner == NULL);
        assert(change.new_owner == NULL);
        name_registry_release_name(&bus->names, peer2, "foobar", &change, &reply);
        assert(reply == DBUS_RELEASE_NAME_REPLY_NOT_OWNER);
        assert(change.name == NULL);
        assert(change.old_owner == NULL);
        assert(change.new_owner == NULL);
        name_registry_release_name(&bus->names, peer1, "foobar", &change, &reply);
        assert(reply == DBUS_RELEASE_NAME_REPLY_RELEASED);
        assert(strcmp(change.name->name, "foobar") == 0);
        assert(change.old_owner == peer1);
        assert(change.new_owner == NULL);
        name_change_deinit(&change);

        peer_unregister(peer2);
        peer_unregister(peer1);
}

static void test_queue(void) {
        _c_cleanup_(bus_freep) Bus *bus = NULL;
        _c_cleanup_(peer_freep) Peer *peer1 = NULL, *peer2 = NULL;
        NameChange change;
        Peer *peer;
        uint32_t reply;
        int r, pair[2];

        name_change_init(&change);

        r = bus_new(&bus, 0, 1024, 1024, 1024, 1024, 1024);
        assert(r >= 0);

        r = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
        assert(r >= 0);

        r = peer_new(&peer1, bus, pair[0]);
        assert(r >= 0);
        r = peer_new(&peer2, bus, pair[1]);
        assert(r >= 0);
        peer_register(peer1);
        peer_register(peer2);

        /* first to request */
        r = name_registry_request_name(&bus->names, peer1, "foobar", 0, &change, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);
        assert(strcmp(change.name->name, "foobar") == 0);
        assert(change.old_owner == NULL);
        assert(change.new_owner == peer1);
        name_change_deinit(&change);
        /* verify the primary owner */
        peer = name_registry_resolve_name(&bus->names, "foobar");
        assert(peer == peer1);
        /* already the owner */
        r = name_registry_request_name(&bus->names, peer1, "foobar", 0, &change, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER);
        assert(change.name == NULL);
        assert(change.old_owner == NULL);
        assert(change.new_owner == NULL);
        /* refuse to queue */
        r = name_registry_request_name(&bus->names, peer2, "foobar", DBUS_NAME_FLAG_DO_NOT_QUEUE, &change, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_EXISTS);
        assert(change.name == NULL);
        assert(change.old_owner == NULL);
        assert(change.new_owner == NULL);
        /* try to overtake, but owner won't allow it */
        r = name_registry_request_name(&bus->names, peer2, "foobar", DBUS_NAME_FLAG_DO_NOT_QUEUE | DBUS_NAME_FLAG_REPLACE_EXISTING, &change, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_EXISTS);
        assert(change.name == NULL);
        assert(change.old_owner == NULL);
        assert(change.new_owner == NULL);
        /* queue */
        r = name_registry_request_name(&bus->names, peer2, "foobar", 0, &change, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_IN_QUEUE);
        assert(change.name == NULL);
        assert(change.old_owner == NULL);
        assert(change.new_owner == NULL);
        /* verify that the primary owner was untouched */
        peer = name_registry_resolve_name(&bus->names, "foobar");
        assert(peer == peer1);
        /* dequeu again */
        name_registry_release_name(&bus->names, peer2, "foobar", &change, &reply);
        assert(reply == DBUS_RELEASE_NAME_REPLY_RELEASED);
        assert(change.name == NULL);
        assert(change.old_owner == NULL);
        assert(change.new_owner == NULL);
        /* verify that the primary owner was untouched */
        peer = name_registry_resolve_name(&bus->names, "foobar");
        assert(peer == peer1);
        /* try to overtake, but wait in queue if it fails */
        r = name_registry_request_name(&bus->names, peer2, "foobar", DBUS_NAME_FLAG_REPLACE_EXISTING, &change, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_IN_QUEUE);
        assert(change.name == NULL);
        assert(change.old_owner == NULL);
        assert(change.new_owner == NULL);
        /* again */
        r = name_registry_request_name(&bus->names, peer2, "foobar", DBUS_NAME_FLAG_REPLACE_EXISTING, &change, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_IN_QUEUE);
        assert(change.name == NULL);
        assert(change.old_owner == NULL);
        assert(change.new_owner == NULL);
        /* update primary owner to allow replacement */
        r = name_registry_request_name(&bus->names, peer1, "foobar", DBUS_NAME_FLAG_ALLOW_REPLACEMENT, &change, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER);
        assert(change.name == NULL);
        assert(change.old_owner == NULL);
        assert(change.new_owner == NULL);
        /* queue again, but do not attempt to overtake */
        r = name_registry_request_name(&bus->names, peer2, "foobar", 0, &change, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_IN_QUEUE);
        assert(change.name == NULL);
        assert(change.old_owner == NULL);
        assert(change.new_owner == NULL);
        /* verify that the primary owner was untouched */
        peer = name_registry_resolve_name(&bus->names, "foobar");
        assert(peer == peer1);
        /* overtake primary owner, allow to be replaced ourselves and refuse to
         * queue */
        r = name_registry_request_name(&bus->names, peer2, "foobar",
                                       DBUS_NAME_FLAG_REPLACE_EXISTING |
                                       DBUS_NAME_FLAG_ALLOW_REPLACEMENT |
                                       DBUS_NAME_FLAG_DO_NOT_QUEUE,
                                       &change, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);
        assert(strcmp(change.name->name, "foobar") == 0);
        assert(change.old_owner == peer1);
        assert(change.new_owner == peer2);
        name_change_deinit(&change);
        /* verify that the primary owner was changed */
        peer = name_registry_resolve_name(&bus->names, "foobar");
        assert(peer == peer2);
        /* overtake again */
        r = name_registry_request_name(&bus->names, peer1, "foobar", DBUS_NAME_FLAG_REPLACE_EXISTING, &change, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);
        assert(strcmp(change.name->name, "foobar") == 0);
        assert(change.old_owner == peer2);
        assert(change.new_owner == peer1);
        name_change_deinit(&change);
        /* verify that the primary owner was reverted to the original */
        peer = name_registry_resolve_name(&bus->names, "foobar");
        assert(peer == peer1);
        /* verify that the old primary owner is no longer on queue */
        name_registry_release_name(&bus->names, peer2, "foobar", &change, &reply);
        assert(reply == DBUS_RELEASE_NAME_REPLY_NOT_OWNER);
        assert(change.name == NULL);
        assert(change.old_owner == NULL);
        assert(change.new_owner == NULL);

        name_registry_release_name(&bus->names, peer1, "foobar", &change, &reply);
        assert(reply == DBUS_RELEASE_NAME_REPLY_RELEASED);
        assert(strcmp(change.name->name, "foobar") == 0);
        assert(change.old_owner == peer1);
        assert(change.new_owner == NULL);
        name_change_deinit(&change);
        peer_unregister(peer2);
        peer_unregister(peer1);
}

int main(int argc, char **argv) {
        test_setup();
        test_release();
        test_queue();
        return 0;
}
