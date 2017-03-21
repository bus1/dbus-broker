/*
 * Test Name Registry
 */

#include <c-macro.h>
#include <stdlib.h>
#include "name.h"
#include "peer.h"
#include "user.h"

static void test_setup(void) {
        UserRegistry *user_registry;
        UserEntry *user;
        Peer *peer;
        NameRegistry *registry;
        uint32_t reply;
        int r;

        assert(user_registry_new(&user_registry, 1024, 1024, 1024) >= 0);
        assert(user_entry_ref_by_uid(user_registry, &user, 1) >= 0);
        assert(peer_new(&peer, user) >= 0);

        r = name_registry_new(&registry);
        assert(r >= 0);

        r = name_registry_request_name(registry, peer, "foobar", 0, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);
        name_registry_release_name(registry, peer, "foobar", &reply);
        assert(reply == DBUS_RELEASE_NAME_REPLY_RELEASED);

        name_registry_free(registry);
        peer_free(peer);
        user_entry_unref(user);
        user_registry_free(user_registry);
}

static void test_release(void) {
        UserRegistry *user_registry;
        UserEntry *user;
        Peer *peer1, *peer2;
        NameRegistry *registry;
        uint32_t reply;
        int r;

        assert(user_registry_new(&user_registry, 1024, 1024, 1024) >= 0);
        assert(user_entry_ref_by_uid(user_registry, &user, 1) >= 0);
        assert(peer_new(&peer1, user) >= 0);
        assert(peer_new(&peer2, user) >= 0);
        assert(name_registry_new(&registry) >= 0);

        r = name_registry_request_name(registry, peer1, "foobar", 0, &reply);
        assert(r >= 0);

        name_registry_release_name(registry, peer1, "baz", &reply);
        assert(reply == DBUS_RELEASE_NAME_REPLY_NON_EXISTENT);
        name_registry_release_name(registry, peer2, "foobar", &reply);
        assert(reply == DBUS_RELEASE_NAME_REPLY_NOT_OWNER);
        name_registry_release_name(registry, peer1, "foobar", &reply);
        assert(reply == DBUS_RELEASE_NAME_REPLY_RELEASED);

        name_registry_free(registry);
        peer_free(peer2);
        peer_free(peer1);
        user_entry_unref(user);
        user_registry_free(user_registry);
}

static void test_queue(void) {
        UserRegistry *user_registry;
        UserEntry *user;
        Peer *peer1, *peer2, *peer;
        NameRegistry *registry;
        uint32_t reply;
        int r;

        assert(user_registry_new(&user_registry, 1024, 1024, 1024) >= 0);
        assert(user_entry_ref_by_uid(user_registry, &user, 1) >= 0);
        assert(peer_new(&peer1, user) >= 0);
        assert(peer_new(&peer2, user) >= 0);
        assert(name_registry_new(&registry) >= 0);

        /* first to request */
        r = name_registry_request_name(registry, peer1, "foobar", 0, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);
        /* verify the primary owner */
        peer = name_registry_resolve_name(registry, "foobar");
        assert(peer == peer1);
        /* already the owner */
        r = name_registry_request_name(registry, peer1, "foobar", 0, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER);
        /* refuse to queue */
        r = name_registry_request_name(registry, peer2, "foobar",
                                       DBUS_NAME_FLAG_DO_NOT_QUEUE, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_EXISTS);
        /* try to overtake, but owner won't allow it */
        r = name_registry_request_name(registry, peer2, "foobar",
                                       DBUS_NAME_FLAG_DO_NOT_QUEUE |
                                       DBUS_NAME_FLAG_REPLACE_EXISTING, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_EXISTS);
        /* queue */
        r = name_registry_request_name(registry, peer2, "foobar", 0, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_IN_QUEUE);
        /* verify that the primary owner was untouched */
        peer = name_registry_resolve_name(registry, "foobar");
        assert(peer == peer1);
        /* dequeu again */
        name_registry_release_name(registry, peer2, "foobar", &reply);
        assert(reply == DBUS_RELEASE_NAME_REPLY_RELEASED);
        /* verify that the primary owner was untouched */
        peer = name_registry_resolve_name(registry, "foobar");
        assert(peer == peer1);
        /* try to overtake, but wait in queue if it fails */
        r = name_registry_request_name(registry, peer2, "foobar",
                                       DBUS_NAME_FLAG_REPLACE_EXISTING, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_IN_QUEUE);
        /* again */
        r = name_registry_request_name(registry, peer2, "foobar",
                                       DBUS_NAME_FLAG_REPLACE_EXISTING, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_IN_QUEUE);
        /* update primary owner to allow replacement */
        r = name_registry_request_name(registry, peer1, "foobar",
                                       DBUS_NAME_FLAG_ALLOW_REPLACEMENT,
                                       &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER);
        /* queue again, but do not attempt to overtake */
        r = name_registry_request_name(registry, peer2, "foobar", 0, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_IN_QUEUE);
        /* verify that the primary owner was untouched */
        peer = name_registry_resolve_name(registry, "foobar");
        assert(peer == peer1);
        /* overtake primary owner, allow to be replaced ourselves and refuse to
         * queue */
        r = name_registry_request_name(registry, peer2, "foobar",
                                       DBUS_NAME_FLAG_REPLACE_EXISTING |
                                       DBUS_NAME_FLAG_ALLOW_REPLACEMENT |
                                       DBUS_NAME_FLAG_DO_NOT_QUEUE,
                                       &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);
        /* verify that the primary owner was changed */
        peer = name_registry_resolve_name(registry, "foobar");
        assert(peer == peer2);
        /* overtake again */
        r = name_registry_request_name(registry, peer1, "foobar",
                                       DBUS_NAME_FLAG_REPLACE_EXISTING, &reply);
        assert(r >= 0);
        assert(reply == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);
        /* verify that the primary owner was reverted to the original */
        peer = name_registry_resolve_name(registry, "foobar");
        assert(peer == peer1);
        /* verify that the old primary owner is no longer on queue */
        name_registry_release_name(registry, peer2, "foobar", &reply);
        assert(reply == DBUS_RELEASE_NAME_REPLY_NOT_OWNER);

        name_registry_release_name(registry, peer1, "foobar", &reply);
        assert(reply == DBUS_RELEASE_NAME_REPLY_RELEASED);
        name_registry_free(registry);
        peer_free(peer2);
        peer_free(peer1);
        user_entry_unref(user);
        user_registry_free(user_registry);
}

int main(int argc, char **argv) {
        test_setup();
        test_release();
        test_queue();
        return 0;
}
