/*
 * Test Name Registry
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "bus/name.h"
#include "dbus/protocol.h"

static NameOwner *resolve_owner(NameRegistry *registry, const char *name_str) {
        NameOwnership *ownership;
        Name *name;

        name = name_registry_find_name(registry, name_str);
        if (!name)
                return NULL;

        ownership = c_list_first_entry(&name->ownership_list, NameOwnership, name_link);
        return ownership ? ownership->owner : NULL;
}

static void test_setup(void) {
        NameRegistry registry;
        NameOwner owner, *o;
        NameChange change;
        int r;

        name_registry_init(&registry);
        name_owner_init(&owner);
        name_change_init(&change);

        r = name_registry_request_name(&registry, &owner, NULL, "foobar", 0, &change);
        c_assert(!r);
        c_assert(strcmp(change.name->name, "foobar") == 0);
        c_assert(change.old_owner == NULL);
        c_assert(change.new_owner == &owner);
        name_change_deinit(&change);
        o = resolve_owner(&registry, "foobar");
        c_assert(o == &owner);
        r = name_registry_release_name(&registry, &owner, "foobar", &change);
        c_assert(r == 0);
        c_assert(strcmp(change.name->name, "foobar") == 0);
        c_assert(change.old_owner == &owner);
        c_assert(change.new_owner == NULL);
        name_change_deinit(&change);
        o = resolve_owner(&registry, "foobar");
        c_assert(o == NULL);

        name_owner_deinit(&owner);
        name_registry_deinit(&registry);
}

static void test_release(void) {
        NameRegistry registry;
        NameOwner owner1, owner2;
        NameChange change;
        int r;

        name_registry_init(&registry);
        name_owner_init(&owner1);
        name_owner_init(&owner2);
        name_change_init(&change);

        r = name_registry_request_name(&registry, &owner1, NULL, "foobar", 0, &change);
        c_assert(!r);
        c_assert(strcmp(change.name->name, "foobar") == 0);
        c_assert(change.old_owner == NULL);
        c_assert(change.new_owner == &owner1);
        name_change_deinit(&change);

        r = name_registry_release_name(&registry, &owner1, "baz", &change);
        c_assert(r == NAME_E_NOT_FOUND);
        c_assert(change.name == NULL);
        c_assert(change.old_owner == NULL);
        c_assert(change.new_owner == NULL);
        r = name_registry_release_name(&registry, &owner2, "foobar", &change);
        c_assert(r == NAME_E_NOT_OWNER);
        c_assert(change.name == NULL);
        c_assert(change.old_owner == NULL);
        c_assert(change.new_owner == NULL);
        r = name_registry_release_name(&registry, &owner1, "foobar", &change);
        c_assert(r == 0);
        c_assert(strcmp(change.name->name, "foobar") == 0);
        c_assert(change.old_owner == &owner1);
        c_assert(change.new_owner == NULL);
        name_change_deinit(&change);

        name_owner_deinit(&owner2);
        name_owner_deinit(&owner1);
        name_registry_deinit(&registry);
}

static void test_queue(void) {
        NameRegistry registry;
        NameOwner owner1, owner2, *o;
        NameChange change;
        int r;

        name_registry_init(&registry);
        name_owner_init(&owner1);
        name_owner_init(&owner2);
        name_change_init(&change);

        /* first to request */
        r = name_registry_request_name(&registry, &owner1, NULL, "foobar", 0, &change);
        c_assert(!r);
        c_assert(strcmp(change.name->name, "foobar") == 0);
        c_assert(change.old_owner == NULL);
        c_assert(change.new_owner == &owner1);
        name_change_deinit(&change);
        /* verify the primary owner */
        o = resolve_owner(&registry, "foobar");
        c_assert(o == &owner1);
        /* already the owner */
        r = name_registry_request_name(&registry, &owner1, NULL, "foobar", 0, &change);
        c_assert(r == NAME_E_ALREADY_OWNER);
        c_assert(change.name == NULL);
        c_assert(change.old_owner == NULL);
        c_assert(change.new_owner == NULL);
        /* refuse to queue */
        r = name_registry_request_name(&registry, &owner2, NULL, "foobar", DBUS_NAME_FLAG_DO_NOT_QUEUE, &change);
        c_assert(r == NAME_E_EXISTS);
        c_assert(change.name == NULL);
        c_assert(change.old_owner == NULL);
        c_assert(change.new_owner == NULL);
        /* try to overtake, but owner won't allow it */
        r = name_registry_request_name(&registry, &owner2, NULL, "foobar", DBUS_NAME_FLAG_DO_NOT_QUEUE | DBUS_NAME_FLAG_REPLACE_EXISTING, &change);
        c_assert(r == NAME_E_EXISTS);
        c_assert(change.name == NULL);
        c_assert(change.old_owner == NULL);
        c_assert(change.new_owner == NULL);
        /* queue */
        r = name_registry_request_name(&registry, &owner2, NULL, "foobar", 0, &change);
        c_assert(r == NAME_E_IN_QUEUE);
        c_assert(change.name == NULL);
        c_assert(change.old_owner == NULL);
        c_assert(change.new_owner == NULL);
        /* verify that the primary owner was untouched */
        o = resolve_owner(&registry, "foobar");
        c_assert(o == &owner1);
        /* dequeu again */
        r = name_registry_release_name(&registry, &owner2, "foobar", &change);
        c_assert(r == 0);
        c_assert(change.name == NULL);
        c_assert(change.old_owner == NULL);
        c_assert(change.new_owner == NULL);
        /* verify that the primary owner was untouched */
        o = resolve_owner(&registry, "foobar");
        c_assert(o == &owner1);
        /* try to overtake, but wait in queue if it fails */
        r = name_registry_request_name(&registry, &owner2, NULL, "foobar", DBUS_NAME_FLAG_REPLACE_EXISTING, &change);
        c_assert(r == NAME_E_IN_QUEUE);
        c_assert(change.name == NULL);
        c_assert(change.old_owner == NULL);
        c_assert(change.new_owner == NULL);
        /* again */
        r = name_registry_request_name(&registry, &owner2, NULL, "foobar", DBUS_NAME_FLAG_REPLACE_EXISTING, &change);
        c_assert(r == NAME_E_IN_QUEUE);
        c_assert(change.name == NULL);
        c_assert(change.old_owner == NULL);
        c_assert(change.new_owner == NULL);
        /* update primary owner to allow replacement */
        r = name_registry_request_name(&registry, &owner1, NULL, "foobar", DBUS_NAME_FLAG_ALLOW_REPLACEMENT, &change);
        c_assert(r == NAME_E_ALREADY_OWNER);
        c_assert(change.name == NULL);
        c_assert(change.old_owner == NULL);
        c_assert(change.new_owner == NULL);
        /* queue again, but do not attempt to overtake */
        r = name_registry_request_name(&registry, &owner2, NULL, "foobar", 0, &change);
        c_assert(r == NAME_E_IN_QUEUE);
        c_assert(change.name == NULL);
        c_assert(change.old_owner == NULL);
        c_assert(change.new_owner == NULL);
        /* verify that the primary owner was untouched */
        o = resolve_owner(&registry, "foobar");
        c_assert(o == &owner1);
        /* overtake primary owner, allow to be replaced ourselves and refuse to
         * queue */
        r = name_registry_request_name(&registry, &owner2, NULL, "foobar",
                                       DBUS_NAME_FLAG_REPLACE_EXISTING |
                                       DBUS_NAME_FLAG_ALLOW_REPLACEMENT |
                                       DBUS_NAME_FLAG_DO_NOT_QUEUE,
                                       &change);
        c_assert(!r);
        c_assert(strcmp(change.name->name, "foobar") == 0);
        c_assert(change.old_owner == &owner1);
        c_assert(change.new_owner == &owner2);
        name_change_deinit(&change);
        /* verify that the primary owner was changed */
        o = resolve_owner(&registry, "foobar");
        c_assert(o == &owner2);
        /* overtake again */
        r = name_registry_request_name(&registry, &owner1, NULL, "foobar", DBUS_NAME_FLAG_REPLACE_EXISTING, &change);
        c_assert(!r);
        c_assert(strcmp(change.name->name, "foobar") == 0);
        c_assert(change.old_owner == &owner2);
        c_assert(change.new_owner == &owner1);
        name_change_deinit(&change);
        /* verify that the primary owner was reverted to the original */
        o = resolve_owner(&registry, "foobar");
        c_assert(o == &owner1);
        /* verify that the old primary owner is no longer on queue */
        r = name_registry_release_name(&registry, &owner2, "foobar", &change);
        c_assert(r == NAME_E_NOT_OWNER);
        c_assert(change.name == NULL);
        c_assert(change.old_owner == NULL);
        c_assert(change.new_owner == NULL);

        r = name_registry_release_name(&registry, &owner1, "foobar", &change);
        c_assert(r == 0);
        c_assert(strcmp(change.name->name, "foobar") == 0);
        c_assert(change.old_owner == &owner1);
        c_assert(change.new_owner == NULL);
        name_change_deinit(&change);

        name_owner_deinit(&owner2);
        name_owner_deinit(&owner1);
        name_registry_deinit(&registry);
}

int main(int argc, char **argv) {
        test_setup();
        test_release();
        test_queue();
        return 0;
}
