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

static void test_queue_counters(void) {
        NameRegistry registry;
        NameOwner owner1, owner2;
        NameChange change;
        int r;

        /*
         * Verify that primary counters are adjusted correctly on queue updates
         * and replacements. They should only count primary ownerships, not any
         * secondary name queuing.
         */

        name_registry_init(&registry);
        name_owner_init(&owner1);
        name_owner_init(&owner2);
        name_change_init(&change);

        c_assert(owner1.n_owner_primaries == 0);
        c_assert(owner2.n_owner_primaries == 0);
        c_assert(registry.n_primaries == 0);
        c_assert(registry.n_primaries_peak == 0);
        c_assert(registry.n_owner_primaries_peak == 0);

        /* owner1: foobar */
        r = name_registry_request_name(&registry, &owner1, NULL, "foobar", 0, &change);
        c_assert(!r);
        name_change_deinit(&change);

        c_assert(owner1.n_owner_primaries == 1);
        c_assert(owner2.n_owner_primaries == 0);
        c_assert(registry.n_primaries == 1);
        c_assert(registry.n_primaries_peak == 1);
        c_assert(registry.n_owner_primaries_peak == 1);

        /* re-request and queuing should not affect counters */
        r = name_registry_request_name(&registry, &owner1, NULL, "foobar", 0, &change);
        c_assert(r == NAME_E_ALREADY_OWNER);
        r = name_registry_request_name(&registry, &owner2, NULL, "foobar", DBUS_NAME_FLAG_DO_NOT_QUEUE, &change);
        c_assert(r == NAME_E_EXISTS);
        r = name_registry_request_name(&registry, &owner2, NULL, "foobar", DBUS_NAME_FLAG_DO_NOT_QUEUE | DBUS_NAME_FLAG_REPLACE_EXISTING, &change);
        c_assert(r == NAME_E_EXISTS);
        r = name_registry_request_name(&registry, &owner2, NULL, "foobar", 0, &change);
        c_assert(r == NAME_E_IN_QUEUE);

        c_assert(owner1.n_owner_primaries == 1);
        c_assert(owner2.n_owner_primaries == 0);
        c_assert(registry.n_primaries == 1);
        c_assert(registry.n_primaries_peak == 1);
        c_assert(registry.n_owner_primaries_peak == 1);

        /* dequeue again */
        r = name_registry_release_name(&registry, &owner2, "foobar", &change);
        c_assert(r == 0);

        c_assert(owner1.n_owner_primaries == 1);
        c_assert(owner2.n_owner_primaries == 0);
        c_assert(registry.n_primaries == 1);
        c_assert(registry.n_primaries_peak == 1);
        c_assert(registry.n_owner_primaries_peak == 1);

        /* queue owner2 then allow replacement (takes effect on next request) */
        r = name_registry_request_name(&registry, &owner2, NULL, "foobar", DBUS_NAME_FLAG_REPLACE_EXISTING, &change);
        c_assert(r == NAME_E_IN_QUEUE);
        r = name_registry_request_name(&registry, &owner1, NULL, "foobar", DBUS_NAME_FLAG_ALLOW_REPLACEMENT, &change);
        c_assert(r == NAME_E_ALREADY_OWNER);
        r = name_registry_request_name(&registry, &owner2, NULL, "foobar", 0, &change);
        c_assert(r == NAME_E_IN_QUEUE);

        c_assert(owner1.n_owner_primaries == 1);
        c_assert(owner2.n_owner_primaries == 0);
        c_assert(registry.n_primaries == 1);
        c_assert(registry.n_primaries_peak == 1);
        c_assert(registry.n_owner_primaries_peak == 1);

        /* now overtake the primary */
        r = name_registry_request_name(&registry, &owner2, NULL, "foobar",
                                       DBUS_NAME_FLAG_REPLACE_EXISTING |
                                       DBUS_NAME_FLAG_ALLOW_REPLACEMENT |
                                       DBUS_NAME_FLAG_DO_NOT_QUEUE,
                                       &change);
        c_assert(!r);
        name_change_deinit(&change);

        c_assert(owner1.n_owner_primaries == 0);
        c_assert(owner2.n_owner_primaries == 1);
        c_assert(registry.n_primaries == 1);
        c_assert(registry.n_primaries_peak == 1);
        c_assert(registry.n_owner_primaries_peak == 1);

        /* overtake again */
        r = name_registry_request_name(&registry, &owner1, NULL, "foobar", DBUS_NAME_FLAG_REPLACE_EXISTING, &change);
        c_assert(!r);
        name_change_deinit(&change);

        c_assert(owner1.n_owner_primaries == 1);
        c_assert(owner2.n_owner_primaries == 0);
        c_assert(registry.n_primaries == 1);
        c_assert(registry.n_primaries_peak == 1);
        c_assert(registry.n_owner_primaries_peak == 1);

        /* release names */
        r = name_registry_release_name(&registry, &owner1, "foobar", &change);
        c_assert(r == 0);
        name_change_deinit(&change);

        name_owner_deinit(&owner2);
        name_owner_deinit(&owner1);
        name_registry_deinit(&registry);
}

static void test_peak_counters(void) {
        NameRegistry registry;
        NameOwner owner1, owner2;
        NameChange change;
        int r;

        /*
         * Verify that primary peak-counters are adjusted correctly when peers
         * acquire primary names.
         */

        name_registry_init(&registry);
        name_owner_init(&owner1);
        name_owner_init(&owner2);
        name_change_init(&change);

        c_assert(owner1.n_owner_primaries == 0);
        c_assert(owner2.n_owner_primaries == 0);
        c_assert(registry.n_primaries == 0);
        c_assert(registry.n_primaries_peak == 0);
        c_assert(registry.n_owner_primaries_peak == 0);

        /* owner1: foobar0 */
        r = name_registry_request_name(&registry, &owner1, NULL, "foobar0", 0, &change);
        c_assert(!r);
        name_change_deinit(&change);

        c_assert(owner1.n_owner_primaries == 1);
        c_assert(owner2.n_owner_primaries == 0);
        c_assert(registry.n_primaries == 1);
        c_assert(registry.n_primaries_peak == 1);
        c_assert(registry.n_owner_primaries_peak == 1);

        /* owner1: foobar1 */
        r = name_registry_request_name(&registry, &owner1, NULL, "foobar1", 0, &change);
        c_assert(!r);
        name_change_deinit(&change);

        c_assert(owner1.n_owner_primaries == 2);
        c_assert(owner2.n_owner_primaries == 0);
        c_assert(registry.n_primaries == 2);
        c_assert(registry.n_primaries_peak == 2);
        c_assert(registry.n_owner_primaries_peak == 2);

        /* owner2: foobar2 */
        r = name_registry_request_name(&registry, &owner2, NULL, "foobar2", 0, &change);
        c_assert(!r);
        name_change_deinit(&change);

        c_assert(owner1.n_owner_primaries == 2);
        c_assert(owner2.n_owner_primaries == 1);
        c_assert(registry.n_primaries == 3);
        c_assert(registry.n_primaries_peak == 3);
        c_assert(registry.n_owner_primaries_peak == 2);

        /* owner2: foobar3 */
        r = name_registry_request_name(&registry, &owner2, NULL, "foobar3", 0, &change);
        c_assert(!r);
        name_change_deinit(&change);

        c_assert(owner1.n_owner_primaries == 2);
        c_assert(owner2.n_owner_primaries == 2);
        c_assert(registry.n_primaries == 4);
        c_assert(registry.n_primaries_peak == 4);
        c_assert(registry.n_owner_primaries_peak == 2);

        /* release names */
        r = name_registry_release_name(&registry, &owner2, "foobar3", &change);
        c_assert(r == 0);
        name_change_deinit(&change);
        r = name_registry_release_name(&registry, &owner2, "foobar2", &change);
        c_assert(r == 0);
        name_change_deinit(&change);

        c_assert(owner1.n_owner_primaries == 2);
        c_assert(owner2.n_owner_primaries == 0);
        c_assert(registry.n_primaries == 2);
        c_assert(registry.n_primaries_peak == 4);
        c_assert(registry.n_owner_primaries_peak == 2);

        r = name_registry_release_name(&registry, &owner1, "foobar1", &change);
        c_assert(r == 0);
        name_change_deinit(&change);
        r = name_registry_release_name(&registry, &owner1, "foobar0", &change);
        c_assert(r == 0);
        name_change_deinit(&change);

        c_assert(owner1.n_owner_primaries == 0);
        c_assert(owner2.n_owner_primaries == 0);
        c_assert(registry.n_primaries == 0);
        c_assert(registry.n_primaries_peak == 4);
        c_assert(registry.n_owner_primaries_peak == 2);

        name_owner_deinit(&owner2);
        name_owner_deinit(&owner1);
        name_registry_deinit(&registry);
}

int main(int argc, char **argv) {
        test_setup();
        test_release();
        test_queue();
        test_queue_counters();
        test_peak_counters();
        return 0;
}
