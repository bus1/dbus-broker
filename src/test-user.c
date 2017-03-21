/*
 * Test User Accounting
 */

#include <c-macro.h>
#include <stdlib.h>
#include "user.h"

static void test_setup(void) {
        UserRegistry *registry = NULL;
        UserEntry *entry1, *entry2, *entry3;
        int r;

        r = user_registry_new(&registry, 1024, 1024, 1024, 1024);
        assert(r >= 0);
        assert(registry);

        r = user_entry_ref_by_uid(registry, &entry1, 1);
        assert(r >= 0);
        assert(entry1);

        r = user_entry_ref_by_uid(registry, &entry2, 1);
        assert(r >= 0);
        assert(entry2 == entry1);

        r = user_entry_ref_by_uid(registry, &entry3, 2);
        assert(r >= 0);
        assert(entry3 != entry1);

        user_entry_unref(entry1);
        user_entry_unref(entry2);
        user_entry_unref(entry3);
        user_registry_free(registry);
}

static void test_quota(void) {
        UserRegistry *registry;
        UserEntry *entry1, *entry2, *entry3;
        UserCharge charge1, charge2;
        int r;

        r = user_registry_new(&registry, 1024, 1024, 1024, 1024);
        assert(r >= 0);

        r = user_entry_ref_by_uid(registry, &entry1, 1);
        assert(r >= 0);

        r = user_entry_ref_by_uid(registry, &entry2, 2);
        assert(r >= 0);

        r = user_entry_ref_by_uid(registry, &entry3, 3);
        assert(r >= 0);

        user_charge_init(&charge1);
        user_charge_init(&charge2);

        /* the first actor can have exactly 512 bytes/fds */
        r = user_charge_apply(&charge1, entry1, entry2, 513, 513);
        assert(r == -EDQUOT);
        r = user_charge_apply(&charge1, entry1, entry2, 512, 512);
        assert(r >= 0);
        r = user_charge_apply(&charge2, entry1, entry2, 1, 1);
        assert(r == -EDQUOT);

        /* the second one exactly 170 */
        r = user_charge_apply(&charge2, entry1, entry3, 171, 171);
        assert(r == -EDQUOT);
        r = user_charge_apply(&charge2, entry1, entry3, 170, 170);
        assert(r >= 0);

        /* release the first one and now the second one can have 512 */
        user_charge_release(&charge1);
        r = user_charge_apply(&charge1, entry1, entry3, 343, 343);
        assert(r == -EDQUOT);
        r = user_charge_apply(&charge1, entry1, entry3, 342, 342);
        assert(r >= 0);

        user_charge_release(&charge2);
        user_charge_release(&charge1);
        user_charge_deinit(&charge2);
        user_charge_deinit(&charge1);
        user_entry_unref(entry1);
        user_entry_unref(entry2);
        user_entry_unref(entry3);
        user_registry_free(registry);
}

int main(int argc, char **argv) {
        test_setup();
        test_quota();
        return 0;
}
