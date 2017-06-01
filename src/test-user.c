/*
 * Test User Accounting
 */

#include <c-macro.h>
#include <stdlib.h>
#include "user.h"

static void test_setup(void) {
        UserRegistry registry;
        User *entry1, *entry2, *entry3;
        int r;

        r = user_registry_init(&registry, _USER_SLOT_N, (unsigned int[]){ 1024, 1024, 1024, 1024, 1024 });
        assert(!r);

        r = user_registry_ref_user(&registry, &entry1, 1);
        assert(r == 0);
        assert(entry1);

        r = user_registry_ref_user(&registry, &entry2, 1);
        assert(r == 0);
        assert(entry2 == entry1);

        r = user_registry_ref_user(&registry, &entry3, 2);
        assert(r == 0);
        assert(entry3 != entry1);

        user_unref(entry1);
        user_unref(entry2);
        user_unref(entry3);
        user_registry_deinit(&registry);
}

static void test_quota(void) {
        UserRegistry registry;
        User *entry1, *entry2, *entry3;
        UserCharge charge1, charge2;
        int r;

        r = user_registry_init(&registry, _USER_SLOT_N, (unsigned int[]){ 1024, 1024, 1024, 1024, 1024 });
        assert(!r);

        r = user_registry_ref_user(&registry, &entry1, 1);
        assert(r == 0);

        r = user_registry_ref_user(&registry, &entry2, 2);
        assert(r == 0);

        r = user_registry_ref_user(&registry, &entry3, 3);
        assert(r == 0);

        user_charge_init(&charge1);
        user_charge_init(&charge2);

        /* the first actor can have exactly 512 bytes */
        r = user_charge(entry1, &charge1, entry2, USER_SLOT_BYTES, 513);
        assert(r == USER_E_QUOTA);
        r = user_charge(entry1, &charge1, entry2, USER_SLOT_BYTES, 512);
        assert(!r);
        r = user_charge(entry1, &charge2, entry2, USER_SLOT_BYTES, 1);
        assert(r == USER_E_QUOTA);

        /* the second one exactly 170 */
        r = user_charge(entry1, &charge2, entry3, USER_SLOT_BYTES, 171);
        assert(r == USER_E_QUOTA);
        r = user_charge(entry1, &charge2, entry3, USER_SLOT_BYTES, 170);
        assert(!r);

        /* release the first one and now the second one can have 512 */
        user_charge_deinit(&charge1);
        user_charge_init(&charge1);
        r = user_charge(entry1, &charge1, entry3, USER_SLOT_BYTES, 343);
        assert(r == USER_E_QUOTA);
        r = user_charge(entry1, &charge1, entry3, USER_SLOT_BYTES, 342);
        assert(r == 0);

        user_charge_deinit(&charge2);
        user_charge_deinit(&charge1);
        user_unref(entry1);
        user_unref(entry2);
        user_unref(entry3);
        user_registry_deinit(&registry);
}

int main(int argc, char **argv) {
        test_setup();
        test_quota();
        return 0;
}
