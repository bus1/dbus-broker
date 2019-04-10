/*
 * Test User Accounting
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include "util/user.h"

static void test_setup(void) {
        UserRegistry registry;
        User *entry1, *entry2, *entry3;
        int r;

        r = user_registry_init(&registry, NULL, _USER_SLOT_N, (unsigned int[]){ 1024, 1024, 1024, 1024, 1024 });
        c_assert(!r);

        r = user_registry_ref_user(&registry, &entry1, 1);
        c_assert(r == 0);
        c_assert(entry1);

        r = user_registry_ref_user(&registry, &entry2, 1);
        c_assert(r == 0);
        c_assert(entry2 == entry1);

        r = user_registry_ref_user(&registry, &entry3, 2);
        c_assert(r == 0);
        c_assert(entry3 != entry1);

        user_unref(entry1);
        user_unref(entry2);
        user_unref(entry3);
        user_registry_deinit(&registry);
}

static void test_quota(void) {
        UserRegistry registry;
        User *entry1, *entry2, *entry3;
        UserCharge charge1, charge2, charge3;
        int r;

        r = user_registry_init(&registry, NULL, _USER_SLOT_N, (unsigned int[]){ 1024, 1024, 1024, 1024, 1024 });
        c_assert(!r);

        r = user_registry_ref_user(&registry, &entry1, 1);
        c_assert(r == 0);

        r = user_registry_ref_user(&registry, &entry2, 2);
        c_assert(r == 0);

        r = user_registry_ref_user(&registry, &entry3, 3);
        c_assert(r == 0);

        user_charge_init(&charge1);
        user_charge_init(&charge2);
        user_charge_init(&charge3);

        /* first actor can have exactly 512 bytes */
        r = user_charge(entry1, &charge2, entry2, USER_SLOT_BYTES, 513);
        c_assert(r == USER_E_QUOTA);
        r = user_charge(entry1, &charge2, entry2, USER_SLOT_BYTES, 512);
        c_assert(!r);
        r = user_charge(entry1, &charge2, entry2, USER_SLOT_BYTES, 1);
        c_assert(r == USER_E_QUOTA);

        /* second actor exactly 170 */
        r = user_charge(entry1, &charge3, entry3, USER_SLOT_BYTES, 171);
        c_assert(r == USER_E_QUOTA);
        r = user_charge(entry1, &charge3, entry3, USER_SLOT_BYTES, 170);
        c_assert(!r);

        /* release the first one and now the second one can have 512 total */
        user_charge_deinit(&charge2);
        r = user_charge(entry1, &charge3, entry3, USER_SLOT_BYTES, 343);
        c_assert(r == USER_E_QUOTA);
        r = user_charge(entry1, &charge3, entry3, USER_SLOT_BYTES, 342);
        c_assert(r == 0);

        /* verify self-allocation can access the remaining 512 */
        r = user_charge(entry1, &charge1, NULL, USER_SLOT_BYTES, 513);
        c_assert(r == USER_E_QUOTA);
        r = user_charge(entry1, &charge1, NULL, USER_SLOT_BYTES, 512);
        c_assert(!r);

        user_charge_deinit(&charge3);
        user_charge_deinit(&charge2);
        user_charge_deinit(&charge1);
        user_unref(entry3);
        user_unref(entry2);
        user_unref(entry1);
        user_registry_deinit(&registry);
}

static void test_overflow(void) {
        UserRegistry registry;
        User *entry1, *entry2;
        UserCharge charge1;
        int r;

        r = user_registry_init(&registry, NULL, _USER_SLOT_N, (unsigned int[]){ 1024, 1024, 1024, 1024, 1024 });
        c_assert(!r);

        r = user_registry_ref_user(&registry, &entry1, 1);
        c_assert(r == 0);

        r = user_registry_ref_user(&registry, &entry2, 2);
        c_assert(r == 0);

        user_charge_init(&charge1);

        /* first actor gets exactly 512 bytes */
        r = user_charge(entry1, &charge1, entry2, USER_SLOT_BYTES, 513);
        c_assert(r == USER_E_QUOTA);
        r = user_charge(entry1, &charge1, entry2, USER_SLOT_BYTES, 1024);
        c_assert(r == USER_E_QUOTA);
        r = user_charge(entry1, &charge1, entry2, USER_SLOT_BYTES, 1025);
        c_assert(r == USER_E_QUOTA);
        r = user_charge(entry1, &charge1, entry2, USER_SLOT_BYTES, 2048);
        c_assert(r == USER_E_QUOTA);
        r = user_charge(entry1, &charge1, entry2, USER_SLOT_BYTES, (unsigned int)-1);
        c_assert(r == USER_E_QUOTA);
        r = user_charge(entry1, &charge1, entry2, USER_SLOT_BYTES, 512);
        c_assert(!r);

        user_charge_deinit(&charge1);
        user_unref(entry2);
        user_unref(entry1);
        user_registry_deinit(&registry);
}

int main(int argc, char **argv) {
        test_setup();
        test_quota();
        test_overflow();
        return 0;
}
