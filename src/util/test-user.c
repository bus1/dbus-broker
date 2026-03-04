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

static void test_per_uid_quota(void) {
        UserRegistry registry;
        User *entry1, *entry2;
        UserCharge charge2;
        int r;

        r = user_registry_init(&registry, NULL, _USER_SLOT_N, (unsigned int[]){ 1024, 1024, 1024, 1024 });
        c_assert(!r);

        /*
         * Test 1: Override applied before user is created.
         * Set a higher quota for uid 1, then create the user and verify it
         * gets the higher limit.
         */
        r = user_registry_set_user_limits(&registry, 1, (unsigned int[]){ 2048, 2048, 2048, 2048 });
        c_assert(!r);

        r = user_registry_ref_user(&registry, &entry1, 1);
        c_assert(!r);

        /* uid 1 should have max 2048, not the global 1024 */
        c_assert(entry1->slots[USER_SLOT_BYTES].max == 2048);
        c_assert(entry1->slots[USER_SLOT_BYTES].n == 2048);

        user_unref(entry1);

        /*
         * Test 2: Override applied to an already-existing user.
         * Create a user, consume some resources, then update its quota.
         */
        r = user_registry_ref_user(&registry, &entry2, 2);
        c_assert(!r);

        /* uid 2 gets default quota */
        c_assert(entry2->slots[USER_SLOT_BYTES].max == 1024);

        /* consume 200 bytes */
        user_charge_init(&charge2);
        r = user_charge(entry2, &charge2, NULL, USER_SLOT_BYTES, 200);
        c_assert(!r);
        c_assert(entry2->slots[USER_SLOT_BYTES].n == 824);

        /* increase quota to 2048 while user is active */
        r = user_registry_set_user_limits(&registry, 2, (unsigned int[]){ 2048, 2048, 2048, 2048 });
        c_assert(!r);

        /* remaining should be adjusted: 2048 - 200 consumed = 1848 */
        c_assert(entry2->slots[USER_SLOT_BYTES].max == 2048);
        c_assert(entry2->slots[USER_SLOT_BYTES].n == 1848);

        /* release the charge: n should return to new max */
        user_charge_deinit(&charge2);
        c_assert(entry2->slots[USER_SLOT_BYTES].n == 2048);

        /*
         * Test 3: Decreasing quota below consumed amount clamps to consumed.
         */
        user_charge_init(&charge2);
        r = user_charge(entry2, &charge2, NULL, USER_SLOT_BYTES, 500);
        c_assert(!r);
        c_assert(entry2->slots[USER_SLOT_BYTES].n == 1548);

        /* try to lower quota to 300, but 500 is already consumed: clamp to 500 */
        r = user_registry_set_user_limits(&registry, 2, (unsigned int[]){ 300, 300, 300, 300 });
        c_assert(!r);
        c_assert(entry2->slots[USER_SLOT_BYTES].max == 500);
        c_assert(entry2->slots[USER_SLOT_BYTES].n == 0);

        /* release charge: n returns to clamped max */
        user_charge_deinit(&charge2);
        c_assert(entry2->slots[USER_SLOT_BYTES].n == 500);
        c_assert(entry2->slots[USER_SLOT_BYTES].max == 500);

        user_unref(entry2);

        /*
         * Test 4: When uid 1 (with override) is created again, override persists.
         */
        r = user_registry_ref_user(&registry, &entry1, 1);
        c_assert(!r);
        c_assert(entry1->slots[USER_SLOT_BYTES].max == 2048);
        user_unref(entry1);

        user_registry_deinit(&registry);
}

int main(int argc, char **argv) {
        test_setup();
        test_quota();
        test_overflow();
        test_per_uid_quota();
        return 0;
}
