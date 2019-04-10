/*
 * Test Reply Tracking
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "bus/reply.h"

static void test_basic(void) {
        ReplyRegistry registry;
        ReplyOwner owner;
        ReplySlot *slot1, *slot2;
        int r;

        reply_registry_init(&registry);
        reply_owner_init(&owner);

        r = reply_slot_new(&slot1, &registry, &owner, NULL, NULL, 1, 1);
        c_assert(!r);

        r = reply_slot_new(&slot1, &registry, &owner, NULL, NULL, 1, 1);
        c_assert(r == REPLY_E_EXISTS);

        slot2 = reply_slot_get_by_id(&registry, 1, 1);
        c_assert(slot2 == slot1);

        slot2 = reply_slot_get_by_id(&registry, 1, 2);
        c_assert(!slot2);

        slot2 = reply_slot_get_by_id(&registry, 2, 1);
        c_assert(!slot2);

        reply_slot_free(slot1);
        reply_owner_deinit(&owner);
        reply_registry_deinit(&registry);
}

int main(int argc, char **argv) {
        test_basic();

        return 0;
}
