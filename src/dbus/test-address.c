/*
 * Test Address Handling
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include "dbus/address.h"

static void test_basic(void) {
        Address addr;

        address_init_from_id(&addr, 0);
        c_assert(addr.type == ADDRESS_TYPE_ID);
        c_assert(!strcmp(address_to_string(&addr), ":1.0"));

        address_init_from_id(&addr, ADDRESS_ID_INVALID - 1);
        c_assert(addr.type == ADDRESS_TYPE_ID);
        c_assert(!strcmp(address_to_string(&addr), ":1.18446744073709551614"));

        address_from_string(&addr, ":1.0");
        c_assert(addr.type == ADDRESS_TYPE_ID);
        c_assert(addr.id == 0);

        /* Would map to ADDRESS_ID_INVALID, thus it must be rejected. */
        address_from_string(&addr, ":1.18446744073709551615");
        c_assert(addr.type == ADDRESS_TYPE_OTHER);

        /* Out of range of uint64_t. */
        address_from_string(&addr, ":1.18446744073709551616");
        c_assert(addr.type == ADDRESS_TYPE_OTHER);

        /* Non-decimal number must be rejected. */
        address_from_string(&addr, ":1.184467440737095516a0");
        c_assert(addr.type == ADDRESS_TYPE_OTHER);

        /* Empty addresses are invalid. */
        address_from_string(&addr, "");
        c_assert(addr.type == ADDRESS_TYPE_OTHER);

        /* Non-1 namespaces are invalid. */
        address_from_string(&addr, ":2.0");
        c_assert(addr.type == ADDRESS_TYPE_OTHER);

        /* Well-known names become type NAME */
        address_from_string(&addr, "foo.bar");
        c_assert(addr.type == ADDRESS_TYPE_NAME);
}

int main(int argc, char **argv) {
        test_basic();
        return 0;
}
