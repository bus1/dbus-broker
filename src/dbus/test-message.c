/*
 * Test D-Bus Message Abstraction
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include "dbus/message.h"

static void test_setup(void) {
        _c_cleanup_(message_unrefp) Message *m1 = NULL, *m2, *m3;
        MessageHeader hdr = { .endian = 'l' };
        int r;

        /* verify constructors / destructors */

        r = message_new_incoming(&m2, hdr);
        c_assert(r == 0);

        r = message_new_incoming(&m3, hdr);
        c_assert(r == 0);

        m3 = message_unref(m3);
        m1 = message_unref(m1);
}

static void test_size(void) {
        MessageHeader hdr = { .endian = 'l' };
        Message *m;
        int r;

        /* verify total message size cannot exceed 128MB */

        hdr.n_body = htole32(0);
        r = message_new_incoming(&m, hdr);
        c_assert(r == 0);
        message_unref(m);

        hdr.n_body = htole32(128);
        r = message_new_incoming(&m, hdr);
        c_assert(r == 0);
        message_unref(m);

        hdr.n_body = htole32(128UL * 1024UL * 1024UL - sizeof(MessageHeader));
        r = message_new_incoming(&m, hdr);
        c_assert(r == 0);
        message_unref(m);

        hdr.n_body = htole32(128UL * 1024UL * 1024UL - sizeof(MessageHeader) + 1UL);
        r = message_new_incoming(&m, hdr);
        c_assert(r == MESSAGE_E_TOO_LARGE);

        hdr.n_fields = htole32(8);
        hdr.n_body = htole32(128UL * 1024UL * 1024UL - sizeof(MessageHeader) - 8);
        r = message_new_incoming(&m, hdr);
        c_assert(r == 0);
        message_unref(m);

        hdr.n_fields = htole32(8 + 1);
        hdr.n_body = htole32(128UL * 1024UL * 1024UL - sizeof(MessageHeader) - 8);
        r = message_new_incoming(&m, hdr);
        c_assert(r == MESSAGE_E_TOO_LARGE);
}

int main(int argc, char **argv) {
        test_setup();
        test_size();
        return 0;
}
