/*
 * Test D-Bus Message Abstraction
 */

#include <c-macro.h>
#include <stdlib.h>
#include "dbus-message.h"

static void test_setup(void) {
        _c_cleanup_(dbus_message_unrefp) DBusMessage *m1 = NULL, *m2, *m3;
        DBusMessageHeader hdr = { .endian = 'l' };
        int r;

        /* verify constructors / destructors */

        r = dbus_message_new(&m2, hdr);
        assert(r >= 0);

        r = dbus_message_new(&m3, hdr);
        assert(r >= 0);

        m3 = dbus_message_unref(m3);
}

static void test_size(void) {
        DBusMessageHeader hdr = { .endian = 'l' };
        DBusMessage *m;
        int r;

        /* verify total message size cannot exceed 128MB */

        hdr.n_body = 0;
        r = dbus_message_new(&m, hdr);
        assert(r >= 0);
        dbus_message_unref(m);

        hdr.n_body = 128;
        r = dbus_message_new(&m, hdr);
        assert(r >= 0);
        dbus_message_unref(m);

        hdr.n_body = 128UL * 1024UL * 1024UL - sizeof(DBusMessageHeader);
        r = dbus_message_new(&m, hdr);
        assert(r >= 0);
        dbus_message_unref(m);

        hdr.n_body = 128UL * 1024UL * 1024UL - sizeof(DBusMessageHeader) + 1UL;
        r = dbus_message_new(&m, hdr);
        assert(r < 0);

        hdr.n_args = 8;
        hdr.n_body = 128UL * 1024UL * 1024UL - sizeof(DBusMessageHeader) - 8;
        r = dbus_message_new(&m, hdr);
        assert(r >= 0);
        dbus_message_unref(m);

        hdr.n_args = 8 + 1;
        hdr.n_body = 128UL * 1024UL * 1024UL - sizeof(DBusMessageHeader) - 8;
        r = dbus_message_new(&m, hdr);
        assert(r < 0);
}

int main(int argc, char **argv) {
        test_setup();
        test_size();
        return 0;
}
