/*
 * Test Bus Context
 */

#include <c-macro.h>
#include <stdlib.h>
#include "bus.h"

static void test_setup(void) {
        _c_cleanup_(bus_freep) Bus *bus = NULL;
        int r;

        r = bus_new(&bus, -1, 1024, 1024, 1024, 1024);
        assert(r >= 0);
        assert(bus);
}

int main(int argc, char **argv) {
        test_setup();
        return 0;
}
