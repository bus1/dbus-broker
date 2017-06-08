/*
 * Test Policy
 */

#include <c-macro.h>
#include <stdlib.h>
#include "policy.h"

static void test_basic() {
        int r;

        r = policy_parse();
        assert(!r);
}

int main(int argc, char **argv) {
        test_basic();
}
