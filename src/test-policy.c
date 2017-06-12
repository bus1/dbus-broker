/*
 * Test Policy
 */

#include <c-macro.h>
#include <stdlib.h>
#include "policy.h"

static void test_basic() {
        PolicyRegistry registry;
        int r;

        policy_registry_init(&registry);

        r = policy_parse(&registry);
        assert(!r);

        policy_registry_deinit(&registry);
}

int main(int argc, char **argv) {
        test_basic();
}
