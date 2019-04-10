/*
 * Test NSS Cache
 */

#undef NDEBUG
#include <c-list.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include "launch/nss-cache.h"

static void test_nss_cache(void) {
        _c_cleanup_(nss_cache_deinit) NSSCache cache = NSS_CACHE_INIT;
        uint32_t uid, gid;
        int r;

        r = nss_cache_get_uid(&cache, NULL, NULL, "com.example.InvalidUser");
        c_assert(r == NSS_CACHE_E_INVALID_NAME);

        r = nss_cache_get_gid(&cache, NULL, "com.example.InvalidGroup");
        c_assert(r == NSS_CACHE_E_INVALID_NAME);

        r = nss_cache_get_uid(&cache, &uid, &gid, "root");
        c_assert(!r);
        c_assert(uid == 0);
        c_assert(gid == 0);

        r = nss_cache_get_gid(&cache, &gid, "root");
        c_assert(!r);
        c_assert(gid == 0);
}

int main(int argc, char **argv) {
        test_nss_cache();
        return 0;
}
