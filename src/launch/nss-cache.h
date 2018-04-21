#pragma once

/*
 * NSS Cache
 */

#include <c-macro.h>
#include <c-rbtree.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct NSSCache NSSCache;

enum {
        _NSS_CACHE_E_SUCCESS,

        NSS_CACHE_E_INVALID_NAME,
};

struct NSSCache {
        CRBTree user_tree;
        CRBTree group_tree;
};

#define NSS_CACHE_INIT {                                                        \
                .user_tree = C_RBTREE_INIT,                                     \
                .group_tree = C_RBTREE_INIT,                                    \
        }

/* nss cache */

void nss_cache_init(NSSCache *cache);
void nss_cache_deinit(NSSCache *cache);

int nss_cache_populate(NSSCache *cache);

int nss_cache_get_uid(NSSCache *cache, uid_t *uidp, const char *user);
int nss_cache_get_gid(NSSCache *cache, gid_t *gidp, const char *group);
