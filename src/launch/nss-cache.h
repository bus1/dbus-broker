#pragma once

/*
 * NSS Cache
 */

#include <c-rbtree.h>
#include <c-stdaux.h>
#include <stdlib.h>

typedef struct NSSCache NSSCache;

enum {
        _NSS_CACHE_E_SUCCESS,

        NSS_CACHE_E_INVALID_NAME,
};

struct NSSCache {
        CRBTree user_tree;
        CRBTree uid_tree;
        CRBTree group_tree;
        CRBTree gid_tree;
};

#define NSS_CACHE_INIT {                                                        \
                .user_tree = C_RBTREE_INIT,                                     \
                .uid_tree = C_RBTREE_INIT,                                      \
                .group_tree = C_RBTREE_INIT,                                    \
                .gid_tree = C_RBTREE_INIT,                                      \
        }

/* nss cache */

void nss_cache_init(NSSCache *cache);
void nss_cache_deinit(NSSCache *cache);

int nss_cache_populate(NSSCache *cache);

int nss_cache_get_uid(NSSCache *cache, uint32_t *uidp, uint32_t *gidp, const char *user);
int nss_cache_get_gid(NSSCache *cache, uint32_t *gidp, const char *group);

int nss_cache_resolve_system_console_users(NSSCache *nss_cache, uint32_t **uidsp, size_t *n_uidsp);
