/*
 * NSS Cache
 */

#include <c-macro.h>
#include <c-rbtree.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/types.h>
#include "launch/nss-cache.h"
#include "util/error.h"

typedef struct NSSCacheNode {
        uint32_t uidgid;
        CRBNode rb;
        char name[];
} NSSCacheNode;

static int nss_cache_node_new(NSSCacheNode **nodep, const char *name, uint32_t uidgid) {
        NSSCacheNode *node;
        size_t n_name = strlen(name);

        node = malloc(sizeof(*node) + n_name + 1);
        if (!node)
                return error_origin(-ENOMEM);
        node->uidgid = uidgid;
        node->rb = (CRBNode)C_RBNODE_INIT(node->rb);
        memcpy(node->name, name, n_name + 1);

        *nodep = node;
        return 0;
}

static NSSCacheNode *nss_cache_node_free(NSSCacheNode *node) {
        assert(!c_rbnode_is_linked(&node->rb));

        free(node);

        return NULL;
}

void nss_cache_init(NSSCache *cache) {
        *cache = (NSSCache)NSS_CACHE_INIT;
}

void nss_cache_deinit(NSSCache *cache) {
        NSSCacheNode *node, *_node;

        c_rbtree_for_each_entry_safe_postorder_unlink(node, _node, &cache->user_tree, rb)
                nss_cache_node_free(node);

        c_rbtree_for_each_entry_safe_postorder_unlink(node, _node, &cache->group_tree, rb)
                nss_cache_node_free(node);
}

static int nss_cache_node_compare(CRBTree *t, void *k, CRBNode *rb) {
        const char *name = k;
        NSSCacheNode *node = c_rbnode_entry(rb, NSSCacheNode, rb);

        return strcmp(name, node->name);
}

int nss_cache_get_uid(NSSCache *cache, uid_t *uidp, const char *user) {
        NSSCacheNode *node;
        CRBNode **slot, *parent;
        int r;

        slot = c_rbtree_find_slot(&cache->user_tree, nss_cache_node_compare, user, &parent);
        if (!slot) {
                node = c_rbnode_entry(parent, NSSCacheNode, rb);
        } else {
                struct passwd *pw;

                pw = getpwnam(user);
                if (!pw)
                        return NSS_CACHE_E_INVALID_NAME;

                r = nss_cache_node_new(&node, user, pw->pw_uid);
                if (r)
                        return error_trace(r);

                c_rbtree_add(&cache->user_tree, parent, slot, &node->rb);
        }

        *uidp = node->uidgid;

        return 0;
}

int nss_cache_get_gid(NSSCache *cache, gid_t *gidp, const char *group) {
        NSSCacheNode *node;
        CRBNode **slot, *parent;
        int r;

        slot = c_rbtree_find_slot(&cache->group_tree, nss_cache_node_compare, group, &parent);
        if (!slot) {
                node = c_rbnode_entry(parent, NSSCacheNode, rb);
        } else {
                struct group *gr;

                gr = getgrnam(group);
                if (!gr)
                        return NSS_CACHE_E_INVALID_NAME;

                r = nss_cache_node_new(&node, group, gr->gr_gid);
                if (r)
                        return error_trace(r);

                c_rbtree_add(&cache->group_tree, parent, slot, &node->rb);
        }

        *gidp = node->uidgid;

        return 0;
}
