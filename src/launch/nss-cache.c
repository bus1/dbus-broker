/*
 * NSS Cache
 *
 * Calling out to NSS is potentially slow and prone to deadlocks, so we
 * maintain a cache to only call out when necessary. This cache does no
 * invalidation, so should not be long-living.
 *
 * The cache can be populated from /etc/{passwd,group}, which means NSS
 * will be invoked only for users/groups that do not appear in these
 * files, which should not happen on a well-configured system.
 *
 * The root user is hardcoded to always return UID 0, see passwd(5).
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

static int nss_cache_add_user(NSSCache *cache, const char *user, uid_t uid) {
        NSSCacheNode *node;
        CRBNode **slot, *parent;
        int r;

        slot = c_rbtree_find_slot(&cache->user_tree, nss_cache_node_compare, user, &parent);
        if (!slot) {
                node = c_rbnode_entry(parent, NSSCacheNode, rb);
                node->uidgid = uid;
        } else {
                r = nss_cache_node_new(&node, user, uid);
                if (r)
                        return error_trace(r);

                c_rbtree_add(&cache->user_tree, parent, slot, &node->rb);
        }

        return 0;
}

static int nss_cache_add_group(NSSCache *cache, const char *group, gid_t gid) {
        NSSCacheNode *node;
        CRBNode **slot, *parent;
        int r;

        slot = c_rbtree_find_slot(&cache->group_tree, nss_cache_node_compare, group, &parent);
        if (!slot) {
                node = c_rbnode_entry(parent, NSSCacheNode, rb);
                node->uidgid = gid;
        } else {
                r = nss_cache_node_new(&node, group, gid);
                if (r)
                        return error_trace(r);

                c_rbtree_add(&cache->group_tree, parent, slot, &node->rb);
        }

        return 0;
}

static int nss_cache_populate_users(NSSCache *cache) {
        _c_cleanup_(c_fclosep) FILE *passwd = NULL;
        struct passwd *pw;
        int r;

        passwd = fopen("/etc/passwd", "rme");
        if (!passwd) {
                if (errno == ENOENT)
                        return 0;

                return error_origin(-errno);
        }

        while ((pw = fgetpwent(passwd))) {
                r = nss_cache_add_user(cache, pw->pw_name, pw->pw_uid);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

static int nss_cache_populate_groups(NSSCache *cache) {
        _c_cleanup_(c_fclosep) FILE *group = NULL;
        struct group *gr;
        int r;

        group = fopen("/etc/group", "rme");
        if (!group) {
                if (errno == ENOENT)
                        return 0;

                return error_origin(-errno);
        }

        while ((gr = fgetgrent(group))) {
                r = nss_cache_add_group(cache, gr->gr_name, gr->gr_gid);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

int nss_cache_populate(NSSCache *cache) {
        int r;

        r = nss_cache_populate_users(cache);
        if (r)
                return error_trace(r);

        r = nss_cache_populate_groups(cache);
        if (r)
                return error_trace(r);

        return 0;
}

int nss_cache_get_uid(NSSCache *cache, uid_t *uidp, const char *user) {
        NSSCacheNode *node;
        CRBNode **slot, *parent;
        char *end;
        unsigned long long int uid;
        int r;

        if (!strcmp(user, "root")) {
                *uidp = 0;
                return 0;
        }

        static_assert(sizeof(uid_t) == sizeof(uint32_t), "uid_t is not 32 bits");
        errno = 0;
        uid = strtoull(user, &end, 10);
        if (end != user && *end == '\0' && errno == 0 && uid < UINT32_MAX) {
                *uidp = uid;
                return 0;
        }

        slot = c_rbtree_find_slot(&cache->user_tree, nss_cache_node_compare, user, &parent);
        if (!slot) {
                node = c_rbnode_entry(parent, NSSCacheNode, rb);
        } else {
                struct passwd *pw;

                fprintf(stderr, "Looking up UID for user '%s' over NSS...\n", user);

                pw = getpwnam(user);
                if (!pw)
                        return NSS_CACHE_E_INVALID_NAME;

                fprintf(stderr, "NSS returned UID %u for user '%s'\n", pw->pw_uid, user);

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
        char *end;
        unsigned long long int gid;
        int r;

        static_assert(sizeof(gid_t) == sizeof(uint32_t), "gid_t is not 32 bits");
        errno = 0;
        gid = strtoull(group, &end, 10);
        if (end != group && *end == '\0' && errno == 0 && gid < UINT32_MAX) {
                *gidp = gid;
                return 0;
        }

        slot = c_rbtree_find_slot(&cache->group_tree, nss_cache_node_compare, group, &parent);
        if (!slot) {
                node = c_rbnode_entry(parent, NSSCacheNode, rb);
        } else {
                struct group *gr;

                fprintf(stderr, "Looking up GID for group '%s' over NSS...\n", group);

                gr = getgrnam(group);
                if (!gr)
                        return NSS_CACHE_E_INVALID_NAME;

                fprintf(stderr, "NSS returned GID %u for group '%s'\n", gr->gr_gid, group);

                r = nss_cache_node_new(&node, group, gr->gr_gid);
                if (r)
                        return error_trace(r);

                c_rbtree_add(&cache->group_tree, parent, slot, &node->rb);
        }

        *gidp = node->uidgid;

        return 0;
}
