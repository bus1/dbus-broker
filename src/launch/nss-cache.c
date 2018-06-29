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
        uint32_t id;
        CRBNode rb_by_name;
        CRBNode rb_by_id;

        /*
         * Note that these structures are not fully allocated. They are plain
         * copies of the source data, with non-static fields cleared to 0.
         */
        union {
                struct passwd pw;
                struct group gr;
        };

        char name[];
} NSSCacheNode;

static int nss_cache_node_new(NSSCacheNode **nodep, const char *name, uint32_t id) {
        NSSCacheNode *node;
        size_t n_name = strlen(name);

        node = malloc(sizeof(*node) + n_name + 1);
        if (!node)
                return error_origin(-ENOMEM);

        node->id = id;
        node->rb_by_name = (CRBNode)C_RBNODE_INIT(node->rb_by_name);
        node->rb_by_id = (CRBNode)C_RBNODE_INIT(node->rb_by_id);
        memcpy(node->name, name, n_name + 1);

        *nodep = node;
        return 0;
}

static NSSCacheNode *nss_cache_node_free(NSSCacheNode *node) {
        c_rbnode_unlink(&node->rb_by_name);
        c_rbnode_unlink(&node->rb_by_id);

        free(node);

        return NULL;
}

void nss_cache_init(NSSCache *cache) {
        *cache = (NSSCache)NSS_CACHE_INIT;
}

void nss_cache_deinit(NSSCache *cache) {
        NSSCacheNode *node, *safe;

        c_rbtree_for_each_entry_safe_postorder_unlink(node,
                                                      safe,
                                                      &cache->user_tree,
                                                      rb_by_name)
                nss_cache_node_free(node);

        c_rbtree_for_each_entry_safe_postorder_unlink(node,
                                                      safe,
                                                      &cache->group_tree,
                                                      rb_by_name)
                nss_cache_node_free(node);

        assert(c_rbtree_is_empty(&cache->user_tree));
        assert(c_rbtree_is_empty(&cache->uid_tree));
        assert(c_rbtree_is_empty(&cache->group_tree));
        assert(c_rbtree_is_empty(&cache->gid_tree));
}

static int nss_cache_node_compare_name(CRBTree *t, void *k, CRBNode *rb) {
        NSSCacheNode *node = c_rbnode_entry(rb, NSSCacheNode, rb_by_name);
        const char *name = k;

        return strcmp(name, node->name);
}

static int nss_cache_node_compare_id(CRBTree *t, void *k, CRBNode *rb) {
        NSSCacheNode *node = c_rbnode_entry(rb, NSSCacheNode, rb_by_id);
        uint32_t id = (uint32_t)(unsigned long)k;

        if (id > node->id)
                return 1;
        else if (id < node->id)
                return -1;
        else
                return 0;
}

static int nss_cache_add(CRBTree *tree_by_name,
                         CRBTree *tree_by_id,
                         NSSCacheNode **nodep,
                         const char *name,
                         uint32_t id) {
        CRBNode **slot_by_name, **slot_by_id, *parent_by_name, *parent_by_id;
        NSSCacheNode *node_by_name, *node_by_id;
        int r;

        slot_by_name = c_rbtree_find_slot(tree_by_name,
                                          nss_cache_node_compare_name,
                                          name,
                                          &parent_by_name);
        slot_by_id = c_rbtree_find_slot(tree_by_id,
                                        nss_cache_node_compare_id,
                                        (void *)(unsigned long)id,
                                        &parent_by_id);

        if (slot_by_name)
                node_by_name = NULL;
        else
                node_by_name = c_rbnode_entry(parent_by_name, NSSCacheNode, rb_by_name);

        if (slot_by_id)
                node_by_id = NULL;
        else
                node_by_id = c_rbnode_entry(parent_by_id, NSSCacheNode, rb_by_id);

        /*
         * Either the entry is linked by-name *AND* by-id (and it is the *SAME*
         * entry), or it is not linked at all. However, if only one of both is
         * known, or if they point to different entries, we will *NOT* cache
         * the new data. This situation implies a UID/GID conflict and there is
         * no sane way to handle this, other than bypassing the cache. Worst
         * case, you will end up calling into NSS all the time.
         */
        if (node_by_name != node_by_id) {
                *nodep = NULL;
                return 0;
        }

        if (!node_by_name && !node_by_id) {
                /*
                 * Neither by-name nor by-id is any entry linked. We have to
                 * create a new entry and link it into both trees.
                 *
                 * This is the common case, since the nss-cache is shortlived
                 * and there really shouldn't be any conflicts in UIDs/GIDs.
                 */
                r = nss_cache_node_new(&node_by_name, name, id);
                if (r)
                        return error_trace(r);

                c_rbtree_add(tree_by_name,
                             parent_by_name,
                             slot_by_name,
                             &node_by_name->rb_by_name);
                c_rbtree_add(tree_by_id,
                             parent_by_id,
                             slot_by_id,
                             &node_by_name->rb_by_id);
        }

        *nodep = node_by_name;
        return 0;
}

static int nss_cache_add_user(NSSCache *cache, struct passwd *pw) {
        NSSCacheNode *node;
        int r;

        r = nss_cache_add(&cache->user_tree,
                          &cache->uid_tree,
                          &node,
                          pw->pw_name,
                          pw->pw_uid);
        if (r)
                return error_trace(r);

        if (node) {
                memset(&node->pw, 0, sizeof(node->pw));
                node->pw.pw_name = node->name;
                node->pw.pw_uid = pw->pw_uid;
                node->pw.pw_gid = pw->pw_gid;
        }

        return 0;
}

static int nss_cache_add_group(NSSCache *cache, struct group *gr) {
        NSSCacheNode *node;
        int r;

        r = nss_cache_add(&cache->group_tree,
                          &cache->gid_tree,
                          &node,
                          gr->gr_name,
                          gr->gr_gid);
        if (r)
                return error_trace(r);

        if (node) {
                memset(&node->gr, 0, sizeof(node->gr));
                node->gr.gr_name = node->name;
                node->gr.gr_gid = gr->gr_gid;
        }

        return 0;
}

static int nss_cache_populate_users(NSSCache *cache) {
        _c_cleanup_(c_fclosep) FILE *passwd = NULL;
        struct passwd *pw;
        int r;

        passwd = fopen("/etc/passwd", "re");
        if (!passwd) {
                if (errno == ENOENT)
                        return 0;

                return error_origin(-errno);
        }

        while ((pw = fgetpwent(passwd))) {
                r = nss_cache_add_user(cache, pw);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

static int nss_cache_populate_groups(NSSCache *cache) {
        _c_cleanup_(c_fclosep) FILE *group = NULL;
        struct group *gr;
        int r;

        group = fopen("/etc/group", "re");
        if (!group) {
                if (errno == ENOENT)
                        return 0;

                return error_origin(-errno);
        }

        while ((gr = fgetgrent(group))) {
                r = nss_cache_add_group(cache, gr);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

int nss_cache_populate(NSSCache *cache) {
        int r;

        r = nss_cache_add_user(cache,
                               &(struct passwd){
                                        .pw_name = (char[]){ "root" },
                                        .pw_uid = 0,
                                        .pw_gid = 0,
                               });
        if (r)
                return error_trace(r);

        r = nss_cache_add_group(cache,
                                &(struct group){
                                        .gr_name = (char[]){ "root" },
                                        .gr_gid = 0,
                                });
        if (r)
                return error_trace(r);

        r = nss_cache_populate_users(cache);
        if (r)
                return error_trace(r);

        r = nss_cache_populate_groups(cache);
        if (r)
                return error_trace(r);

        return 0;
}

int nss_cache_get_uid(NSSCache *cache, uint32_t *uidp, uint32_t *gidp, const char *name) {
        unsigned long long id;
        NSSCacheNode *node;
        struct passwd *pw;
        bool by_id = false;
        char *end;
        int r;

        static_assert(sizeof(uid_t) == sizeof(uint32_t), "uid_t is not 32 bits");

        /* try parsing @name as a numeric ID */
        errno = 0;
        id = strtoull(name, &end, 10);
        if (end != name && *end == '\0' && errno == 0 && id < UINT32_MAX)
                by_id = true;

        /*
         * First try a lookup in our cache. If we find an entry, use it and
         * return it. If not, we have to fall back to NSS lookups below.
         */
        if (by_id)
                node = c_rbtree_find_entry(&cache->uid_tree,
                                           nss_cache_node_compare_id,
                                           (void *)(unsigned long)id,
                                           NSSCacheNode,
                                           rb_by_id);
        else
                node = c_rbtree_find_entry(&cache->user_tree,
                                           nss_cache_node_compare_name,
                                           name,
                                           NSSCacheNode,
                                           rb_by_name);
        if (node) {
                pw = &node->pw;
        } else {
                fprintf(stderr, "Looking up NSS user entry for '%s'...\n", name);

                if (by_id)
                        pw = getpwuid(id);
                else
                        pw = getpwnam(name);

                if (pw) {
                        fprintf(stderr, "NSS returned NAME '%s' and UID '%u'\n",
                                pw->pw_name, pw->pw_uid);
                } else {
                        fprintf(stderr, "NSS returned no entry for '%s'\n",
                                name);
                        return NSS_CACHE_E_INVALID_NAME;
                }

                r = nss_cache_add_user(cache, pw);
                if (r)
                        return r;
        }

        if (uidp)
                *uidp = pw->pw_uid;
        if (gidp)
                *gidp = pw->pw_gid;
        return 0;
}

int nss_cache_get_gid(NSSCache *cache, uint32_t *gidp, const char *name) {
        unsigned long long id;
        NSSCacheNode *node;
        struct group *gr;
        bool by_id = false;
        char *end;
        int r;

        static_assert(sizeof(gid_t) == sizeof(uint32_t), "gid_t is not 32 bits");

        /* try parsing @name as a numeric ID */
        errno = 0;
        id = strtoull(name, &end, 10);
        if (end != name && *end == '\0' && errno == 0 && id < UINT32_MAX)
                by_id = true;

        /*
         * First try a lookup in our cache. If we find an entry, use it and
         * return it. If not, we have to fall back to NSS lookups below.
         */
        if (by_id)
                node = c_rbtree_find_entry(&cache->gid_tree,
                                           nss_cache_node_compare_id,
                                           (void *)(unsigned long)id,
                                           NSSCacheNode,
                                           rb_by_id);
        else
                node = c_rbtree_find_entry(&cache->group_tree,
                                           nss_cache_node_compare_name,
                                           name,
                                           NSSCacheNode,
                                           rb_by_name);
        if (node) {
                gr = &node->gr;
        } else {
                fprintf(stderr, "Looking up NSS group entry for '%s'...\n", name);

                if (by_id)
                        gr = getgrgid(id);
                else
                        gr = getgrnam(name);

                if (gr) {
                        fprintf(stderr, "NSS returned NAME '%s' and GID '%u'\n",
                                gr->gr_name, gr->gr_gid);
                } else {
                        fprintf(stderr, "NSS returned no entry for '%s'\n",
                                name);
                        return NSS_CACHE_E_INVALID_NAME;
                }

                r = nss_cache_add_group(cache, gr);
                if (r)
                        return r;
        }

        *gidp = gr->gr_gid;
        return 0;
}

int nss_cache_resolve_system_console_users(NSSCache *nss_cache, uint32_t **uidsp, size_t *n_uidsp) {
        static const char * const usernames[] = { SYSTEM_CONSOLE_USERS };
        _c_cleanup_(c_freep) uint32_t *uids = NULL;
        size_t i, n_uids = 0;
        uid_t uid;
        int r;

        if (!C_ARRAY_SIZE(usernames)) {
                *uidsp = NULL;
                *n_uidsp = 0;
                return 0;
        }

        uids = calloc(C_ARRAY_SIZE(usernames), sizeof(*uids));
        if (!uids)
                return error_origin(-ENOMEM);

        for (i = 0; i < C_ARRAY_SIZE(usernames); ++i) {
                r = nss_cache_get_uid(nss_cache, &uid, NULL, usernames[i]);
                if (r) {
                        if (r == NSS_CACHE_E_INVALID_NAME)
                                continue;

                        return error_fold(r);
                }

                uids[n_uids++] = uid;
        }

        *uidsp = uids;
        *n_uidsp = n_uids;
        uids = NULL;
        return 0;
}
