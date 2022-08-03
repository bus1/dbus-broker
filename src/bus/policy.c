/*
 * D-Bus Policy
 */

#include <c-dvar.h>
#include <c-list.h>
#include <c-rbtree.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include "bus/name.h"
#include "bus/policy.h"
#include "dbus/protocol.h"
#include "util/apparmor.h"
#include "util/common.h"
#include "util/error.h"
#include "util/selinux.h"

/* D-Bus type 'a(btbs)' */
#define POLICY_TYPE_a_btbs              \
        C_DVAR_T_ARRAY(                 \
                C_DVAR_T_TUPLE4(        \
                        C_DVAR_T_b,     \
                        C_DVAR_T_t,     \
                        C_DVAR_T_b,     \
                        C_DVAR_T_s      \
                )                       \
        )

/* D-Bus type 'a(btssssuutt)' */
#define POLICY_TYPE_a_btssssuutt        \
        C_DVAR_T_ARRAY(                 \
                C_DVAR_T_TUPLE10(       \
                        C_DVAR_T_b,     \
                        C_DVAR_T_t,     \
                        C_DVAR_T_s,     \
                        C_DVAR_T_s,     \
                        C_DVAR_T_s,     \
                        C_DVAR_T_s,     \
                        C_DVAR_T_u,     \
                        C_DVAR_T_u,     \
                        C_DVAR_T_t,     \
                        C_DVAR_T_t      \
                )                       \
        )

/* D-Bus type that contains an entire policy dump */
#define POLICY_TYPE                                                             \
        C_DVAR_T_TUPLE4(                                                        \
                C_DVAR_T_ARRAY(                                                 \
                        C_DVAR_T_TUPLE2(                                        \
                                C_DVAR_T_u,                                     \
                                C_DVAR_T_TUPLE5(                                \
                                        C_DVAR_T_b,                             \
                                        C_DVAR_T_t,                             \
                                        POLICY_TYPE_a_btbs,                     \
                                        POLICY_TYPE_a_btssssuutt,               \
                                        POLICY_TYPE_a_btssssuutt                \
                                )                                               \
                        )                                                       \
                ),                                                              \
                C_DVAR_T_ARRAY(                                                 \
                        C_DVAR_T_TUPLE4(                                        \
                                C_DVAR_T_b,                                     \
                                C_DVAR_T_u,                                     \
                                C_DVAR_T_u,                                     \
                                C_DVAR_T_TUPLE5(                                \
                                        C_DVAR_T_b,                             \
                                        C_DVAR_T_t,                             \
                                        POLICY_TYPE_a_btbs,                     \
                                        POLICY_TYPE_a_btssssuutt,               \
                                        POLICY_TYPE_a_btssssuutt                \
                                )                                               \
                        )                                                       \
                ),                                                              \
                C_DVAR_T_ARRAY(                                                 \
                        C_DVAR_T_TUPLE2(                                        \
                                C_DVAR_T_s,                                     \
                                C_DVAR_T_s                                      \
                        )                                                       \
                ),                                                              \
                C_DVAR_T_b                                                      \
        )

/*
 * XXX: This should be a compile-time static type, rather than computed at
 *      runtime!
 *
 * Preferably, what we would want here is:
 *
 *     static const CDVarType policy_type[] = {
 *             C_DVAR_T_INIT(POLICY_TYPE)
 *     };
 *
 * However, the type is so big, the `C_DVAR_T_*` macros end up producing too
 * big of an output and compilers fall over if they run on low-end machines.
 * Hence, we compute the type at runtime for now. This is not a big issue,
 * since this is fast, anyway. However, it feels wrong to do this at runtime,
 * so we should find a better way to encode this at compile-time.
 */
static const CDVarType *policy_type = NULL;

static PolicyXmit *policy_xmit_free(PolicyXmit *xmit) {
        if (!xmit)
                return NULL;

        c_list_unlink(&xmit->batch_link);
        free(xmit);

        return NULL;
}

C_DEFINE_CLEANUP(PolicyXmit *, policy_xmit_free);

static int policy_xmit_new(PolicyXmit **xmitp,
                           unsigned int type,
                           unsigned int broadcast,
                           const char *path,
                           const char *interface,
                           const char *member,
                           uint64_t min_fds,
                           uint64_t max_fds) {
        _c_cleanup_(policy_xmit_freep) PolicyXmit *xmit = NULL;
        size_t n_path, n_interface, n_member;
        void *p;

        n_path = (path && *path) ? strlen(path) + 1 : 0;
        n_interface = (interface && *interface) ? strlen(interface) + 1 : 0;
        n_member = (member && *member) ? strlen(member) + 1 : 0;

        xmit = calloc(1, sizeof(*xmit) + n_path + n_interface + n_member);
        if (!xmit)
                return error_origin(-ENOMEM);

        *xmit = (PolicyXmit)POLICY_XMIT_NULL(*xmit);
        xmit->type = type;
        xmit->broadcast = broadcast;
        xmit->min_fds = min_fds;
        xmit->max_fds = max_fds;

        p = xmit + 1;
        if (n_path) {
                xmit->path = p;
                p = stpcpy(p, path) + 1;
        }
        if (n_interface) {
                xmit->interface = p;
                p = stpcpy(p, interface) + 1;
        }
        if (n_member) {
                xmit->member = p;
                p = stpcpy(p, member) + 1;
        }

        *xmitp = xmit;
        xmit = NULL;
        return 0;
}

static int policy_batch_name_compare(CRBTree *t, void *k, CRBNode *n) {
        PolicyBatchName *name = c_container_of(n, PolicyBatchName, batch_node);

        return strcmp(k, name->name);
}

static PolicyBatchName *policy_batch_name_free(PolicyBatchName *name) {
        PolicyXmit *xmit;

        if (!name)
                return NULL;

        while ((xmit = c_list_first_entry(&name->recv_unindexed, PolicyXmit, batch_link)))
                policy_xmit_free(xmit);
        while ((xmit = c_list_first_entry(&name->send_unindexed, PolicyXmit, batch_link)))
                policy_xmit_free(xmit);

        c_rbnode_unlink(&name->batch_node);
        free(name);

        return NULL;
}

C_DEFINE_CLEANUP(PolicyBatchName *, policy_batch_name_free);

static int policy_batch_name_new(PolicyBatchName **namep, PolicyBatch *batch, const char *name_str) {
        _c_cleanup_(policy_batch_name_freep) PolicyBatchName *name = NULL;

        name = calloc(1, sizeof(*name) + strlen(name_str) + 1);
        if (!name)
                return error_origin(-ENOMEM);

        *name = (PolicyBatchName)POLICY_BATCH_NAME_NULL(*name);
        name->batch = batch;
        strcpy(name->name, name_str);

        *namep = name;
        name = NULL;
        return 0;
}

/**
 * policy_batch_new() - XXX
 */
int policy_batch_new(PolicyBatch **batchp) {
        _c_cleanup_(policy_batch_unrefp) PolicyBatch *batch = NULL;

        batch = calloc(1, sizeof(*batch));
        if (!batch)
                return error_origin(-ENOMEM);

        *batch = (PolicyBatch)POLICY_BATCH_NULL(*batch);

        *batchp = batch;
        batch = NULL;
        return 0;
}

/* internal callback for policy_batch_unref() */
void policy_batch_free(_Atomic unsigned long *n_refs, void *userdata) {
        PolicyBatch *batch = c_container_of(n_refs, PolicyBatch, n_refs);
        PolicyBatchName *name, *t_name;

        c_rbtree_for_each_entry_safe_postorder_unlink(name, t_name, &batch->name_tree, batch_node)
                policy_batch_name_free(name);

        free(batch);
}

static PolicyBatchName *policy_batch_find_name(PolicyBatch *batch, const char *name_str) {
        return c_rbtree_find_entry(&batch->name_tree,
                                   policy_batch_name_compare,
                                   name_str,
                                   PolicyBatchName,
                                   batch_node);
}

static int policy_batch_at_name(PolicyBatch *batch, PolicyBatchName **namep, const char *name_str) {
        CRBNode *parent, **slot;
        PolicyBatchName *name;
        int r;

        slot = c_rbtree_find_slot(&batch->name_tree, policy_batch_name_compare, name_str, &parent);
        if (slot) {
                r = policy_batch_name_new(&name, batch, name_str);
                if (r)
                        return error_trace(r);

                c_rbtree_add(&name->batch->name_tree, parent, slot, &name->batch_node);
        } else {
                name = c_container_of(parent, PolicyBatchName, batch_node);
        }

        *namep = name;
        return 0;
}

static int policy_batch_add_own(PolicyBatch *batch,
                                const char *name_str,
                                PolicyVerdict verdict) {
        PolicyBatchName *name;
        int r;

        r = policy_batch_at_name(batch, &name, name_str);
        if (r)
                return error_trace(r);

        /*
         * If the priority is lower than the current verdict, there is no point
         * in remembering it, since it will always be superceded.
         */
        if (verdict.priority >= name->own_verdict.priority)
                name->own_verdict = verdict;

        return 0;
}

static int policy_batch_add_own_prefix(PolicyBatch *batch,
                                       const char *name_str,
                                       PolicyVerdict verdict) {
        PolicyBatchName *name;
        int r;

        r = policy_batch_at_name(batch, &name, name_str);
        if (r)
                return error_trace(r);

        /*
         * If the priority is lower than the current verdict, there is no point
         * in remembering it, since it will always be superceded.
         */
        if (verdict.priority >= name->own_prefix_verdict.priority)
                name->own_prefix_verdict = verdict;

        return 0;
}

static int policy_batch_add_send(PolicyBatch *batch,
                                 const char *name_str,
                                 PolicyVerdict verdict,
                                 unsigned int type,
                                 unsigned int broadcast,
                                 const char *path,
                                 const char *interface,
                                 const char *member,
                                 uint64_t min_fds,
                                 uint64_t max_fds) {
        _c_cleanup_(policy_xmit_freep) PolicyXmit *xmit = NULL;
        PolicyBatchName *name;
        int r;

        r = policy_xmit_new(&xmit, type, broadcast, path, interface, member, min_fds, max_fds);
        if (r)
                return error_trace(r);

        xmit->verdict = verdict;

        r = policy_batch_at_name(batch, &name, name_str ?: "");
        if (r)
                return error_trace(r);

        c_list_link_tail(&name->send_unindexed, &xmit->batch_link);
        xmit = NULL;
        return 0;
}

static int policy_batch_add_recv(PolicyBatch *batch,
                                 const char *name_str,
                                 PolicyVerdict verdict,
                                 unsigned int type,
                                 unsigned int broadcast,
                                 const char *path,
                                 const char *interface,
                                 const char *member,
                                 uint64_t min_fds,
                                 uint64_t max_fds) {
        _c_cleanup_(policy_xmit_freep) PolicyXmit *xmit = NULL;
        PolicyBatchName *name;
        int r;

        r = policy_xmit_new(&xmit, type, broadcast, path, interface, member, min_fds, max_fds);
        if (r)
                return error_trace(r);

        xmit->verdict = verdict;

        r = policy_batch_at_name(batch, &name, name_str ?: "");
        if (r)
                return error_trace(r);

        c_list_link_tail(&name->recv_unindexed, &xmit->batch_link);
        xmit = NULL;
        return 0;
}

static int policy_registry_node_compare(CRBTree *t, void *k, CRBNode *n) {
        PolicyRegistryNode *node = c_container_of(n, PolicyRegistryNode, registry_node);
        PolicyRegistryNodeIndex *index = k;

        if (index->uidgid_start < node->index.uidgid_start)
                return -1;
        else if (index->uidgid_start > node->index.uidgid_start)
                return 1;
        else if (index->uidgid_end < node->index.uidgid_end)
                return -1;
        else if (index->uidgid_end > node->index.uidgid_end)
                return 1;
        else
                return 0;
}

static PolicyRegistryNode *policy_registry_node_free(PolicyRegistryNode *node) {
        if (!node)
                return NULL;

        c_rbnode_unlink(&node->registry_node);
        policy_batch_unref(node->batch);
        free(node);

        return NULL;
}

C_DEFINE_CLEANUP(PolicyRegistryNode *, policy_registry_node_free);

static int policy_registry_node_new(PolicyRegistryNode **nodep, uint32_t uidgid_start, uint32_t uidgid_end) {
        _c_cleanup_(policy_registry_node_freep) PolicyRegistryNode *node = NULL;
        int r;

        node = calloc(1, sizeof(*node));
        if (!node)
                return error_origin(-ENOMEM);

        *node = (PolicyRegistryNode)POLICY_REGISTRY_NODE_NULL(*node);
        node->index.uidgid_start = uidgid_start;
        node->index.uidgid_end = uidgid_end;

        r = policy_batch_new(&node->batch);
        if (r)
                return error_trace(r);

        *nodep = node;
        node = NULL;
        return 0;
}

/**
 * policy_registry_new() - XXX
 */
int policy_registry_new(PolicyRegistry **registryp, const char *fallback_seclabel) {
        _c_cleanup_(policy_registry_freep) PolicyRegistry *registry = NULL;
        int r;

        registry = calloc(1, sizeof(*registry));
        if (!registry)
                return error_origin(-ENOMEM);

        *registry = (PolicyRegistry)POLICY_REGISTRY_NULL;

        r = bus_apparmor_registry_new(&registry->apparmor, fallback_seclabel);
        if (r)
                return error_fold(r);

        r = bus_selinux_registry_new(&registry->selinux, fallback_seclabel);
        if (r)
                return error_fold(r);

        r = policy_batch_new(&registry->default_batch);
        if (r)
                return error_trace(r);

        *registryp = registry;
        registry = NULL;
        return 0;
}

/**
 * policy_registry_free() - XXX
 */
PolicyRegistry *policy_registry_free(PolicyRegistry *registry) {
        PolicyRegistryNode *node, *t_node;

        if (!registry)
                return NULL;

        c_rbtree_for_each_entry_safe_postorder_unlink(node, t_node, &registry->gid_tree, registry_node)
                policy_registry_node_free(node);
        c_rbtree_for_each_entry_safe_postorder_unlink(node, t_node, &registry->uid_tree, registry_node)
                policy_registry_node_free(node);
        c_rbtree_for_each_entry_safe_postorder_unlink(node, t_node, &registry->uid_range_tree, registry_node)
                policy_registry_node_free(node);

        policy_batch_unref(registry->default_batch);
        bus_selinux_registry_unref(registry->selinux);
        bus_apparmor_registry_unref(registry->apparmor);
        free(registry);

        return NULL;
}

static PolicyRegistryNode *policy_registry_find_uid(PolicyRegistry *registry, uint32_t uid) {
        PolicyRegistryNodeIndex index = {
                .uidgid_start = uid,
                .uidgid_end = uid,
        };

        return c_rbtree_find_entry(&registry->uid_tree,
                                   policy_registry_node_compare,
                                   &index,
                                   PolicyRegistryNode,
                                   registry_node);
}

static PolicyRegistryNode *policy_registry_find_gid(PolicyRegistry *registry, uint32_t gid) {
        PolicyRegistryNodeIndex index = {
                .uidgid_start = gid,
                .uidgid_end = gid,
        };

        return c_rbtree_find_entry(&registry->gid_tree,
                                   policy_registry_node_compare,
                                   &index,
                                   PolicyRegistryNode,
                                   registry_node);
}

static int policy_registry_at_uidgid(CRBTree *tree, PolicyRegistryNode **nodep, uint32_t uidgid_start, uint32_t uidgid_end) {
        CRBNode *parent, **slot;
        PolicyRegistryNode *node;
        PolicyRegistryNodeIndex index = {
                .uidgid_start = uidgid_start,
                .uidgid_end = uidgid_end,
        };
        int r;

        slot = c_rbtree_find_slot(tree,
                                  policy_registry_node_compare,
                                  &index,
                                  &parent);
        if (slot) {
                r = policy_registry_node_new(&node, uidgid_start, uidgid_end);
                if (r)
                        return error_trace(r);

                c_rbtree_add(tree, parent, slot, &node->registry_node);
        } else {
                node = c_container_of(parent, PolicyRegistryNode, registry_node);
        }

        *nodep = node;
        return 0;
}

static int policy_registry_at_uid(PolicyRegistry *registry, PolicyRegistryNode **nodep, uint32_t uid) {
        return policy_registry_at_uidgid(&registry->uid_tree, nodep, uid, uid);
}

static int policy_registry_at_uid_range(PolicyRegistry *registry, PolicyRegistryNode **nodep, uint32_t uid_start, uint32_t uid_end) {
        return policy_registry_at_uidgid(&registry->uid_range_tree, nodep, uid_start, uid_end);
}

static int policy_registry_at_gid(PolicyRegistry *registry, PolicyRegistryNode **nodep, uint32_t gid) {
        return policy_registry_at_uidgid(&registry->gid_tree, nodep, gid, gid);
}

static int policy_registry_import_batch(PolicyRegistry *registry,
                                        PolicyBatch *batch,
                                        CDVar *v) {
        const char *name_str, *interface, *member, *path;
        PolicyVerdict verdict;
        unsigned int type, broadcast;
        uint64_t min_fds, max_fds;
        bool is_prefix;
        int r;

        c_dvar_read(v, "(bt", &verdict.verdict, &verdict.priority);
        batch->connect_verdict = verdict;

        c_dvar_read(v, "[");

        while (c_dvar_more(v)) {
                c_dvar_read(v,
                            "(btbs)",
                            &verdict.verdict,
                            &verdict.priority,
                            &is_prefix,
                            &name_str);

                if (is_prefix)
                        r = policy_batch_add_own_prefix(batch, name_str, verdict);
                else
                        r = policy_batch_add_own(batch, name_str, verdict);
                if (r)
                        return error_trace(r);
        }

        c_dvar_read(v, "][");

        while (c_dvar_more(v)) {
                c_dvar_read(v, "(btssssuutt)",
                            &verdict.verdict,
                            &verdict.priority,
                            &name_str,
                            &path,
                            &interface,
                            &member,
                            &type,
                            &broadcast,
                            &min_fds,
                            &max_fds);

                if (broadcast >= _UTIL_TRISTATE_N)
                        return POLICY_E_INVALID;

                r = policy_batch_add_send(batch,
                                          name_str,
                                          verdict,
                                          type,
                                          broadcast,
                                          path,
                                          interface,
                                          member,
                                          min_fds,
                                          max_fds);
                if (r)
                        return error_trace(r);
        }

        c_dvar_read(v, "][");

        while (c_dvar_more(v)) {
                c_dvar_read(v, "(btssssuutt)",
                            &verdict.verdict,
                            &verdict.priority,
                            &name_str,
                            &path,
                            &interface,
                            &member,
                            &type,
                            &broadcast,
                            &min_fds,
                            &max_fds);

                if (broadcast >= _UTIL_TRISTATE_N)
                        return POLICY_E_INVALID;

                r = policy_batch_add_recv(batch,
                                          name_str,
                                          verdict,
                                          type,
                                          broadcast,
                                          path,
                                          interface,
                                          member,
                                          min_fds,
                                          max_fds);
                if (r)
                        return error_trace(r);
        }

        c_dvar_read(v, "])");

        return 0;
}

/**
 * policy_registry_import() - XXX
 */
int policy_registry_import(PolicyRegistry *registry, CDVar *v) {
        PolicyRegistryNode *node;
        const char *bustype;
        bool apparmor;
        int r;

        c_dvar_read(v, "<(", policy_type);

        c_dvar_read(v, "[");

        while (c_dvar_more(v)) {
                uint32_t uid;

                c_dvar_read(v, "(u", &uid);

                if (uid == (uint32_t)-1) {
                        r = policy_registry_import_batch(registry, registry->default_batch, v);
                        if (r)
                                return error_trace(r);
                } else {
                        r = policy_registry_at_uid(registry, &node, uid);
                        if (r)
                                return error_trace(r);

                        r = policy_registry_import_batch(registry, node->batch, v);
                        if (r)
                                return error_trace(r);
                }

                c_dvar_read(v, ")");
        }

        c_dvar_read(v, "][");

        while (c_dvar_more(v)) {
                bool group;
                uint32_t uidgid_start, uidgid_end;

                c_dvar_read(v, "(buu", &group, &uidgid_start, &uidgid_end);

                if (group) {
                        if (uidgid_start != uidgid_end)
                                return POLICY_E_INVALID;

                        r = policy_registry_at_gid(registry, &node, uidgid_start);
                        if (r)
                                return error_trace(r);
                } else {
                        r = policy_registry_at_uid_range(registry, &node, uidgid_start, uidgid_end);
                        if (r)
                                return error_trace(r);
                }

                r = policy_registry_import_batch(registry, node->batch, v);
                if (r)
                        return error_trace(r);

                c_dvar_read(v, ")");
        }

        c_dvar_read(v, "][");

        while (c_dvar_more(v)) {
                const char *name, *seclabel;

                c_dvar_read(v, "(ss)", &name, &seclabel);

                r = bus_selinux_registry_add_name(registry->selinux, name, seclabel);
                if (r)
                        return error_fold(r);
        }

        c_dvar_read(v, "]bs)>", &apparmor, &bustype);

        r = bus_apparmor_set_bus_type(registry->apparmor, apparmor ? bustype : NULL);
        if (r)
                return error_fold(r);

        r = c_dvar_get_poison(v);
        if (r)
                return POLICY_E_INVALID;

        return 0;
}

/**
 * policy_snapshot_new() - XXX
 */
int policy_snapshot_new(PolicySnapshot **snapshotp,
                        PolicyRegistry *registry,
                        const char *seclabel,
                        uint32_t uid,
                        const uint32_t *gids,
                        size_t n_gids) {
        _c_cleanup_(policy_snapshot_freep) PolicySnapshot *snapshot = NULL;
        PolicyRegistryNode *node;
        size_t n_batches = 1 + n_gids;

        c_rbtree_for_each_entry(node, &registry->uid_range_tree, registry_node) {
                if (node->index.uidgid_start > uid)
                        continue;
                if (node->index.uidgid_end < uid)
                        continue;

                ++n_batches;
        }

        snapshot = calloc(1, sizeof(*snapshot) + n_batches * sizeof(*snapshot->batches));
        if (!snapshot)
                return error_origin(-ENOMEM);

        *snapshot = (PolicySnapshot)POLICY_SNAPSHOT_NULL;

        snapshot->apparmor = bus_apparmor_registry_ref(registry->apparmor);
        snapshot->selinux = bus_selinux_registry_ref(registry->selinux);

        snapshot->seclabel = strdup(seclabel);
        if (!snapshot->seclabel)
                return error_origin(-ENOMEM);

        /* fetch matching uid policy */
        node = policy_registry_find_uid(registry, uid);
        if (node)
                snapshot->batches[snapshot->n_batches++] = policy_batch_ref(node->batch);
        else
                snapshot->batches[snapshot->n_batches++] = policy_batch_ref(registry->default_batch);

        /* fetch all matching uid-range policies */
        c_rbtree_for_each_entry(node, &registry->uid_range_tree, registry_node) {
                if (node->index.uidgid_start > uid)
                        continue;
                if (node->index.uidgid_end < uid)
                        continue;

                snapshot->batches[snapshot->n_batches++] = policy_batch_ref(node->batch);
        }

        /* fetch all matching gid policies */
        while (n_gids-- > 0) {
                node = policy_registry_find_gid(registry, gids[n_gids]);
                if (node)
                        snapshot->batches[snapshot->n_batches++] = policy_batch_ref(node->batch);
        }

        c_assert(snapshot->n_batches <= n_batches);

        *snapshotp = snapshot;
        snapshot = NULL;
        return 0;
}

/**
 * policy_snapshot_free() - XXX
 */
PolicySnapshot *policy_snapshot_free(PolicySnapshot *snapshot) {
        if (!snapshot)
                return NULL;

        while (snapshot->n_batches-- > 0)
                policy_batch_unref(snapshot->batches[snapshot->n_batches]);
        free(snapshot->seclabel);
        bus_selinux_registry_unref(snapshot->selinux);
        bus_apparmor_registry_unref(snapshot->apparmor);
        free(snapshot);

        return NULL;
}

/**
 * policy_snapshot_dup() - XXX
 */
int policy_snapshot_dup(PolicySnapshot *snapshot, PolicySnapshot **newp) {
        _c_cleanup_(policy_snapshot_freep) PolicySnapshot *new = NULL;
        size_t i;

        new = calloc(1, sizeof(*new) + snapshot->n_batches * sizeof(*new->batches));
        if (!new)
                return error_origin(-ENOMEM);

        *new = (PolicySnapshot)POLICY_SNAPSHOT_NULL;

        new->apparmor = bus_apparmor_registry_ref(snapshot->apparmor);
        new->selinux = bus_selinux_registry_ref(snapshot->selinux);

        new->seclabel = strdup(snapshot->seclabel);
        if (!new->seclabel)
                return error_origin(-ENOMEM);

        for (i = 0; i < snapshot->n_batches; ++i)
                new->batches[new->n_batches++] = policy_batch_ref(snapshot->batches[i]);

        *newp = new;
        new = NULL;
        return 0;
}

/**
 * policy_snapshot_check_connect() - XXX
 */
int policy_snapshot_check_connect(PolicySnapshot *snapshot) {
        PolicyVerdict verdict = POLICY_VERDICT_INIT;
        size_t i;

        for (i = 0; i < snapshot->n_batches; ++i)
                if (verdict.priority < snapshot->batches[i]->connect_verdict.priority)
                        verdict = snapshot->batches[i]->connect_verdict;

        return verdict.verdict ? 0 : POLICY_E_ACCESS_DENIED;
}

/**
 * policy_snapshot_check_own() - XXX
 */
int policy_snapshot_check_own(PolicySnapshot *snapshot, const char *name_str) {
        PolicyVerdict verdict = POLICY_VERDICT_INIT;
        PolicyBatchName *name;
        const char *end;
        CRBNode *rb;
        size_t i;
        int v, r;

        r = bus_apparmor_check_own(snapshot->apparmor, snapshot->seclabel, name_str);
        if (r) {
                if (r == BUS_APPARMOR_E_DENIED)
                        return POLICY_E_APPARMOR_ACCESS_DENIED;

                return error_fold(r);
        }

        r = bus_selinux_check_own(snapshot->selinux, snapshot->seclabel, name_str);
        if (r) {
                if (r == SELINUX_E_DENIED)
                        return POLICY_E_SELINUX_ACCESS_DENIED;

                return error_fold(r);
        }

        for (i = 0; i < snapshot->n_batches; ++i) {
                /*
                 * Iterate all prefixes of @name_str, including the empty
                 * prefix and the full string.
                 */
                for (end = name_str;
                     ;
                     end = strchrnul(end + 1, '.')) {
                        rb = snapshot->batches[i]->name_tree.root;
                        while (rb) {
                                name = c_container_of(rb, PolicyBatchName, batch_node);
                                v = strncmp(name_str, name->name, end - name_str);
                                if (v < 0)
                                        rb = rb->left;
                                else if (v > 0)
                                        rb = rb->right;
                                else if (name->name[end - name_str])
                                        rb = rb->left;
                                else
                                        break;
                        }

                        if (rb) {
                                if (verdict.priority < name->own_verdict.priority)
                                        verdict = name->own_verdict;
                                if (verdict.priority < name->own_prefix_verdict.priority)
                                        verdict = name->own_prefix_verdict;
                        }

                        if (!*end)
                                break;
                }
        }

        return verdict.verdict ? 0 : POLICY_E_ACCESS_DENIED;
}

static void policy_snapshot_check_xmit_name(PolicyBatch *batch,
                                            bool is_send,
                                            PolicyVerdict *verdict,
                                            const char *name_str,
                                            const char *interface,
                                            const char *member,
                                            const char *path,
                                            unsigned int type,
                                            bool broadcast,
                                            size_t n_fds) {
        PolicyBatchName *name;
        PolicyXmit *xmit;
        CList *list;

        name = policy_batch_find_name(batch, name_str);
        if (!name)
                return;

        list = is_send ? &name->send_unindexed : &name->recv_unindexed;

        c_list_for_each_entry(xmit, list, batch_link) {
                if (verdict->priority >= xmit->verdict.priority)
                        continue;

                if (xmit->type)
                        if (type != xmit->type)
                                continue;

                if (xmit->path)
                        if (!path || strcmp(path, xmit->path))
                                continue;

                if (xmit->interface)
                        if (!interface || strcmp(interface, xmit->interface))
                                continue;

                if (xmit->member)
                        if (!member || strcmp(member, xmit->member))
                                continue;

                switch (xmit->broadcast) {
                case UTIL_TRISTATE_YES:
                        if (!broadcast)
                                continue;
                        break;
                case UTIL_TRISTATE_NO:
                        if (broadcast)
                                continue;
                        break;
                }

                if (xmit->min_fds > n_fds)
                        continue;

                if (xmit->max_fds < n_fds)
                        continue;

                *verdict = xmit->verdict;
        }
}

static void policy_snapshot_check_xmit(PolicyBatch *batch,
                                       bool is_send,
                                       PolicyVerdict *verdict,
                                       NameSet *nameset,
                                       const char *interface,
                                       const char *method,
                                       const char *path,
                                       unsigned int type,
                                       bool broadcast,
                                       size_t n_fds) {
        NameOwnership *ownership;
        size_t i;

        /*
         * The empty name is a catch-all entry. Always check it for every
         * policy decision.
         *
         * XXX: Maybe we should cache the pointer to the catch-all entry, since
         *      doing the lookup on all messages seems rather expensive just
         *      for the sake of simplicity.
         */
        policy_snapshot_check_xmit_name(batch,
                                        is_send,
                                        verdict,
                                        "",
                                        interface,
                                        method,
                                        path,
                                        type,
                                        broadcast,
                                        n_fds);

        if (!nameset) {
                /*
                 * If no names are passed, this messages deals with the driver.
                 * Hence, hard-code its name, since the driver owns it
                 * unconditionally, and just that name.
                 */
                policy_snapshot_check_xmit_name(batch,
                                                is_send,
                                                verdict,
                                                "org.freedesktop.DBus",
                                                interface,
                                                method,
                                                path,
                                                type,
                                                broadcast,
                                                n_fds);
        } else if (nameset->type == NAME_SET_TYPE_OWNER) {
                /*
                 * A set of owned names is given. In this case, we iterate all
                 * of them and match against each. Note that this matches even
                 * on non-primary name owners.
                 */
                c_rbtree_for_each_entry(ownership,
                                        &nameset->owner->ownership_tree,
                                        owner_node)
                        policy_snapshot_check_xmit_name(batch,
                                                        is_send,
                                                        verdict,
                                                        ownership->name->name,
                                                        interface,
                                                        method,
                                                        path,
                                                        type,
                                                        broadcast,
                                                        n_fds);
        } else if (nameset->type == NAME_SET_TYPE_SNAPSHOT) {
                /*
                 * An ownership-snapshot is given. Again, we simply iterate the
                 * names and match each. Note that the snapshot must contain
                 * queued names as well, since the policy matches on it.
                 */
                for (i = 0; i < nameset->snapshot->n_names; ++i)
                        policy_snapshot_check_xmit_name(batch,
                                                        is_send,
                                                        verdict,
                                                        nameset->snapshot->names[i]->name,
                                                        interface,
                                                        method,
                                                        path,
                                                        type,
                                                        broadcast,
                                                        n_fds);
        } else if (nameset->type != NAME_SET_TYPE_EMPTY) {
                c_assert(0);
        }
}

/**
 * policy_snapshot_check_send() - XXX
 */
int policy_snapshot_check_send(PolicySnapshot *snapshot,
                               const char *subject_seclabel,
                               NameSet *subject,
                               uint64_t subject_id,
                               const char *interface,
                               const char *method,
                               const char *path,
                               unsigned int type,
                               bool broadcast,
                               size_t n_fds) {
        PolicyVerdict verdict = POLICY_VERDICT_INIT;
        size_t i;
        int r;

        r = bus_apparmor_check_send(snapshot->apparmor, snapshot->seclabel, subject_seclabel,
                                    subject, subject_id, path, interface, method);
        if (r) {
                if (r == BUS_APPARMOR_E_DENIED)
                        return POLICY_E_APPARMOR_ACCESS_DENIED;

                return error_fold(r);
        }

        r = bus_selinux_check_send(snapshot->selinux, snapshot->seclabel, subject_seclabel);
        if (r) {
                if (r == SELINUX_E_DENIED)
                        return POLICY_E_SELINUX_ACCESS_DENIED;

                return error_fold(r);
        }

        for (i = 0; i < snapshot->n_batches; ++i)
                policy_snapshot_check_xmit(snapshot->batches[i],
                                           true,
                                           &verdict,
                                           subject,
                                           interface,
                                           method,
                                           path,
                                           type,
                                           broadcast,
                                           n_fds);

        return verdict.verdict ? 0 : POLICY_E_ACCESS_DENIED;
}

/**
 * policy_snapshot_check_receive() - XXX
 */
int policy_snapshot_check_receive(PolicySnapshot *snapshot,
                                  const char *subject_seclabel,
                                  NameSet *subject,
                                  uint64_t subject_id,
                                  const char *interface,
                                  const char *method,
                                  const char *path,
                                  unsigned int type,
                                  bool broadcast,
                                  size_t n_fds) {
        PolicyVerdict verdict = POLICY_VERDICT_INIT;
        size_t i;

        for (i = 0; i < snapshot->n_batches; ++i)
                policy_snapshot_check_xmit(snapshot->batches[i],
                                           false,
                                           &verdict,
                                           subject,
                                           interface,
                                           method,
                                           path,
                                           type,
                                           broadcast,
                                           n_fds);

        return verdict.verdict ? 0 : POLICY_E_ACCESS_DENIED;
}
