/*
 * D-Bus Policy
 */

#include <c-list.h>
#include <c-macro.h>
#include <c-rbtree.h>
#include <stdlib.h>
#include "bus/name.h"
#include "bus/policy.h"
#include "dbus/protocol.h"
#include "util/error.h"

bool policy_decision_is_default(PolicyDecision *decision) {
        return !decision->priority && !decision->deny;
}

static int policy_own_entry_new(PolicyOwnEntry **entryp, CRBTree *policy,
                                      const char *name, bool deny, uint64_t priority,
                                      CRBNode *parent, CRBNode **slot) {
        PolicyOwnEntry *entry;
        size_t n_name = strlen(name) + 1;

        entry = malloc(sizeof(*entry) + n_name);
        if (!entry)
                return error_origin(-ENOMEM);
        entry->policy = policy;
        entry->decision.deny = deny;
        entry->decision.priority = priority;
        c_rbtree_add(policy, parent, slot, &entry->rb);
        memcpy((char*)entry->name, name, n_name);

        if (entryp)
                *entryp = entry;
        return 0;
}

static PolicyOwnEntry *policy_own_entry_free(PolicyOwnEntry *entry) {
        if (!entry)
                return NULL;

        c_rbtree_remove_init(entry->policy, &entry->rb);

        free(entry);

        return NULL;
}

void policy_own_init(PolicyOwn *policy) {
        *policy = (PolicyOwn)POLICY_OWN_INIT;
}

void policy_own_deinit(PolicyOwn *policy) {
        PolicyOwnEntry *entry, *safe;

        c_rbtree_for_each_entry_unlink(entry, safe, &policy->names, rb)
                policy_own_entry_free(entry);

        c_rbtree_for_each_entry_unlink(entry, safe, &policy->prefixes, rb)
                policy_own_entry_free(entry);

        policy_own_init(policy);
}

bool policy_own_is_empty(PolicyOwn *policy) {
        return c_rbtree_is_empty(&policy->names) &&
               c_rbtree_is_empty(&policy->prefixes) &&
               policy_decision_is_default(&policy->wildcard);
}

static int policy_own_instantiate(PolicyOwn *target, PolicyOwn *source) {
        PolicyOwnEntry *entry;
        int r;

        r = policy_own_set_wildcard(target, source->wildcard.deny, source->wildcard.priority);
        if (r)
                return error_trace(r);

        c_rbtree_for_each_entry(entry, &source->names, rb) {
                r = policy_own_add_name(target, entry->name, entry->decision.deny, entry->decision.priority);
                if (r)
                        return error_trace(r);
        }

        c_rbtree_for_each_entry(entry, &source->prefixes, rb) {
                r = policy_own_add_prefix(target, entry->name, entry->decision.deny, entry->decision.priority);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

int policy_own_set_wildcard(PolicyOwn *policy, bool deny, uint64_t priority) {
        if (policy->wildcard.priority > priority)
                return 0;

        policy->wildcard.deny = deny;
        policy->wildcard.priority = priority;

        return 0;
}

struct stringn {
        const char *string;
        size_t n_string;
};

static int policy_own_entry_compare(CRBTree *tree, void *k, CRBNode *rb) {
        const char *string = ((struct stringn *)k)->string;
        size_t n_string = ((struct stringn *)k)->n_string;
        PolicyOwnEntry *entry = c_container_of(rb, PolicyOwnEntry, rb);
        int r;

        r = strncmp(string, entry->name, n_string);
        if (r)
                return r;

        if (entry->name[n_string])
                return -1;

        return 0;
}

static int policy_own_add_entry(CRBTree *policy, const char *name, bool deny, uint64_t priority) {
        CRBNode *parent, **slot;
        struct stringn stringn = {
                .string = name,
                .n_string = strlen(name),
        };
        int r;

        slot = c_rbtree_find_slot(policy, policy_own_entry_compare, &stringn, &parent);
        if (!slot) {
                PolicyOwnEntry *entry = c_container_of(parent, PolicyOwnEntry, rb);

                if (entry->decision.priority < priority) {
                        entry->decision.deny = deny;
                        entry->decision.priority = priority;
                }
        } else {
                r = policy_own_entry_new(NULL, policy, name, deny, priority, parent, slot);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

int policy_own_add_prefix(PolicyOwn *policy, const char *prefix, bool deny, uint64_t priority) {
        if (!strcmp(prefix, ""))
                return error_trace(policy_own_set_wildcard(policy, deny, priority));
        else
                return error_trace(policy_own_add_entry(&policy->prefixes, prefix, deny, priority));
}

int policy_own_add_name(PolicyOwn *policy, const char *name, bool deny, uint64_t priority) {
        return error_trace(policy_own_add_entry(&policy->names, name, deny, priority));
}

static void policy_own_update_decision(CRBTree *policy, struct stringn *stringn, PolicyDecision *decision) {
        PolicyOwnEntry *entry;

        entry = c_rbtree_find_entry(policy, policy_own_entry_compare, stringn, PolicyOwnEntry, rb);
        if (!entry)
                return;

        if (entry->decision.priority < decision->priority)
                return;

        *decision = entry->decision;
        return;
}

static void policy_own_check_allowed(PolicyOwn *policy, const char *name, PolicyDecision *decision) {
        struct stringn stringn = {
                .string = name,
                .n_string = strlen(name),
        };

        if (decision->priority < policy->wildcard.priority)
                *decision = policy->wildcard;

        policy_own_update_decision(&policy->names, &stringn, decision);

        if (!c_rbtree_is_empty(&policy->prefixes)) {
                const char *dot = name;

                do {
                        dot = strchrnul(dot + 1, '.');
                        stringn.n_string = dot - name;
                        policy_own_update_decision(&policy->prefixes, &stringn, decision);
                } while (*dot);
        }
}

static int policy_connect_entry_new(PolicyConnectEntry **entryp, CRBTree *policy,
                                       uid_t uid, bool deny, uint64_t priority,
                                       CRBNode *parent, CRBNode **slot) {
        PolicyConnectEntry *entry;

        entry = calloc(1, sizeof(*entry));
        if (!entry)
                return error_origin(-ENOMEM);
        entry->policy = policy;
        entry->decision.deny = deny;
        entry->decision.priority = priority;
        entry->uid = uid;
        c_rbtree_add(policy, parent, slot, &entry->rb);

        if (entryp)
                *entryp = entry;
        return 0;
}

static PolicyConnectEntry *policy_connect_entry_free(PolicyConnectEntry *entry) {
        if (!entry)
                return NULL;

        c_rbtree_remove_init(entry->policy, &entry->rb);

        free(entry);

        return NULL;
}

void policy_connect_init(PolicyConnect *policy) {
        *policy = (PolicyConnect)POLICY_CONNECT_INIT;
}

void policy_connect_deinit(PolicyConnect *policy) {
        PolicyConnectEntry *entry, *safe;

        c_rbtree_for_each_entry_unlink(entry, safe, &policy->uid_tree, rb)
                policy_connect_entry_free(entry);

        c_rbtree_for_each_entry_unlink(entry, safe, &policy->gid_tree, rb)
                policy_connect_entry_free(entry);

        policy_connect_init(policy);
}

bool policy_connect_is_empty(PolicyConnect *policy) {
        return c_rbtree_is_empty(&policy->uid_tree) &&
               c_rbtree_is_empty(&policy->gid_tree) &&
               policy_decision_is_default(&policy->wildcard);
}

int policy_connect_set_wildcard(PolicyConnect *policy, bool deny, uint64_t priority) {
        if (policy->wildcard.priority > priority)
                return 0;

        policy->wildcard.deny = deny;
        policy->wildcard.priority = priority;

        return 0;
}

static int policy_connect_entry_compare(CRBTree *tree, void *k, CRBNode *rb) {
        uid_t uid = *(uid_t *)k;
        PolicyConnectEntry *entry = c_container_of(rb, PolicyConnectEntry, rb);

        if (uid < entry->uid)
                return -1;
        else if (uid > entry->uid)
                return 1;
        else
                return 0;
}

static int policy_connect_add_entry(CRBTree *policy, uid_t uid, bool deny, uint64_t priority) {
        CRBNode *parent, **slot;
        int r;

        slot = c_rbtree_find_slot(policy, policy_connect_entry_compare, &uid, &parent);
        if (!slot) {
                PolicyConnectEntry *entry = c_container_of(parent, PolicyConnectEntry, rb);

                if (entry->decision.priority < priority) {
                        entry->decision.deny = deny;
                        entry->decision.priority = priority;
                }
        } else {
                r = policy_connect_entry_new(NULL, policy, uid, deny, priority, parent, slot);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

int policy_connect_add_uid(PolicyConnect *policy, uid_t uid, bool deny, uint64_t priority) {
        return error_trace(policy_connect_add_entry(&policy->uid_tree, uid, deny, priority));
}

int policy_connect_add_gid(PolicyConnect *policy, gid_t gid, bool deny, uint64_t priority) {
        return error_trace(policy_connect_add_entry(&policy->gid_tree, (uid_t)gid, deny, priority));
}

static void policy_connect_update_decision(CRBTree *policy, uid_t uid, PolicyDecision *decision) {
        PolicyConnectEntry *entry;

        entry = c_rbtree_find_entry(policy, policy_connect_entry_compare, &uid, PolicyConnectEntry, rb);
        if (!entry)
                return;

        if (entry->decision.priority < decision->priority)
                return;

        *decision = entry->decision;
        return;
}

static int policy_connect_check_allowed(PolicyConnect *policy, uid_t uid, gid_t *gids, size_t n_gids) {
        PolicyDecision decision = policy->wildcard;

        policy_connect_update_decision(&policy->uid_tree, uid, &decision);

        for (size_t i = 0; i < n_gids; i++)
                policy_connect_update_decision(&policy->gid_tree, (uid_t)gids[i], &decision);

        return decision.deny ? POLICY_E_ACCESS_DENIED : 0;
}

int policy_connect_instantiate(PolicyConnect *target, PolicyConnect *source) {
        PolicyConnectEntry *entry;
        int r;

        r = policy_connect_set_wildcard(target, source->wildcard.deny, source->wildcard.priority);
        if (r)
                return error_trace(r);

        c_rbtree_for_each_entry(entry, &source->uid_tree, rb) {
                r = policy_connect_add_uid(target, entry->uid, entry->decision.deny, entry->decision.priority);
                if (r)
                        return error_trace(r);
        }

        c_rbtree_for_each_entry(entry, &source->gid_tree, rb) {
                r = policy_connect_add_gid(target, entry->uid, entry->decision.deny, entry->decision.priority);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

static int policy_xmit_entry_new(PolicyXmitEntry **entryp, CList *policy,
                                         const char *interface, const char *member, const char *path, int type,
                                         bool deny, uint64_t priority) {
        PolicyXmitEntry *entry;
        char *buffer;
        size_t n_interface = interface ? strlen(interface) + 1 : 0,
               n_member = member ? strlen(member) + 1 : 0,
               n_path = path ? strlen(path) + 1 : 0;

        entry = malloc(sizeof(*entry) + n_interface + n_member + n_path);
        if (!entry)
                return error_origin(-ENOMEM);
        buffer = (char*)(entry + 1);

        if (interface) {
                entry->interface = buffer;
                buffer = stpcpy(buffer, interface) + 1;
        } else {
                entry->interface = NULL;
        }

        if (member) {
                entry->member = buffer;
                buffer = stpcpy(buffer, member) + 1;
        } else {
                entry->member = NULL;
        }

        if (path) {
                entry->path = buffer;
                buffer = stpcpy(buffer, path) + 1;
        } else {
                entry->path = NULL;
        }

        entry->type = type;

        entry->decision.deny = deny;
        entry->decision.priority = priority;

        c_list_link_tail(policy, &entry->policy_link);

        if (entryp)
                *entryp = entry;

        return 0;
}

static PolicyXmitEntry *policy_xmit_entry_free(PolicyXmitEntry *entry) {
        if (!entry)
                return NULL;

        c_list_unlink_init(&entry->policy_link);

        free(entry);

        return NULL;
}

static int policy_xmit_by_name_new(PolicyXmitByName **by_namep, CRBTree *policy,
                                           const char *name,
                                           CRBNode *parent, CRBNode **slot) {
        PolicyXmitByName *by_name;
        size_t n_name = strlen(name) + 1;

        by_name = malloc(sizeof(*by_name) + n_name);
        if (!by_name)
                return error_origin(-ENOMEM);
        memcpy((char*)by_name->name, name, n_name);
        by_name->policy = policy;
        by_name->entry_list = (CList)C_LIST_INIT(by_name->entry_list);
        c_rbtree_add(policy, parent, slot, &by_name->policy_node);

        if (by_namep)
                *by_namep = by_name;

        return 0;
}

static PolicyXmitByName *policy_xmit_by_name_free(PolicyXmitByName *by_name) {
        if (!by_name)
                return NULL;

        while (!c_list_is_empty(&by_name->entry_list))
                policy_xmit_entry_free(c_list_first_entry(&by_name->entry_list, PolicyXmitEntry, policy_link));

        c_rbtree_remove_init(by_name->policy, &by_name->policy_node);

        free(by_name);

        return NULL;
}

void policy_xmit_init(PolicyXmit *policy) {
        *policy = (PolicyXmit)POLICY_XMIT_INIT(*policy);
}

void policy_xmit_deinit(PolicyXmit *policy) {
        PolicyXmitByName *by_name, *safe;

        c_rbtree_for_each_entry_unlink(by_name, safe, &policy->policy_by_name_tree, policy_node)
                policy_xmit_by_name_free(by_name);

        while (!c_list_is_empty(&policy->wildcard_entry_list))
                policy_xmit_entry_free(c_list_first_entry(&policy->wildcard_entry_list, PolicyXmitEntry, policy_link));

        policy_xmit_init(policy);
}

bool policy_xmit_is_empty(PolicyXmit *policy) {
        return c_rbtree_is_empty(&policy->policy_by_name_tree) &&
               c_list_is_empty(&policy->wildcard_entry_list);
}

static int policy_xmit_by_name_instantiate(PolicyXmit *target, const char *name, CList *source) {
        PolicyXmitEntry *entry;
        int r;

        c_list_for_each_entry(entry, source, policy_link) {
                r = policy_xmit_add_entry(target,
                                                  name, entry->interface, entry->member, entry->path, entry->type,
                                                  entry->decision.deny, entry->decision.priority);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

static int policy_xmit_instantiate(PolicyXmit *target, PolicyXmit *source) {
        PolicyXmitByName *policy;
        int r;

        r = policy_xmit_by_name_instantiate(target, NULL, &source->wildcard_entry_list);
        if (r)
                return error_trace(r);

        c_rbtree_for_each_entry(policy, &source->policy_by_name_tree, policy_node) {
                r = policy_xmit_by_name_instantiate(target, policy->name, &policy->entry_list);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

static int policy_xmit_by_name_compare(CRBTree *tree, void *k, CRBNode *rb) {
        const char *name = k;
        PolicyXmitByName *by_name = c_container_of(rb, PolicyXmitByName, policy_node);

        return strcmp(name, by_name->name);
}

int policy_xmit_add_entry(PolicyXmit *policy,
                                  const char *name, const char *interface, const char *member, const char *path, int type,
                                  bool deny, uint64_t priority) {
        CRBNode *parent, **slot;
        CList *policy_list;
        int r;

        if (type == DBUS_MESSAGE_TYPE_METHOD_RETURN ||
            type == DBUS_MESSAGE_TYPE_ERROR)
                /* replies are not subject to policy, this differs from the dbus daemon */
                return 0;

        if (name) {
                PolicyXmitByName *by_name;

                slot = c_rbtree_find_slot(&policy->policy_by_name_tree, policy_xmit_by_name_compare, name, &parent);
                if (!slot) {
                        by_name = c_container_of(parent, PolicyXmitByName, policy_node);
                } else {
                        r = policy_xmit_by_name_new(&by_name, &policy->policy_by_name_tree, name, parent, slot);
                        if (r)
                                return error_trace(r);
                }

                policy_list = &by_name->entry_list;
        } else {
                policy_list = &policy->wildcard_entry_list;
        }

        r = policy_xmit_entry_new(NULL, policy_list, interface, member, path, type, deny, priority);
        if (r)
                return error_trace(r);

        return 0;
}

static void policy_xmit_update_decision(CList *policy,
                                                const char *interface, const char *member, const char *path, int type,
                                                PolicyDecision *decision) {
        PolicyXmitEntry *entry;

        c_list_for_each_entry(entry, policy, policy_link) {
                if (entry->decision.priority < decision->priority)
                        continue;

                if (entry->interface)
                        if (!interface || strcmp(entry->interface, interface))
                                continue;

                if (entry->member)
                        if (!member || strcmp(entry->member, member))
                                continue;

                if (entry->path)
                        if (!path || strcmp(entry->path, path))
                                continue;

                if (entry->type)
                        if (entry->type != type)
                                continue;

                *decision = entry->decision;
        }
}

static void policy_xmit_update_decision_by_name(CRBTree *policy, const char *name,
                                                        const char *interface, const char *member, const char *path, int type,
                                                        PolicyDecision *decision) {
        PolicyXmitByName *by_name;

        by_name = c_rbtree_find_entry(policy, policy_xmit_by_name_compare, name, PolicyXmitByName, policy_node);
        if (!by_name)
                return;

        policy_xmit_update_decision(&by_name->entry_list, interface, member, path, type, decision);
}

static void policy_xmit_check_allowed(PolicyXmit *policy, NameSet *subject,
                                              const char *interface, const char *member, const char *path, int type,
                                              PolicyDecision *decision) {
        policy_xmit_update_decision(&policy->wildcard_entry_list, interface, member, path, type, decision);

        if (!c_rbtree_is_empty(&policy->policy_by_name_tree)) {
                if (subject) {
                        NameOwner *owner;
                        NameOwnership *ownership;
                        NameSnapshot *snapshot;

                        switch (subject->type) {
                        case NAME_SET_TYPE_OWNER:
                                owner = subject->owner;

                                c_rbtree_for_each_entry(ownership, &owner->ownership_tree, owner_node) {
                                        if (!name_ownership_is_primary(ownership))
                                                continue;

                                        policy_xmit_update_decision_by_name(&policy->policy_by_name_tree, ownership->name->name,
                                                                                    interface, member, path, type,
                                                                                    decision);
                                }
                                break;
                        case NAME_SET_TYPE_SNAPSHOT:
                                snapshot = subject->snapshot;

                                for (size_t i = 0; i < snapshot->n_names; ++i)
                                        policy_xmit_update_decision_by_name(&policy->policy_by_name_tree, snapshot->names[i]->name,
                                                                                    interface, member, path, type,
                                                                                    decision);
                                break;
                        default:
                                assert(0);
                        }
                } else {
                        /* the subject is the driver */
                        policy_xmit_update_decision_by_name(&policy->policy_by_name_tree, "org.freedesktop.DBus",
                                                                    interface, member, path, type,
                                                                    decision);
                }
        }
}

void policy_init(Policy *policy) {
        *policy = (Policy)POLICY_INIT(*policy);
}

void policy_deinit(Policy *policy) {
        assert(policy->uid == (uid_t)-1);

        policy_xmit_deinit(&policy->policy_receive);
        policy_xmit_deinit(&policy->policy_send);
        policy_own_deinit(&policy->policy_own);
}

bool policy_is_empty(Policy *policy) {
        return policy_own_is_empty(&policy->policy_own) &&
               policy_xmit_is_empty(&policy->policy_send) &&
               policy_xmit_is_empty(&policy->policy_receive);
}

static int policy_new(Policy **policyp, CRBTree *registry, uid_t uid, CRBNode *parent, CRBNode **slot) {
        Policy *policy;

        policy = calloc(1, sizeof(*policy));
        if (!policy)
                return error_origin(-ENOMEM);

        policy_init(policy);

        policy->uid = uid;

        if (registry)
                c_rbtree_add(registry, parent, slot, &policy->registry_node);

        if (policyp)
                *policyp = policy;
        return 0;
}

void policy_free(_Atomic unsigned long *n_refs, void *userdata) {
        Policy *policy = c_container_of(n_refs, Policy, n_refs);

        assert(!c_rbnode_is_linked(&policy->registry_node));
        policy->uid = (uid_t) -1;

        policy_deinit(policy);

        free(policy);
}

int policy_instantiate(Policy *target, Policy *source) {
        int r;

        r = policy_own_instantiate(&target->policy_own, &source->policy_own);
        if (r)
                return error_trace(r);

        r = policy_xmit_instantiate(&target->policy_send, &source->policy_send);
        if (r)
                return error_trace(r);

        r = policy_xmit_instantiate(&target->policy_receive, &source->policy_receive);
        if (r)
                return error_trace(r);

        return 0;
}

static int policy_compare(CRBTree *tree, void *k, CRBNode *rb) {
        uid_t uid = *(uid_t*)k;
        Policy *policy = c_container_of(rb, Policy, registry_node);

        if (uid < policy->uid)
                return -1;
        else if (uid > policy->uid)
                return 1;
        else
                return 0;
}

int peer_policy_instantiate(PeerPolicy *policy, PolicyRegistry *registry, uid_t uid, gid_t *gids, size_t n_gids) {
        Policy *source;
        int r;

        assert(!policy->uid_policy);
        assert(!policy->gid_policies);
        assert(!policy->n_gid_policies);

        r = policy_connect_check_allowed(&registry->policy_connect, uid, gids, n_gids);
        if (r)
                return error_trace(r);

        source = c_rbtree_find_entry(&registry->uid_policy_tree, policy_compare, &uid, Policy, registry_node);
        if (!source)
                source = registry->wildcard_uid_policy;
        policy->uid_policy = policy_ref(source);

        if (n_gids) {
                policy->gid_policies = malloc(n_gids * sizeof(*policy->gid_policies));
                if (!policy->gid_policies)
                        return error_origin(-ENOMEM);

                for (size_t i = 0; i < n_gids; ++i) {
                        source = c_rbtree_find_entry(&registry->gid_policy_tree, policy_compare, gids + i, Policy, registry_node);
                        if (source)
                                policy->gid_policies[policy->n_gid_policies++] = policy_ref(source);
                }
        }

        return 0;
}

int peer_policy_copy(PeerPolicy *target, PeerPolicy *source) {
        assert(!target->uid_policy);
        assert(!target->gid_policies);
        assert(!target->n_gid_policies);

        target->uid_policy = policy_ref(source->uid_policy);

        if (source->n_gid_policies) {
                target->gid_policies = malloc(source->n_gid_policies * sizeof(*target->gid_policies));
                if (!target->gid_policies)
                        return error_origin(-ENOMEM);

                for (size_t i = 0; i < source->n_gid_policies; ++i)
                        target->gid_policies[i] = policy_ref(source->gid_policies[i]);

                target->n_gid_policies = source->n_gid_policies;
        }

        return 0;
}

void peer_policy_deinit(PeerPolicy *policy) {
        policy->uid_policy = policy_unref(policy->uid_policy);
        for (size_t i = 0; i < policy->n_gid_policies; ++i)
                policy_unref(policy->gid_policies[i]);

        /* the gid policy array may be overallocated, so make sure to free even if it is empty */
        policy->gid_policies = c_free(policy->gid_policies);
        policy->n_gid_policies = 0;
}

int peer_policy_check_own(PeerPolicy *policy, const char *name) {
        PolicyDecision decision = {};

        policy_own_check_allowed(&policy->uid_policy->policy_own, name, &decision);

        for (size_t i = 0; i < policy->n_gid_policies; ++i)
                policy_own_check_allowed(&policy->gid_policies[i]->policy_own, name, &decision);

        return decision.deny ? POLICY_E_ACCESS_DENIED : 0;
}

int peer_policy_check_send(PeerPolicy *policy, NameSet *subject, const char *interface, const char *method, const char *path, int type) {
        PolicyDecision decision = {};

        policy_xmit_check_allowed(&policy->uid_policy->policy_send, subject, interface, method, path, type, &decision);

        for (size_t i = 0; i < policy->n_gid_policies; ++i)
                policy_xmit_check_allowed(&policy->gid_policies[i]->policy_send, subject, interface, method, path, type, &decision);

        return decision.deny ? POLICY_E_ACCESS_DENIED : 0;
}

int peer_policy_check_receive(PeerPolicy *policy, NameSet *subject, const char *interface, const char *method, const char *path, int type) {
        PolicyDecision decision = {};

        policy_xmit_check_allowed(&policy->uid_policy->policy_receive, subject, interface, method, path, type, &decision);

        for (size_t i = 0; i < policy->n_gid_policies; ++i)
                policy_xmit_check_allowed(&policy->gid_policies[i]->policy_receive, subject, interface, method, path, type, &decision);

        return decision.deny ? POLICY_E_ACCESS_DENIED : 0;
}

int policy_registry_init(PolicyRegistry *registry) {
        int r;

        *registry = (PolicyRegistry)POLICY_REGISTRY_NULL(*registry);

        r = policy_new(&registry->wildcard_uid_policy, NULL, (uid_t)-1, NULL, NULL);
        if (r)
                return error_trace(r);

        return 0;
}

void policy_registry_deinit(PolicyRegistry *registry) {
        Policy *policy, *safe;

        c_rbtree_for_each_entry_unlink(policy, safe, &registry->gid_policy_tree, registry_node)
                policy_unref(policy);
        c_rbtree_for_each_entry_unlink(policy, safe, &registry->uid_policy_tree, registry_node)
                policy_unref(policy);
        policy_unref(registry->wildcard_uid_policy);
        policy_connect_deinit(&registry->policy_connect);
}

int policy_registry_get_policy_by_uid(PolicyRegistry *registry, Policy **policyp, uid_t uid) {
        CRBNode *parent, **slot;
        int r;

        slot = c_rbtree_find_slot(&registry->uid_policy_tree, policy_compare, &uid, &parent);
        if (!slot) {
                *policyp = c_container_of(parent, Policy, registry_node);
                return 0;
        } else {
                r = policy_new(policyp, &registry->uid_policy_tree, uid, parent, slot);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

int policy_registry_get_policy_by_gid(PolicyRegistry *registry, Policy **policyp, gid_t gid) {
        CRBNode *parent, **slot;
        int r;

        slot = c_rbtree_find_slot(&registry->gid_policy_tree, policy_compare, &gid, &parent);
        if (!slot) {
                *policyp = c_container_of(parent, Policy, registry_node);
                return 0;
        } else {
                r = policy_new(policyp, &registry->gid_policy_tree, (uid_t)gid, parent, slot);
                if (r)
                        return error_trace(r);
        }

        return 0;
}
