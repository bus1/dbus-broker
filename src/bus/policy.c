/*
 * D-Bus Policy
 */

#include <c-macro.h>
#include <c-rbtree.h>
#include <expat.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include "bus/name.h"
#include "bus/policy.h"
#include "dbus/protocol.h"
#include "util/error.h"

bool policy_decision_is_default(PolicyDecision *decision) {
        return !decision->priority && !decision->deny;
}

/* ownership policy */
static int ownership_policy_entry_new(OwnershipPolicyEntry **entryp, CRBTree *policy,
                                      const char *name, bool deny, uint64_t priority,
                                      CRBNode *parent, CRBNode **slot) {
        OwnershipPolicyEntry *entry;
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

static OwnershipPolicyEntry *ownership_policy_entry_free(OwnershipPolicyEntry *entry) {
        if (!entry)
                return NULL;

        c_rbtree_remove_init(entry->policy, &entry->rb);

        free(entry);

        return NULL;
}

void ownership_policy_init(OwnershipPolicy *policy) {
        *policy = (OwnershipPolicy)OWNERSHIP_POLICY_INIT;
}

void ownership_policy_deinit(OwnershipPolicy *policy) {
        OwnershipPolicyEntry *entry, *safe;

        c_rbtree_for_each_entry_unlink(entry, safe, &policy->names, rb)
                ownership_policy_entry_free(entry);

        c_rbtree_for_each_entry_unlink(entry, safe, &policy->prefixes, rb)
                ownership_policy_entry_free(entry);

        ownership_policy_init(policy);
}

bool ownership_policy_is_empty(OwnershipPolicy *policy) {
        return c_rbtree_is_empty(&policy->names) &&
               c_rbtree_is_empty(&policy->prefixes) &&
               policy_decision_is_default(&policy->wildcard);
}

static int ownership_policy_instantiate(OwnershipPolicy *target, OwnershipPolicy *source) {
        OwnershipPolicyEntry *entry;
        int r;

        r = ownership_policy_set_wildcard(target, source->wildcard.deny, source->wildcard.priority);
        if (r)
                return error_trace(r);

        c_rbtree_for_each_entry(entry, &source->names, rb) {
                r = ownership_policy_add_name(target, entry->name, entry->decision.deny, entry->decision.priority);
                if (r)
                        return error_trace(r);
        }

        c_rbtree_for_each_entry(entry, &source->prefixes, rb) {
                r = ownership_policy_add_prefix(target, entry->name, entry->decision.deny, entry->decision.priority);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

int ownership_policy_set_wildcard(OwnershipPolicy *policy, bool deny, uint64_t priority) {
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

static int ownership_policy_entry_compare(CRBTree *tree, void *k, CRBNode *rb) {
        const char *string = ((struct stringn *)k)->string;
        size_t n_string = ((struct stringn *)k)->n_string;
        OwnershipPolicyEntry *entry = c_container_of(rb, OwnershipPolicyEntry, rb);
        int r;

        r = strncmp(string, entry->name, n_string);
        if (r)
                return r;

        if (entry->name[n_string])
                return -1;

        return 0;
}

static int ownership_policy_add_entry(CRBTree *policy, const char *name, bool deny, uint64_t priority) {
        CRBNode *parent, **slot;
        struct stringn stringn = {
                .string = name,
                .n_string = strlen(name),
        };
        int r;

        slot = c_rbtree_find_slot(policy, ownership_policy_entry_compare, &stringn, &parent);
        if (!slot) {
                OwnershipPolicyEntry *entry = c_container_of(parent, OwnershipPolicyEntry, rb);

                if (entry->decision.priority < priority) {
                        entry->decision.deny = deny;
                        entry->decision.priority = priority;
                }
        } else {
                r = ownership_policy_entry_new(NULL, policy, name, deny, priority, parent, slot);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

int ownership_policy_add_prefix(OwnershipPolicy *policy, const char *prefix, bool deny, uint64_t priority) {
        return error_trace(ownership_policy_add_entry(&policy->prefixes, prefix, deny, priority));
}

int ownership_policy_add_name(OwnershipPolicy *policy, const char *name, bool deny, uint64_t priority) {
        return error_trace(ownership_policy_add_entry(&policy->names, name, deny, priority));
}

static void ownership_policy_update_decision(CRBTree *policy, struct stringn *stringn, PolicyDecision *decision) {
        OwnershipPolicyEntry *entry;

        entry = c_rbtree_find_entry(policy, ownership_policy_entry_compare, stringn, OwnershipPolicyEntry, rb);
        if (!entry)
                return;

        if (entry->decision.priority < decision->priority)
                return;

        *decision = entry->decision;
        return;
}

static void ownership_policy_check_allowed(OwnershipPolicy *policy, const char *name, PolicyDecision *decision) {
        struct stringn stringn = {
                .string = name,
                .n_string = strlen(name),
        };

        if (decision->priority < policy->wildcard.priority)
                *decision = policy->wildcard;

        ownership_policy_update_decision(&policy->names, &stringn, decision);

        if (!c_rbtree_is_empty(&policy->prefixes)) {
                const char *dot = name;

                do {
                        dot = strchrnul(dot + 1, '.');
                        stringn.n_string = dot - name;
                        ownership_policy_update_decision(&policy->prefixes, &stringn, decision);
                } while (*dot);
        }
}

/* connection policy */
static int connection_policy_entry_new(ConnectionPolicyEntry **entryp, CRBTree *policy,
                                       uid_t uid, bool deny, uint64_t priority,
                                       CRBNode *parent, CRBNode **slot) {
        ConnectionPolicyEntry *entry;

        entry = calloc(1, sizeof(*entry));
        if (!entry)
                return error_origin(-ENOMEM);
        entry->policy = policy;
        entry->decision.deny = deny;
        entry->decision.priority = priority;
        c_rbtree_add(policy, parent, slot, &entry->rb);

        if (entryp)
                *entryp = entry;
        return 0;
}

static ConnectionPolicyEntry *connection_policy_entry_free(ConnectionPolicyEntry *entry) {
        if (!entry)
                return NULL;

        c_rbtree_remove_init(entry->policy, &entry->rb);

        free(entry);

        return NULL;
}

void connection_policy_init(ConnectionPolicy *policy) {
        *policy = (ConnectionPolicy)CONNECTION_POLICY_INIT;
}

void connection_policy_deinit(ConnectionPolicy *policy) {
        ConnectionPolicyEntry *entry, *safe;

        c_rbtree_for_each_entry_unlink(entry, safe, &policy->uid_tree, rb)
                connection_policy_entry_free(entry);

        c_rbtree_for_each_entry_unlink(entry, safe, &policy->gid_tree, rb)
                connection_policy_entry_free(entry);

        connection_policy_init(policy);
}

bool connection_policy_is_empty(ConnectionPolicy *policy) {
        return c_rbtree_is_empty(&policy->uid_tree) &&
               c_rbtree_is_empty(&policy->gid_tree) &&
               policy_decision_is_default(&policy->wildcard);
}

int connection_policy_set_wildcard(ConnectionPolicy *policy, bool deny, uint64_t priority) {
        if (policy->wildcard.priority > priority)
                return 0;

        policy->wildcard.deny = deny;
        policy->wildcard.priority = priority;

        return 0;
}

static int connection_policy_entry_compare(CRBTree *tree, void *k, CRBNode *rb) {
        uid_t uid = *(uid_t *)k;
        ConnectionPolicyEntry *entry = c_container_of(rb, ConnectionPolicyEntry, rb);

        if (uid < entry->uid)
                return -1;
        else if (uid > entry->uid)
                return 1;
        else
                return 0;
}

static int connection_policy_add_entry(CRBTree *policy, uid_t uid, bool deny, uint64_t priority) {
        CRBNode *parent, **slot;
        int r;

        slot = c_rbtree_find_slot(policy, connection_policy_entry_compare, &uid, &parent);
        if (!slot) {
                ConnectionPolicyEntry *entry = c_container_of(parent, ConnectionPolicyEntry, rb);

                if (entry->decision.priority < priority) {
                        entry->decision.deny = deny;
                        entry->decision.priority = priority;
                }
        } else {
                r = connection_policy_entry_new(NULL, policy, uid, deny, priority, parent, slot);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

int connection_policy_add_uid(ConnectionPolicy *policy, uid_t uid, bool deny, uint64_t priority) {
        return error_trace(connection_policy_add_entry(&policy->uid_tree, uid, deny, priority));
}

int connection_policy_add_gid(ConnectionPolicy *policy, gid_t gid, bool deny, uint64_t priority) {
        return error_trace(connection_policy_add_entry(&policy->gid_tree, (uid_t)gid, deny, priority));
}

static void connection_policy_update_decision(CRBTree *policy, uid_t uid, PolicyDecision *decision) {
        ConnectionPolicyEntry *entry;

        entry = c_rbtree_find_entry(policy, connection_policy_entry_compare, &uid, ConnectionPolicyEntry, rb);
        if (!entry)
                return;

        if (entry->decision.priority < decision->priority)
                return;

        *decision = entry->decision;
        return;
}

static int connection_policy_check_allowed(ConnectionPolicy *policy, uid_t uid, gid_t *gids, size_t n_gids) {
        PolicyDecision decision = policy->wildcard;

        connection_policy_update_decision(&policy->uid_tree, uid, &decision);

        for (size_t i = 0; i < n_gids; i++)
                connection_policy_update_decision(&policy->gid_tree, (uid_t)gids[i], &decision);

        return decision.deny ? POLICY_E_ACCESS_DENIED : 0;
}

int connection_policy_instantiate(ConnectionPolicy *target, ConnectionPolicy *source) {
        ConnectionPolicyEntry *entry;
        int r;

        r = connection_policy_set_wildcard(target, source->wildcard.deny, source->wildcard.priority);
        if (r)
                return error_trace(r);

        c_rbtree_for_each_entry(entry, &source->uid_tree, rb) {
                r = connection_policy_add_uid(target, entry->uid, entry->decision.deny, entry->decision.priority);
                if (r)
                        return error_trace(r);
        }

        c_rbtree_for_each_entry(entry, &source->gid_tree, rb) {
                r = connection_policy_add_gid(target, entry->uid, entry->decision.deny, entry->decision.priority);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

/* transmission policy */
static int transmission_policy_entry_new(TransmissionPolicyEntry **entryp, CList *policy,
                                         const char *interface, const char *member, const char *path, int type,
                                         bool deny, uint64_t priority) {
        TransmissionPolicyEntry *entry;
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

static TransmissionPolicyEntry *transmission_policy_entry_free(TransmissionPolicyEntry *entry) {
        if (!entry)
                return NULL;

        c_list_unlink_init(&entry->policy_link);

        free(entry);

        return NULL;
}

static int transmission_policy_by_name_new(TransmissionPolicyByName **by_namep, CRBTree *policy,
                                           const char *name,
                                           CRBNode *parent, CRBNode **slot) {
        TransmissionPolicyByName *by_name;
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

static TransmissionPolicyByName *transmission_policy_by_name_free(TransmissionPolicyByName *by_name) {
        if (!by_name)
                return NULL;

        while (!c_list_is_empty(&by_name->entry_list))
                transmission_policy_entry_free(c_list_first_entry(&by_name->entry_list, TransmissionPolicyEntry, policy_link));

        c_rbtree_remove_init(by_name->policy, &by_name->policy_node);

        free(by_name);

        return NULL;
}

void transmission_policy_init(TransmissionPolicy *policy) {
        *policy = (TransmissionPolicy)TRANSMISSION_POLICY_INIT(*policy);
}

void transmission_policy_deinit(TransmissionPolicy *policy) {
        TransmissionPolicyByName *by_name, *safe;

        c_rbtree_for_each_entry_unlink(by_name, safe, &policy->policy_by_name_tree, policy_node)
                transmission_policy_by_name_free(by_name);

        while (!c_list_is_empty(&policy->wildcard_entry_list))
                transmission_policy_entry_free(c_list_first_entry(&policy->wildcard_entry_list, TransmissionPolicyEntry, policy_link));

        transmission_policy_init(policy);
}

bool transmission_policy_is_empty(TransmissionPolicy *policy) {
        return c_rbtree_is_empty(&policy->policy_by_name_tree) &&
               c_list_is_empty(&policy->wildcard_entry_list);
}

static int transmission_policy_by_name_instantiate(TransmissionPolicy *target, const char *name, CList *source) {
        TransmissionPolicyEntry *entry;
        int r;

        c_list_for_each_entry(entry, source, policy_link) {
                r = transmission_policy_add_entry(target,
                                                  name, entry->interface, entry->member, entry->path, entry->type,
                                                  entry->decision.deny, entry->decision.priority);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

static int transmission_policy_instantiate(TransmissionPolicy *target, TransmissionPolicy *source) {
        TransmissionPolicyByName *policy;
        int r;

        r = transmission_policy_by_name_instantiate(target, NULL, &source->wildcard_entry_list);
        if (r)
                return error_trace(r);

        c_rbtree_for_each_entry(policy, &source->policy_by_name_tree, policy_node) {
                r = transmission_policy_by_name_instantiate(target, policy->name, &policy->entry_list);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

static int transmission_policy_by_name_compare(CRBTree *tree, void *k, CRBNode *rb) {
        const char *name = k;
        TransmissionPolicyByName *by_name = c_container_of(rb, TransmissionPolicyByName, policy_node);

        return strcmp(name, by_name->name);
}

int transmission_policy_add_entry(TransmissionPolicy *policy,
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
                TransmissionPolicyByName *by_name;

                slot = c_rbtree_find_slot(&policy->policy_by_name_tree, transmission_policy_by_name_compare, name, &parent);
                if (!slot) {
                        by_name = c_container_of(parent, TransmissionPolicyByName, policy_node);
                } else {
                        r = transmission_policy_by_name_new(&by_name, &policy->policy_by_name_tree, name, parent, slot);
                        if (r)
                                return error_trace(r);
                }

                policy_list = &by_name->entry_list;
        } else {
                policy_list = &policy->wildcard_entry_list;
        }

        r = transmission_policy_entry_new(NULL, policy_list, interface, member, path, type, deny, priority);
        if (r)
                return error_trace(r);

        return 0;
}

static void transmission_policy_update_decision(CList *policy,
                                                const char *interface, const char *member, const char *path, int type,
                                                PolicyDecision *decision) {
        TransmissionPolicyEntry *entry;

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

static void transmission_policy_update_decision_by_name(CRBTree *policy, const char *name,
                                                        const char *interface, const char *member, const char *path, int type,
                                                        PolicyDecision *decision) {
        TransmissionPolicyByName *by_name;

        by_name = c_rbtree_find_entry(policy, transmission_policy_by_name_compare, name, TransmissionPolicyByName, policy_node);
        if (!by_name)
                return;

        transmission_policy_update_decision(&by_name->entry_list, interface, member, path, type, decision);
}

static void transmission_policy_check_allowed(TransmissionPolicy *policy, NameSet *subject,
                                              const char *interface, const char *member, const char *path, int type,
                                              PolicyDecision *decision) {
        transmission_policy_update_decision(&policy->wildcard_entry_list, interface, member, path, type, decision);

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

                                        transmission_policy_update_decision_by_name(&policy->policy_by_name_tree, ownership->name->name,
                                                                                    interface, member, path, type,
                                                                                    decision);
                                }
                                break;
                        case NAME_SET_TYPE_SNAPSHOT:
                                snapshot = subject->snapshot;

                                for (size_t i = 0; i < snapshot->n_names; ++i)
                                        transmission_policy_update_decision_by_name(&policy->policy_by_name_tree, snapshot->names[i]->name,
                                                                                    interface, member, path, type,
                                                                                    decision);
                                break;
                        default:
                                assert(0);
                        }
                } else {
                        /* the subject is the driver */
                        transmission_policy_update_decision_by_name(&policy->policy_by_name_tree, "org.freedesktop.DBus",
                                                                    interface, member, path, type,
                                                                    decision);
                }
        }
}

/* policy */
void policy_init(Policy *policy) {
        *policy = (Policy)POLICY_INIT(*policy);
}

void policy_deinit(Policy *policy) {
        assert(policy->uid == (uid_t)-1);

        transmission_policy_deinit(&policy->receive_policy);
        transmission_policy_deinit(&policy->send_policy);
        ownership_policy_deinit(&policy->ownership_policy);
}

bool policy_is_empty(Policy *policy) {
        return ownership_policy_is_empty(&policy->ownership_policy) &&
               transmission_policy_is_empty(&policy->send_policy) &&
               transmission_policy_is_empty(&policy->receive_policy);
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

        r = ownership_policy_instantiate(&target->ownership_policy, &source->ownership_policy);
        if (r)
                return error_trace(r);

        r = transmission_policy_instantiate(&target->send_policy, &source->send_policy);
        if (r)
                return error_trace(r);

        r = transmission_policy_instantiate(&target->receive_policy, &source->receive_policy);
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

/* peer policy */
int peer_policy_instantiate(PeerPolicy *policy, PolicyRegistry *registry, uid_t uid, gid_t *gids, size_t n_gids) {
        Policy *source;
        int r;

        assert(!policy->uid_policy);
        assert(!policy->gid_policies);
        assert(!policy->n_gid_policies);

        r = connection_policy_check_allowed(&registry->connection_policy, uid, gids, n_gids);
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

        ownership_policy_check_allowed(&policy->uid_policy->ownership_policy, name, &decision);

        for (size_t i = 0; policy->n_gid_policies; ++i)
                ownership_policy_check_allowed(&policy->gid_policies[i]->ownership_policy, name, &decision);

        return decision.deny ? POLICY_E_ACCESS_DENIED : 0;
}

int peer_policy_check_send(PeerPolicy *policy, NameSet *subject, const char *interface, const char *method, const char *path, int type) {
        PolicyDecision decision = {};

        transmission_policy_check_allowed(&policy->uid_policy->send_policy, subject, interface, method, path, type, &decision);

        for (size_t i = 0; policy->n_gid_policies; ++i)
                transmission_policy_check_allowed(&policy->gid_policies[i]->send_policy, subject, interface, method, path, type, &decision);

        return decision.deny ? POLICY_E_ACCESS_DENIED : 0;
}

int peer_policy_check_receive(PeerPolicy *policy, NameSet *subject, const char *interface, const char *method, const char *path, int type) {
        PolicyDecision decision = {};

        transmission_policy_check_allowed(&policy->uid_policy->receive_policy, subject, interface, method, path, type, &decision);

        for (size_t i = 0; policy->n_gid_policies; ++i)
                transmission_policy_check_allowed(&policy->gid_policies[i]->receive_policy, subject, interface, method, path, type, &decision);

        return decision.deny ? POLICY_E_ACCESS_DENIED : 0;
}

/* policy registry */
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
        connection_policy_deinit(&registry->connection_policy);
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

bool policy_registry_needs_groups(PolicyRegistry *registry) {
        return !c_rbtree_is_empty(&registry->connection_policy.gid_tree) ||
               !c_rbtree_is_empty(&registry->gid_policy_tree);
}
