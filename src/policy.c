/*
 * D-Bus Policy
 */

#include <c-macro.h>
#include <c-rbtree.h>
#include <expat.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include "dbus/protocol.h"
#include "name.h"
#include "peer.h"
#include "policy.h"
#include "util/error.h"

#define POLICY_PRIORITY_INCREMENT       (((uint64_t)-1) / 5)
#define POLICY_PRIORITY_BASE_DEFAULT    (POLICY_PRIORITY_INCREMENT * 0)
#define POLICY_PRIORITY_BASE_USER       (POLICY_PRIORITY_INCREMENT * 1)
#define POLICY_PRIORITY_BASE_GROUP      (POLICY_PRIORITY_INCREMENT * 2)
#define POLICY_PRIORITY_BASE_CONSOLE    (POLICY_PRIORITY_INCREMENT * 3)
#define POLICY_PRIORITY_BASE_MANDATORY  (POLICY_PRIORITY_INCREMENT * 4)

typedef struct PolicyParser PolicyParser;

struct PolicyParser {
        PolicyRegistry *registry;
        PolicyParser *parent;
        XML_Parser parser;
        const char *filename;
        bool busconfig;
        bool includedir;
        char characterdata[PATH_MAX + 1];
        size_t n_characterdata;
        size_t level;

        Policy *policy;
        uint64_t priority_base;
        uint64_t priority;
};

#define POLICY_PARSER_NULL {                    \
                .priority_base = (uint64_t)-1,  \
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
        *policy = (OwnershipPolicy){};
}

void ownership_policy_deinit(OwnershipPolicy *policy) {
        OwnershipPolicyEntry *entry, *safe;

        c_rbtree_for_each_entry_unlink(entry, safe, &policy->names, rb)
                ownership_policy_entry_free(entry);

        c_rbtree_for_each_entry_unlink(entry, safe, &policy->prefixes, rb)
                ownership_policy_entry_free(entry);

        ownership_policy_init(policy);
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

int ownership_policy_add_entry(CRBTree *policy, const char *name, bool deny, uint64_t priority) {
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

int ownership_policy_check_allowed(OwnershipPolicy *policy, const char *name) {
        PolicyDecision decision = policy->wildcard;
        struct stringn stringn = {
                .string = name,
                .n_string = strlen(name),
        };

        ownership_policy_update_decision(&policy->names, &stringn, &decision);

        if (!c_rbtree_is_empty(&policy->prefixes)) {
                const char *dot = name;

                do {
                        dot = strchrnul(dot + 1, '.');
                        stringn.n_string = dot - name;
                        ownership_policy_update_decision(&policy->prefixes, &stringn, &decision);
                } while (*dot);
        }

        return decision.deny ? POLICY_E_ACCESS_DENIED : 0;
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
        *policy = (ConnectionPolicy){};
}

void connection_policy_deinit(ConnectionPolicy *policy) {
        ConnectionPolicyEntry *entry, *safe;

        c_rbtree_for_each_entry_unlink(entry, safe, &policy->uid_tree, rb)
                connection_policy_entry_free(entry);

        c_rbtree_for_each_entry_unlink(entry, safe, &policy->gid_tree, rb)
                connection_policy_entry_free(entry);

        connection_policy_init(policy);
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

int connection_policy_add_entry(CRBTree *policy, uid_t uid, bool deny, uint64_t priority) {
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

int connection_policy_check_allowed(ConnectionPolicy *policy, uid_t uid, gid_t *gids, size_t n_gids) {
        PolicyDecision decision = policy->wildcard;

        connection_policy_update_decision(&policy->uid_tree, uid, &decision);

        for (size_t i = 0; i < n_gids; i++)
                connection_policy_update_decision(&policy->gid_tree, (uid_t)gids[i], &decision);

        return decision.deny ? POLICY_E_ACCESS_DENIED : 0;
}

/* transmission policy */
static int transmission_policy_entry_new(TransmissionPolicyEntry **entryp, CList *policy,
                                         const char *interface, const char *member, const char *error, const char *path, int type,
                                         bool deny, uint64_t priority) {
        TransmissionPolicyEntry *entry;
        char *buffer;
        size_t n_interface = interface ? strlen(interface) + 1 : 0,
               n_member = member ? strlen(member) + 1 : 0,
               n_error = error ? strlen(error) + 1 : 0,
               n_path = path ? strlen(path) + 1 : 0;

        entry = malloc(sizeof(*entry) + n_interface + n_member + n_error + n_path);
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

        if (error) {
                entry->error = buffer;
                buffer = stpcpy(buffer, error) + 1;
        } else {
                entry->error = NULL;
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
        policy->policy_by_name_tree = (CRBTree){};
        policy->wildcard_entry_list = (CList)C_LIST_INIT(policy->wildcard_entry_list);
}

void transmission_policy_deinit(TransmissionPolicy *policy) {
        TransmissionPolicyByName *by_name, *safe;

        c_rbtree_for_each_entry_unlink(by_name, safe, &policy->policy_by_name_tree, policy_node)
                transmission_policy_by_name_free(by_name);

        while (!c_list_is_empty(&policy->wildcard_entry_list))
                transmission_policy_entry_free(c_list_first_entry(&policy->wildcard_entry_list, TransmissionPolicyEntry, policy_link));

        transmission_policy_init(policy);
}

static int transmission_policy_by_name_compare(CRBTree *tree, void *k, CRBNode *rb) {
        const char *name = k;
        TransmissionPolicyByName *by_name = c_container_of(rb, TransmissionPolicyByName, policy_node);

        return strcmp(name, by_name->name);
}

int transmission_policy_add_entry(TransmissionPolicy *policy,
                                  const char *name, const char *interface, const char *member, const char *error, const char *path, int type,
                                  bool deny, uint64_t priority) {
        CRBNode *parent, **slot;
        CList *policy_list;
        int r;

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

        r = transmission_policy_entry_new(NULL, policy_list, interface, member, error, path, type, deny, priority);
        if (r)
                return error_trace(r);

        return 0;
}

static void transmission_policy_update_decision(CList *policy,
                                                const char *interface, const char *member, const char *error, const char *path, int type,
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

                if (entry->error)
                        if (!error || strcmp(entry->error, error))
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
                                                        const char *interface, const char *member, const char *error, const char *path, int type,
                                                        PolicyDecision *decision) {
        TransmissionPolicyByName *by_name;

        by_name = c_rbtree_find_entry(policy, transmission_policy_by_name_compare, name, TransmissionPolicyByName, policy_node);
        if (!by_name)
                return;

        transmission_policy_update_decision(&by_name->entry_list, interface, member, error, path, type, decision);
}

int transmission_policy_check_allowed(TransmissionPolicy *policy, Peer *subject,
                                      const char *interface, const char *member, const char *error, const char *path, int type) {
        PolicyDecision decision = {};

        if (subject) {
                NameOwnership *ownership;

                c_rbtree_for_each_entry(ownership, &subject->owned_names.ownership_tree, owner_node) {
                        if (!name_ownership_is_primary(ownership))
                                continue;

                        transmission_policy_update_decision_by_name(&policy->policy_by_name_tree, ownership->name->name,
                                                                    interface, member, error, path, type,
                                                                    &decision);
                }
        } else {
                /* the subject is the driver */
                transmission_policy_update_decision_by_name(&policy->policy_by_name_tree, "org.freedesktop.DBus",
                                                            interface, member, error, path, type,
                                                            &decision);
        }

        transmission_policy_update_decision(&policy->wildcard_entry_list, interface, member, error, path, type, &decision);

        return decision.deny ? POLICY_E_ACCESS_DENIED : 0;
}

/* policy */
void policy_init(Policy *policy) {
        ownership_policy_init(&policy->ownership_policy);
        transmission_policy_init(&policy->send_policy);
        transmission_policy_init(&policy->receive_policy);
        policy->registry = NULL;
        c_rbnode_init(&policy->registry_node);
        policy->uid = (uid_t)-1;
}

void policy_deinit(Policy *policy) {
        assert(!policy->registry);
        assert(!c_rbnode_is_linked(&policy->registry_node));
        assert(policy->uid == (uid_t)-1);

        transmission_policy_deinit(&policy->receive_policy);
        transmission_policy_deinit(&policy->send_policy);
        ownership_policy_deinit(&policy->ownership_policy);
}

static int policy_new(Policy **policyp, CRBTree *registry, uid_t uid, CRBNode *parent, CRBNode **slot) {
        Policy *policy;

        policy = calloc(1, sizeof(*policy));
        if (!policy)
                return error_origin(-ENOMEM);

        policy_init(policy);

        policy->registry = registry;
        policy->uid = uid;
        c_rbtree_add(registry, parent, slot, &policy->registry_node);

        if (policyp)
                *policyp = policy;
        return 0;
}

static Policy *policy_free(Policy *policy) {
        if (!policy)
                return NULL;

        c_rbtree_remove_init(policy->registry, &policy->registry_node);
        policy->registry = NULL;
        policy->uid = (uid_t) -1;

        policy_deinit(policy);

        free(policy);

        return NULL;
}

/* policy registry */
void policy_registry_init(PolicyRegistry *registry) {
        connection_policy_init(&registry->connection_policy);
        policy_init(&registry->default_policy);
        registry->uid_policy_tree = (CRBTree){};
        registry->gid_policy_tree = (CRBTree){};
        policy_init(&registry->at_console_policy);
        policy_init(&registry->not_at_console_policy);
}

void policy_registry_deinit(PolicyRegistry *registry) {
        Policy *policy, *safe;

        policy_deinit(&registry->not_at_console_policy);
        policy_deinit(&registry->at_console_policy);
        c_rbtree_for_each_entry_unlink(policy, safe, &registry->gid_policy_tree, registry_node)
                policy_free(policy);
        c_rbtree_for_each_entry_unlink(policy, safe, &registry->uid_policy_tree, registry_node)
                policy_free(policy);
        policy_deinit(&registry->default_policy);
        connection_policy_deinit(&registry->connection_policy);
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

static int policy_registry_get_policy_by_uid(PolicyRegistry *registry, Policy **policyp, uid_t uid) {
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

static int policy_registry_get_policy_by_gid(PolicyRegistry *registry, Policy **policyp, gid_t gid) {
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

static int policy_get_needed_groups(PolicyRegistry *registry, uid_t uid, gid_t **gidsp, size_t *n_gidsp) {
        struct passwd *passwd;
        _c_cleanup_(c_freep) gid_t *gids = NULL;
        int n_gids = 64;
        int r;

        if (c_rbtree_is_empty(&registry->connection_policy.gid_tree) &&
            c_rbtree_is_empty(&registry->gid_policy_tree)) {
                *gidsp = NULL;
                *n_gidsp = 0;
                return 0;
        }

        passwd = getpwuid(uid);
        if (!passwd)
                return error_origin(-errno);

        do {
                void *tmp;

                tmp = realloc(gids, n_gids);
                if (!tmp)
                        return error_origin(-ENOMEM);
                else
                        gids = tmp;

                r = getgrouplist(passwd->pw_name, passwd->pw_gid, gids, &n_gids);
        } while (r < 0);

        *gidsp = gids;
        gids = NULL;
        *n_gidsp = n_gids;
        return 0;
}

int policy_registry_instantiate_policy(PolicyRegistry *registry, uid_t uid, Policy *policy) {
        _c_cleanup_(c_freep) gid_t *gids = NULL;
        size_t n_gids;
        int r;

        r = policy_get_needed_groups(registry, uid, &gids, &n_gids);
        if (r)
                return error_trace(r);

        r = connection_policy_check_allowed(&registry->connection_policy, uid, gids, n_gids);
        if (r)
                return error_trace(r);

        return 0;
}

/* parser */
static int policy_parse_directory(PolicyParser *parent, const char *dirpath) {
        const char suffix[] = ".conf";
        _c_cleanup_(c_closedirp) DIR *dir = NULL;
        struct dirent *de;
        size_t n;
        int r;

        dir = opendir(dirpath);
        if (!dir) {
                if (errno == ENOENT || errno == ENOTDIR)
                        return 0;
                else
                        return error_origin(-errno);
        }

        for (errno = 0, de = readdir(dir);
             de;
             errno = 0, de = readdir(dir)) {
                _c_cleanup_(c_freep) char *filename = NULL;

                if (de->d_name[0] == '.')
                        continue;

                n = strlen(de->d_name);
                if (n <= strlen(suffix))
                        continue;
                if (strcmp(de->d_name + n - strlen(suffix), suffix))
                        continue;

                r = asprintf(&filename, "%s/%s", dirpath, de->d_name);
                if (r < 0)
                        return error_origin(-ENOMEM);

                r = policy_parser_parse_file(parent->registry, filename, parent);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

static int policy_parser_handler_policy(PolicyParser *parser, const XML_Char **attributes) {
        int r;

        if (!attributes)
                goto error;

        if (!strcmp(*attributes, "context")) {
                if (!*(++attributes))
                        goto error;

                parser->policy = &parser->registry->default_policy;

                if (!strcmp(*attributes, "default")) {
                        parser->priority_base = POLICY_PRIORITY_BASE_DEFAULT;
                } else if (!strcmp(*attributes, "mandatory")) {
                        parser->priority_base = POLICY_PRIORITY_BASE_MANDATORY;
                } else {
                        goto error;
                }
        } else if (!strcmp(*attributes, "user")) {
                struct passwd *passwd;

                if (!*(++attributes))
                        goto error;

                parser->priority_base = POLICY_PRIORITY_BASE_USER;

                passwd = getpwnam(*attributes);
                if (!passwd)
                        return error_origin(-errno);

                r = policy_registry_get_policy_by_uid(parser->registry, &parser->policy, passwd->pw_uid);
                if (r)
                        return error_trace(r);
        } else if (!strcmp(*attributes, "group")) {
                struct group *group;

                if (!*(++attributes))
                        goto error;

                parser->priority_base = POLICY_PRIORITY_BASE_GROUP;

                group = getgrnam(*attributes);
                if (!group)
                        return error_origin(-errno);

                r = policy_registry_get_policy_by_gid(parser->registry, &parser->policy, group->gr_gid);
                if (r)
                        return error_trace(r);
        } else if (!strcmp(*attributes, "at_console")) {
                if (!*(++attributes))
                        goto error;

                parser->priority_base = POLICY_PRIORITY_BASE_CONSOLE;

                if (!strcmp(*attributes, "true")) {
                        parser->policy = &parser->registry->at_console_policy;
                } else if (!strcmp(*attributes, "false")) {
                        parser->policy = &parser->registry->not_at_console_policy;
                } else {
                        goto error;
                }
        } else {
                goto error;
        }

        if (*(++attributes))
                goto error;

        return 0;
error:
        fprintf(stderr, "This isn't good\n");
        return 0; /* XXX: error handling */
}

static int policy_parser_handler_entry(PolicyParser *parser, const XML_Char **attributes, bool deny) {
        TransmissionPolicy *transmission_policy = NULL;
        bool send = false, receive = false;
        const char *name = NULL, *interface = NULL, *member = NULL, *error = NULL, *path = NULL;
        int type = 0, r;

        while (*attributes) {
                const char *key = *(attributes++), *value = *(attributes++);

                if (!strcmp(key, "own")) {
                        if (!strcmp(value, "*")) {
                                r = ownership_policy_set_wildcard(&parser->policy->ownership_policy,
                                                                  deny, parser->priority_base + parser->priority ++);
                                if (r)
                                        return error_trace(r);
                        } else {
                                r = ownership_policy_add_name(&parser->policy->ownership_policy, value,
                                                              deny, parser->priority_base + parser->priority ++);
                                if (r)
                                        return error_trace(r);
                        }
                        continue;
                } else if (!strcmp(key, "own_prefix")) {
                        r = ownership_policy_add_prefix(&parser->policy->ownership_policy, value,
                                                        deny, parser->priority_base + parser->priority ++);
                        if (r)
                                return error_trace(r);
                        continue;
                } else if (!strcmp(key, "user")) {
                        if (!strcmp(value, "*")) {
                                r = connection_policy_set_wildcard(&parser->registry->connection_policy,
                                                                   deny, parser->priority_base + parser->priority ++);
                                if (r)
                                        return error_trace(r);
                        } else {
                                struct passwd *passwd;

                                passwd = getpwnam(value);
                                if (!passwd)
                                        return error_origin(-errno);

                                r = connection_policy_add_uid(&parser->registry->connection_policy, passwd->pw_uid,
                                                              deny, parser->priority_base + parser->priority ++);
                                if (r)
                                        return error_trace(r);
                        }
                        continue;
                } else if (!strcmp(key, "group")) {
                        if (!strcmp(value, "*")) {
                                r = connection_policy_set_wildcard(&parser->registry->connection_policy,
                                                                   deny, parser->priority_base + parser->priority ++);
                                if (r)
                                        return error_trace(r);
                        } else {
                                struct group *group;

                                group = getgrnam(value);
                                if (!group)
                                        return error_origin(-errno);

                                r = connection_policy_add_gid(&parser->registry->connection_policy, group->gr_gid,
                                                              deny, parser->priority_base + parser->priority ++);
                                if (r)
                                        return error_trace(r);
                        }
                        continue;
                } else if (!strncmp(key, "send_", strlen("send_"))) {
                        if (receive)
                                goto error;

                        send = true;
                        transmission_policy = &parser->policy->send_policy;

                        key += strlen("send_");
                } else if (!strncmp(key, "receive_", strlen("receive_"))) {
                        if (send)
                                goto error;

                        receive = true;
                        transmission_policy = &parser->policy->receive_policy;

                        key += strlen("receive_");
                } else {
                        continue;
                }

                if (send == true && !strcmp(key, "destination")) {
                        if (name)
                                goto error;

                        name = value;
                } else if (receive == true && !strcmp(key, "sender")) {
                        if (name)
                                goto error;

                        name = value;
                } else if (!strcmp(key, "interface")) {
                        if (interface)
                                goto error;

                        interface = value;
                } else if (!strcmp(key, "member")) {
                        if (member)
                                goto error;

                        member = value;
                } else if (!strcmp(key, "error")) {
                        if (error)
                                goto error;

                        error = value;
                } else if (!strcmp(key, "path")) {
                        if (path)
                                goto error;

                        path = value;
                } else if (!strcmp(key, "type")) {
                        if (type)
                                goto error;

                        if (!strcmp(value, "method_call"))
                                type = DBUS_MESSAGE_TYPE_METHOD_CALL;
                        else if (!strcmp(value, "method_return"))
                                type = DBUS_MESSAGE_TYPE_METHOD_RETURN;
                        else if (!strcmp(value, "error"))
                                type = DBUS_MESSAGE_TYPE_ERROR;
                        else if (!strcmp(value, "signal"))
                                type = DBUS_MESSAGE_TYPE_SIGNAL;
                        else
                                goto error;
                }
        }

        if (transmission_policy) {
                r = transmission_policy_add_entry(transmission_policy, name, interface, member, error, path, type,
                                                  deny, parser->priority_base + parser->priority ++);
                if (r)
                        return error_trace(r);
        }

        return 0;
error:
        fprintf(stderr, "This isn't good!\n");
        return 0; /* XXX: error handling */
}

static void policy_parser_handler_start(void *userdata, const XML_Char *name, const XML_Char **attributes) {
        PolicyParser *parser = userdata;
        int r;

        switch (parser->level++) {
                case 0:
                        if (!strcmp(name, "busconfig"))
                                parser->busconfig = true;

                        break;
                case 1:
                        if (!parser->busconfig)
                                break;

                        if (!strcmp(name, "policy")) {
                                r = policy_parser_handler_policy(parser, attributes);
                                assert(!r); /* XXX: error handling */
                        } else if (!strcmp(name, "includedir")) {
                                parser->includedir = true;
                        }
                        break;
                case 2:
                        if (!parser->policy)
                                break;

                        if (!strcmp(name, "deny")) {
                                r = policy_parser_handler_entry(parser, attributes, true);
                                assert(!r); /* XXX: error handling */
                        } else if (!strcmp(name, "allow")) {
                                r = policy_parser_handler_entry(parser, attributes, false);
                                assert(!r); /* XXX: error handling */
                        }
                        break;
                default:
                        break;
        }
}

static void policy_parser_handler_end(void *userdata, const XML_Char *name) {
        PolicyParser *parser = userdata;

        switch (--parser->level) {
        case 0:
                if (!strcmp(name, "busconfig")) {
                        assert(parser->busconfig);
                        parser->busconfig = false;
                }
                break;
        case 1:
                if (parser->busconfig) {
                        if (!strcmp(name, "policy")) {
                                assert(parser->policy);
                                parser->policy = NULL;
                                parser->priority_base = (uint64_t)-1;
                        } else if (!strcmp(name, "includedir")) {
                                assert(parser->includedir);
                                policy_parse_directory(parser, parser->characterdata);
                                parser->includedir = false;
                                memset(parser->characterdata, 0, sizeof(parser->characterdata));
                                parser->n_characterdata = 0;
                        }
                }
                break;
        default:
                break;
        }
}

static void policy_parser_character_handler(void *userdata, const XML_Char *data, int n_data) {
        PolicyParser *parser = userdata;

        if (!n_data)
                return;

        if (!parser->includedir)
                return;

        if (!parser->n_characterdata && data[0] != '/') {
                const char *end;

                end = strrchr(parser->filename, '/');
                if (!end)
                        goto error;

                memcpy(parser->characterdata, parser->filename, end - parser->filename + 1);
                parser->n_characterdata = end - parser->filename + 1;
        }

        if (parser->n_characterdata + n_data > PATH_MAX)
                goto error;

        memcpy(parser->characterdata + parser->n_characterdata, data, n_data);

        return;
error:
        fprintf(stderr, "This isn't good.\n");
}

static void policy_parser_init(PolicyParser *parser, PolicyRegistry *registry, PolicyParser *parent, const char *filename) {
        *parser = (PolicyParser)POLICY_PARSER_NULL;
        if (parent) {
                parser->parent = parent;
                parser->priority = parent->priority;
        }
        parser->registry = registry;
        parser->filename = filename;
        parser->parser = XML_ParserCreate(NULL);
        XML_SetUserData(parser->parser, parser);
        XML_SetElementHandler(parser->parser, policy_parser_handler_start, policy_parser_handler_end);
        XML_SetCharacterDataHandler(parser->parser, policy_parser_character_handler);
}

static void policy_parser_deinit(PolicyParser *parser) {
        assert(!parser->policy);
        assert(parser->priority_base == (uint64_t)-1);
        assert(parser->priority < POLICY_PRIORITY_INCREMENT);

        if (parser->parent)
                parser->parent->priority = parser->priority;

        XML_ParserFree(parser->parser);
        *parser = (PolicyParser)POLICY_PARSER_NULL;
}

int policy_parser_parse_file(PolicyRegistry *registry, const char *filename, PolicyParser *parent) {
        PolicyParser parser = (PolicyParser)POLICY_PARSER_NULL;
        _c_cleanup_(c_fclosep) FILE *file = NULL;
        char buffer[1024];
        size_t len;
        int r;

        for (PolicyParser *p = parent; p; p = p->parent)
                if (!strcmp(p->filename, filename))
                        return POLICY_E_CIRCULAR_INCLUDE;

        file = fopen(filename, "r");
        if (!file) {
                if (errno == ENOENT)
                        return 0;

                return error_origin(-errno);
        }

        policy_parser_init(&parser, registry, parent, filename);
        do {
                len = fread(buffer, sizeof(char), sizeof(buffer), file);
                if (!len && ferror(file))
                        return error_origin(-EIO);

                r = XML_Parse(parser.parser, buffer, len, XML_FALSE);
                if (r != XML_STATUS_OK)
                        goto error;
        } while (len == sizeof(buffer));

        r = XML_Parse(parser.parser, NULL, 0, XML_TRUE);
        if (r != XML_STATUS_OK)
                goto error;
        policy_parser_deinit(&parser);

        return 0;
error:
        fprintf(stderr, "%s +%lu: %s\n",
                parser.filename,
                XML_GetCurrentLineNumber(parser.parser),
                XML_ErrorString(XML_GetErrorCode(parser.parser)));
        policy_parser_deinit(&parser);
        return POLICY_E_INVALID_XML;
}
