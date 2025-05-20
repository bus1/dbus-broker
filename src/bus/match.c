/*
 * D-Bus Match Rules
 */

#include <c-dvar.h>
#include <c-list.h>
#include <c-rbtree.h>
#include <c-stdaux.h>
#include "bus/match.h"
#include "dbus/address.h"
#include "dbus/message.h"
#include "dbus/protocol.h"
#include "util/error.h"
#include "util/misc.h"
#include "util/string.h"

static bool match_key_equal(const char *key1, const char *key2, size_t n_key2) {
        if (strlen(key1) != n_key2)
                return false;

        return !strncmp(key1, key2, n_key2);
}

static int match_keys_assign(MatchKeys *keys, const char *key, size_t n_key, const char *value, bool allow_eavesdrop) {
        if (match_key_equal("type", key, n_key)) {
                if (keys->filter.type != DBUS_MESSAGE_TYPE_INVALID)
                        return MATCH_E_INVALID;

                if (strcmp(value, "signal") == 0)
                        keys->filter.type = DBUS_MESSAGE_TYPE_SIGNAL;
                else if (strcmp(value, "method_call") == 0)
                        keys->filter.type = DBUS_MESSAGE_TYPE_METHOD_CALL;
                else if (strcmp(value, "method_return") == 0)
                        keys->filter.type = DBUS_MESSAGE_TYPE_METHOD_RETURN;
                else if (strcmp(value, "error") == 0)
                        keys->filter.type = DBUS_MESSAGE_TYPE_ERROR;
                else
                        return MATCH_E_INVALID;
        } else if (match_key_equal("sender", key, n_key)) {
                Address addr;

                if (keys->sender)
                        return MATCH_E_INVALID;
                if (!dbus_validate_name(value, strlen(value)))
                        return MATCH_E_INVALID;
                keys->sender = value;

                address_from_string(&addr, value);
                if (addr.type == ADDRESS_TYPE_ID) {
                        /*
                         * Usually rules are indexed by sender, however, we also allow rules that match
                         * on a sender ID to not be indexed, in case the peer with the ID does not yet
                         * exits. Therefore, we must also remember the sender id.
                         */
                        keys->filter.sender = addr.id;
                }
        } else if (match_key_equal("destination", key, n_key)) {
                if (keys->destination)
                        return MATCH_E_INVALID;
                if (!dbus_validate_name(value, strlen(value)))
                        return MATCH_E_INVALID;
                keys->destination = value;
        } else if (match_key_equal("interface", key, n_key)) {
                if (keys->filter.interface)
                        return MATCH_E_INVALID;
                if (!dbus_validate_interface(value, strlen(value)))
                        return MATCH_E_INVALID;
                keys->filter.interface = value;
        } else if (match_key_equal("member", key, n_key)) {
                if (keys->filter.member)
                        return MATCH_E_INVALID;
                if (!dbus_validate_member(value, strlen(value)))
                        return MATCH_E_INVALID;
                keys->filter.member = value;
        } else if (match_key_equal("path", key, n_key)) {
                if (keys->filter.path || keys->path_namespace)
                        return MATCH_E_INVALID;
                if (!c_dvar_is_path(value, strlen(value)))
                        return MATCH_E_INVALID;
                keys->filter.path = value;
        } else if (match_key_equal("path_namespace", key, n_key)) {
                if (keys->path_namespace || keys->filter.path)
                        return MATCH_E_INVALID;
                if (!c_dvar_is_path(value, strlen(value)))
                        return MATCH_E_INVALID;
                keys->path_namespace = value;
        } else if (match_key_equal("eavesdrop", key, n_key)) {
                /*
                 * If the caller explicitly allows eavesdrop filters, we parse
                 * them but immediately discard it. We only support this to
                 * allow BecomeMonitor() to work with legacy eavesdrop filters
                 * which `dbus-monitor` seems to enforce on all its matches.
                 * In all other cases, we never support eavesdropping, nor do
                 * we allow such filters to be parsed.
                 */
                if (!allow_eavesdrop)
                        return MATCH_E_INVALID;
                if (strcmp(value, "true") != 0 && strcmp(value, "false") != 0)
                        return MATCH_E_INVALID;
        } else if (match_key_equal("arg0namespace", key, n_key)) {
                if (keys->arg0namespace || keys->filter.args[0] || keys->filter.argpaths[0])
                        return MATCH_E_INVALID;
                if (!dbus_validate_namespace(value, strlen(value)))
                        return MATCH_E_INVALID;
                keys->arg0namespace = value;
        } else if (n_key >= strlen("arg") && match_key_equal("arg", key, strlen("arg"))) {
                unsigned int i = 0;

                key += strlen("arg");
                n_key -= strlen("arg");

                for (unsigned int j = 0; j < 2 && n_key; ++j, ++key, --n_key) {
                        if (*key < '0' || *key > '9')
                                break;

                        i = i * 10 + *key - '0';
                }

                if (i == 0 && keys->arg0namespace)
                        return MATCH_E_INVALID;
                if (i > 63)
                        return MATCH_E_INVALID;

                if (keys->filter.args[i] || keys->filter.argpaths[i])
                        return MATCH_E_INVALID;

                if (match_key_equal("", key, n_key)) {
                        keys->filter.args[i] = value;
                        if (i + 1 > keys->filter.n_args)
                                keys->filter.n_args = i + 1;
                } else if (match_key_equal("path", key, n_key)) {
                        keys->filter.argpaths[i] = value;
                        if (i + 1 > keys->filter.n_argpaths)
                                keys->filter.n_argpaths = i + 1;
                } else
                        return MATCH_E_INVALID;
        } else {
                return MATCH_E_INVALID;
        }

        return 0;
}

static int match_copy_value(const char **match, char **p) {
        const char *m = *match;
        bool quoted = false;
        char c;

        /*
         * Within single quotes (apostrophe), a backslash represents itself,
         * and an apostrophe ends the quoted section. Outside single quotes, \'
         * (backslash, apostrophe) represents an apostrophe, and any backslash
         * not followed by an apostrophe represents itself.
         *
         * Note that this is quite counter-intuitive to everyone used to
         * shell-style quoting. However, we strictly follow the D-Bus
         * specification and reference-implementation here!
         */

        do {
                for ( ; *m == '\''; ++m)
                        quoted = !quoted;

                switch ((c = *m++)) {
                case 0:
                        --m; /* leave zero-terminating for caller */
                        break;
                case ',':
                        c = quoted ? ',' : 0;
                        break;
                case '\\':
                        c = (!quoted && *m == '\'') ? *m++ : '\\';
                        break;
                }


                **p = c;
        } while (*(*p)++);

        if (quoted)
                return MATCH_E_INVALID;

        *match = m;
        return 0;
}

static int match_parse_key(const char **match, const char **keyp, size_t *n_keyp) {
        const char *key;
        size_t n_key = 0;

        /* skip any leading whitespace and stray equal signs */
        *match += strspn(*match, " \t\n\r=");
        if (!**match)
                return MATCH_E_EOF;

        /* skip over the key, recording its length */
        n_key = strcspn(*match, " \t\n\r=");
        key = *match;
        *match += n_key;
        if (!**match)
                return MATCH_E_INVALID;

        /* drop trailing whitespace */
        *match += strspn(*match, " \t\n\r");

        /* skip over the equals sign between the key and the value */
        if (**match != '=')
                return MATCH_E_INVALID;
        else
                ++*match;

        *keyp = key;
        *n_keyp = n_key;
        return 0;
}

static int match_keys_parse(MatchKeys *keys, const char *string, bool allow_eavesdrop) {
        const char *key, *value;
        size_t n_key, n_buffer;
        char *p;
        int r;

        /*
         * Parse the rule-string @string into @keys. We repeatedly pop off a
         * key from @string and copy over the value into @keys, remembering the
         * pointer to it. If anything fails, we simply bail out.
         *
         * Note that we rely on @string to be zero-terminated!
         */

        p = keys->buffer;

        for (;;) {
                r = match_parse_key(&string, &key, &n_key);
                if (r)
                        break;

                value = p;
                r = match_copy_value(&string, &p);
                if (r)
                        break;

                r = match_keys_assign(keys, key, n_key, value, allow_eavesdrop);
                if (r)
                        break;
        }

        n_buffer = p - keys->buffer;

        c_assert(n_buffer <= keys->n_buffer);

        keys->n_buffer = p - keys->buffer;

        return (r == MATCH_E_EOF) ? 0 : error_trace(r);
}

static void match_keys_deinit(MatchKeys *keys) {
        *keys = (MatchKeys)MATCH_KEYS_NULL;
}

C_DEFINE_CLEANUP(MatchKeys *, match_keys_deinit);

static int match_keys_init(MatchKeys *k, const char *string, size_t n_string, bool allow_eavesdrop) {
        _c_cleanup_(match_keys_deinitp) MatchKeys *keys = k;
        int r;

        c_assert(n_string > 0);
        c_assert(n_string - 1 <= MATCH_RULE_LENGTH_MAX);

        *keys = (MatchKeys)MATCH_KEYS_NULL;
        keys->n_buffer = n_string;

        r = match_keys_parse(keys, string, allow_eavesdrop);
        if (r)
                return error_trace(r);

        keys = NULL;
        return 0;
}

static int match_keys_clone(MatchKeys *k, MatchKeys *old) {
        _c_cleanup_(match_keys_deinitp) MatchKeys *keys = k;
        size_t n_buffer;
        char *p;

        *keys = (MatchKeys)MATCH_KEYS_NULL;
        keys->n_buffer = old->n_buffer;

        keys->filter.type = old->filter.type;
        keys->filter.sender = old->filter.sender;

        p = keys->buffer;

        if (old->filter.interface) {
                keys->filter.interface = p;
                p = stpcpy(p, old->filter.interface) + 1;
        }

        if (old->filter.member) {
                keys->filter.member = p;
                p = stpcpy(p, old->filter.member) + 1;
        }

        if (old->filter.path) {
                keys->filter.path = p;
                p = stpcpy(p, old->filter.path) + 1;
        }

        for (size_t i = 0; i < old->filter.n_args; ++i) {
                if (old->filter.args[i]) {
                        keys->filter.args[i] = p;
                        p = stpcpy(p, old->filter.args[i]) + 1;
                }
        }
        keys->filter.n_args = old->filter.n_args;

        for (size_t i = 0; i < old->filter.n_argpaths; ++i) {
                if (old->filter.argpaths[i]) {
                        keys->filter.argpaths[i] = p;
                        p = stpcpy(p, old->filter.argpaths[i]) + 1;
                }
        }
        keys->filter.n_argpaths = old->filter.n_argpaths;

        if (old->destination) {
                keys->destination = p;
                p = stpcpy(p, old->destination) + 1;
        }

        if (old->sender) {
                keys->sender = p;
                p = stpcpy(p, old->sender) + 1;
        }

        if (old->path_namespace) {
                keys->path_namespace = p;
                p = stpcpy(p, old->path_namespace) + 1;
        }

        if (old->arg0namespace) {
                keys->arg0namespace = p;
                p = stpcpy(p, old->arg0namespace) + 1;
        }

        n_buffer = p - keys->buffer;

        c_assert(n_buffer <= keys->n_buffer);

        keys->n_buffer = p - keys->buffer;


        keys = NULL;
        return 0;
}

static MatchKeys *match_keys_free(MatchKeys *keys) {
        if (keys) {
                match_keys_deinit(keys);
                free(keys);
        }
        return NULL;
}

C_DEFINE_CLEANUP(MatchKeys *, match_keys_free);

static int match_keys_new(MatchKeys **keysp, const char *string) {
        _c_cleanup_(match_keys_freep) MatchKeys *keys = NULL;
        size_t n_string;
        int r;

        n_string = strlen(string) + 1;
        if (n_string - 1 > MATCH_RULE_LENGTH_MAX)
                return MATCH_E_INVALID;

        keys = calloc(1, sizeof(*keys) + n_string);
        if (!keys)
                return error_origin(-ENOMEM);

        r = match_keys_init(keys, string, n_string, false);
        if (r)
                return error_trace(r);

        *keysp = keys;
        keys = NULL;
        return 0;
}

static bool match_string_prefix(const char *string, const char *prefix, char delimiter, bool delimiter_included) {
        char *tail;

        if (string == prefix)
                return true;

        if (!string || !prefix)
                return false;

        tail = string_prefix(string, prefix);
        if (!tail)
                return false;

        if (delimiter_included) {
                if (tail == string || (*tail != '\0' && *(tail - 1) != delimiter))
                        return false;
        } else {
                if (*tail != '\0' && *tail != delimiter)
                        return false;
        }

        return true;
}

static bool match_keys_match_metadata(MatchKeys *keys, MessageMetadata *metadata) {
        if (keys->filter.n_args > metadata->n_args)
                return false;

        if (keys->filter.n_argpaths > metadata->n_args)
                return false;

        if (keys->path_namespace && !match_string_prefix(metadata->fields.path, keys->path_namespace, '/', false))
                return false;

        if (keys->arg0namespace && !(metadata->args[0].element == 's' && match_string_prefix(metadata->args[0].value, keys->arg0namespace, '.', false)))
                return false;

        for (unsigned int i = 0; i < keys->filter.n_args || i < keys->filter.n_argpaths; i ++) {
                if (keys->filter.args[i] && !(metadata->args[i].element == 's' && string_equal(keys->filter.args[i], metadata->args[i].value)))
                        return false;

                if (keys->filter.argpaths[i]) {
                        if (!match_string_prefix(metadata->args[i].value, keys->filter.argpaths[i], '/', true) &&
                            !match_string_prefix(keys->filter.argpaths[i], metadata->args[i].value, '/', true))
                                return false;
                }
        }

        if (keys->filter.type != DBUS_MESSAGE_TYPE_INVALID && keys->filter.type != metadata->header.type)
                return false;

        if (keys->filter.sender != ADDRESS_ID_INVALID && keys->filter.sender != metadata->sender_id)
                return false;

        if (keys->filter.interface && !string_equal(keys->filter.interface, metadata->fields.interface))
                return false;

        if (keys->filter.member && !string_equal(keys->filter.member, metadata->fields.member))
                return false;

        if (keys->filter.path && !string_equal(keys->filter.path, metadata->fields.path))
                return false;

        return true;
}

static int match_registry_by_path_compare(CRBTree *tree, void *k, CRBNode *rb) {
        MatchRegistryByPath *registry = c_container_of(rb, MatchRegistryByPath, registry_node);
        const char *path1 = k ?: "", *path2 = registry->path;

        return strcmp(path1, path2);
}

static int match_registry_by_path_new(MatchRegistryByPath **registryp, const char *path) {
        MatchRegistryByPath *registry;
        size_t n_path;

        if (!path)
                path = "";

        n_path = strlen(path);

        registry = malloc(sizeof(*registry) + n_path + 1);
        if (!registry)
                return error_origin(-ENOMEM);

        *registry = (MatchRegistryByPath)MATCH_REGISTRY_BY_PATH_INIT(*registry);
        strcpy(registry->path, path);

        *registryp = registry;
        return 0;
}

static MatchRegistryByPath *match_registry_by_path_ref(MatchRegistryByPath *registry) {
        if (!registry)
                return NULL;

        c_assert(registry->n_refs > 0);

        ++registry->n_refs;

        return registry;
}

static MatchRegistryByPath *match_registry_by_path_unref(MatchRegistryByPath *registry) {
        if (!registry || --registry->n_refs > 0)
                return NULL;

        c_assert(c_rbtree_is_empty(&registry->interface_tree));

        c_rbnode_unlink(&registry->registry_node);
        free(registry);

        return NULL;
}

C_DEFINE_CLEANUP(MatchRegistryByPath *, match_registry_by_path_unref);

static void match_registry_by_path_link(MatchRegistryByPath *registry, CRBTree *tree, CRBNode *parent, CRBNode **slot) {
        c_rbtree_add(tree, parent, slot, &registry->registry_node);
}

static int match_registry_by_interface_compare(CRBTree *tree, void *k, CRBNode *rb) {
        MatchRegistryByInterface *registry = c_container_of(rb, MatchRegistryByInterface, registry_node);
        const char *interface1 = k ?: "", *interface2 = registry->interface;

        return strcmp(interface1, interface2);
}

static int match_registry_by_interface_new(MatchRegistryByInterface **registryp, const char *interface) {
        MatchRegistryByInterface *registry;
        size_t n_interface;

        if (!interface)
                interface = "";

        n_interface = strlen(interface);

        registry = malloc(sizeof(*registry) + n_interface + 1);
        if (!registry)
                return error_origin(-ENOMEM);

        *registry = (MatchRegistryByInterface)MATCH_REGISTRY_BY_INTERFACE_INIT(*registry);
        strcpy(registry->interface, interface);

        *registryp = registry;
        return 0;
}

static MatchRegistryByInterface *match_registry_by_interface_ref(MatchRegistryByInterface *registry) {
        if (!registry)
                return NULL;

        c_assert(registry->n_refs > 0);

        ++registry->n_refs;

        return registry;
}

static MatchRegistryByInterface *match_registry_by_interface_unref(MatchRegistryByInterface *registry) {
        if (!registry || --registry->n_refs > 0)
                return NULL;

        c_assert(c_rbtree_is_empty(&registry->member_tree));

        c_rbnode_unlink(&registry->registry_node);
        match_registry_by_path_unref(registry->registry_by_path);
        free(registry);

        return NULL;
}

C_DEFINE_CLEANUP(MatchRegistryByInterface *, match_registry_by_interface_unref);

static void match_registry_by_interface_link(MatchRegistryByInterface *registry, MatchRegistryByPath *registry_by_path, CRBNode *parent, CRBNode **slot) {
        c_rbtree_add(&registry_by_path->interface_tree, parent, slot, &registry->registry_node);
        registry->registry_by_path = match_registry_by_path_ref(registry_by_path);
}

static int match_registry_by_member_compare(CRBTree *tree, void *k, CRBNode *rb) {
        MatchRegistryByMember *registry = c_container_of(rb, MatchRegistryByMember, registry_node);
        const char *member1 = k ?: "", *member2 = registry->member;

        return strcmp(member1, member2);
}

static int match_registry_by_member_new(MatchRegistryByMember **registryp, const char *member) {
        MatchRegistryByMember *registry;
        size_t n_member;

        if (!member)
                member = "";

        n_member = strlen(member);

        registry = malloc(sizeof(*registry) + n_member + 1);
        if (!registry)
                return error_origin(-ENOMEM);

        *registry = (MatchRegistryByMember)MATCH_REGISTRY_BY_MEMBER_INIT(*registry);
        strcpy(registry->member, member);

        *registryp = registry;
        return 0;
}

static MatchRegistryByMember *match_registry_by_member_ref(MatchRegistryByMember *registry) {
        if (!registry)
                return NULL;

        c_assert(registry->n_refs > 0);

        ++registry->n_refs;

        return registry;
}

static MatchRegistryByMember *match_registry_by_member_unref(MatchRegistryByMember *registry) {
        if (!registry || --registry->n_refs > 0)
                return NULL;

        c_assert(c_rbtree_is_empty(&registry->keys_tree));

        c_rbnode_unlink(&registry->registry_node);
        match_registry_by_interface_unref(registry->registry_by_interface);
        free(registry);

        return NULL;
}

C_DEFINE_CLEANUP(MatchRegistryByMember *, match_registry_by_member_unref);

static void match_registry_by_member_link(MatchRegistryByMember *registry, MatchRegistryByInterface *registry_by_interface, CRBNode *parent, CRBNode **slot) {
        c_rbtree_add(&registry_by_interface->member_tree, parent, slot, &registry->registry_node);
        registry->registry_by_interface = match_registry_by_interface_ref(registry_by_interface);
}

static int match_keys_compare(MatchKeys *key1, MatchKeys *key2) {
        int r;

        if ((r = string_compare(key1->sender, key2->sender)) ||
            (r = string_compare(key1->destination, key2->destination)) ||
            (r = string_compare(key1->filter.interface, key2->filter.interface)) ||
            (r = string_compare(key1->filter.member, key2->filter.member)) ||
            (r = string_compare(key1->filter.path, key2->filter.path)) ||
            (r = string_compare(key1->path_namespace, key2->path_namespace)) ||
            (r = string_compare(key1->arg0namespace, key2->arg0namespace)))
                return r;

        if (key1->filter.type > key2->filter.type)
                return 1;
        if (key1->filter.type < key2->filter.type)
                return -1;

        if (key1->filter.n_args < key2->filter.n_args)
                return -1;
        if (key1->filter.n_args > key2->filter.n_args)
                return 1;

        if (key1->filter.n_argpaths < key2->filter.n_argpaths)
                return -1;
        if (key1->filter.n_argpaths > key2->filter.n_argpaths)
                return 1;

        for (size_t i = 0; i < key1->filter.n_args || i < key1->filter.n_argpaths; i ++) {
                if ((r = string_compare(key1->filter.args[i], key2->filter.args[i])) ||
                    (r = string_compare(key1->filter.argpaths[i], key2->filter.argpaths[i])))
                        return r;
        }

        return 0;
}

static int match_registry_by_keys_compare(CRBTree *tree, void *k, CRBNode *rb) {
        MatchRegistryByKeys *registry = c_container_of(rb, MatchRegistryByKeys, registry_node);
        MatchKeys *keys1 = k, *keys2 = &registry->keys;

        return match_keys_compare(keys1, keys2);
}

static int match_registry_by_keys_new(MatchRegistryByKeys **registryp, MatchKeys *keys) {
        MatchRegistryByKeys *registry;

        registry = malloc(sizeof(*registry) + keys->n_buffer);
        if (!registry)
                return error_origin(-ENOMEM);

        *registry = (MatchRegistryByKeys)MATCH_REGISTRY_BY_KEYS_INIT(*registry);
        match_keys_clone(&registry->keys, keys);

        *registryp = registry;
        return 0;
}

static MatchRegistryByKeys *match_registry_by_keys_ref(MatchRegistryByKeys *registry) {
        if (!registry)
                return NULL;

        c_assert(registry->n_refs > 0);

        ++registry->n_refs;

        return registry;
}

static MatchRegistryByKeys *match_registry_by_keys_unref(MatchRegistryByKeys *registry) {
        if (!registry || --registry->n_refs > 0)
                return NULL;

        c_assert(c_list_is_empty(&registry->rule_list));

        c_rbnode_unlink(&registry->registry_node);
        match_registry_by_member_unref(registry->registry_by_member);
        free(registry);

        return NULL;
}

C_DEFINE_CLEANUP(MatchRegistryByKeys *, match_registry_by_keys_unref);

static void match_registry_by_keys_link(MatchRegistryByKeys *registry, MatchRegistryByMember *registry_by_member, CRBNode *parent, CRBNode **slot) {
        c_rbtree_add(&registry_by_member->keys_tree, parent, slot, &registry->registry_node);
        registry->registry_by_member = match_registry_by_member_ref(registry_by_member);
}

static int match_rule_compare(CRBTree *tree, void *k, CRBNode *rb) {
        MatchRule *rule = c_container_of(rb, MatchRule, owner_node);
        MatchKeys *key1 = k, *key2 = &rule->keys;

        return match_keys_compare(key1, key2);
}

static MatchRule *match_rule_free(MatchRule *rule) {
        if (!rule)
                return NULL;

        c_assert(!rule->n_user_refs);

        match_keys_deinit(&rule->keys);
        user_charge_deinit(&rule->charge[1]);
        user_charge_deinit(&rule->charge[0]);
        c_rbnode_unlink(&rule->owner_node);
        match_rule_unlink(rule);
        free(rule);

        return NULL;
}

C_DEFINE_CLEANUP(MatchRule *, match_rule_free);

static int match_rule_new(MatchRule **rulep, MatchOwner *owner, User *user, const char *string, bool allow_eavesdrop) {
        _c_cleanup_(match_rule_freep) MatchRule *rule = NULL;
        size_t n_string;
        int r;

        n_string = strlen(string) + 1;
        if (n_string - 1 > MATCH_RULE_LENGTH_MAX)
                return MATCH_E_INVALID;

        rule = calloc(1, sizeof(*rule) + n_string);
        if (!rule)
                return error_origin(-ENOMEM);

        *rule = (MatchRule)MATCH_RULE_NULL(*rule);
        rule->owner = owner;

        r = user_charge(user, &rule->charge[0], NULL, USER_SLOT_BYTES, sizeof(*rule) + n_string);
        r = r ?: user_charge(user, &rule->charge[1], NULL, USER_SLOT_MATCHES, 1);
        if (r)
                return (r == USER_E_QUOTA) ? MATCH_E_QUOTA : error_fold(r);

        r = match_keys_init(&rule->keys, string, n_string, allow_eavesdrop);
        if (r)
                return error_trace(r);

        *rulep = rule;
        rule = NULL;
        return 0;
}

/**
 * match_rule_user_ref() - XXX
 */
MatchRule *match_rule_user_ref(MatchRule *rule) {
        if (!rule)
                return NULL;

        c_assert(rule->n_user_refs > 0);

        ++rule->n_user_refs;

        return rule;
}

/**
 * match_rule_user_unref() - XXX
 */
MatchRule *match_rule_user_unref(MatchRule *rule) {
        if (!rule)
                return NULL;

        c_assert(rule->n_user_refs > 0);

        --rule->n_user_refs;

        if (rule->n_user_refs == 0)
                match_rule_free(rule);

        return NULL;
}

static void match_rule_link_by_keys(MatchRule *rule, MatchRegistryByKeys *registry) {
        c_list_link_tail(&registry->rule_list, &rule->registry_link);
        rule->registry_by_keys = match_registry_by_keys_ref(registry);
}

static int match_rule_link_by_member(MatchRule *rule, MatchRegistryByMember *registry) {
        _c_cleanup_(match_registry_by_keys_unrefp) MatchRegistryByKeys *registry_by_keys = NULL;
        CRBNode **slot, *parent;
        int r;

        slot = c_rbtree_find_slot(&registry->keys_tree, match_registry_by_keys_compare, &rule->keys, &parent);
        if (!slot) {
                registry_by_keys = match_registry_by_keys_ref(c_rbnode_entry(parent, MatchRegistryByKeys, registry_node));
        } else {
                r = match_registry_by_keys_new(&registry_by_keys, &rule->keys);
                if (r)
                        return error_trace(r);

                match_registry_by_keys_link(registry_by_keys, registry, parent, slot);
        }

        match_rule_link_by_keys(rule, registry_by_keys);

        return 0;
}

static int match_rule_link_by_interface(MatchRule *rule, MatchRegistryByInterface *registry) {
        _c_cleanup_(match_registry_by_member_unrefp) MatchRegistryByMember *registry_by_member = NULL;
        CRBNode **slot, *parent;
        int r;

        slot = c_rbtree_find_slot(&registry->member_tree, match_registry_by_member_compare, rule->keys.filter.member, &parent);
        if (!slot) {
                registry_by_member = match_registry_by_member_ref(c_rbnode_entry(parent, MatchRegistryByMember, registry_node));
        } else {
                r = match_registry_by_member_new(&registry_by_member, rule->keys.filter.member);
                if (r)
                        return error_trace(r);

                match_registry_by_member_link(registry_by_member, registry, parent, slot);
        }

        r = match_rule_link_by_member(rule, registry_by_member);
        if (r)
                return error_trace(r);

        return 0;
}

static int match_rule_link_by_path(MatchRule *rule, MatchRegistryByPath *registry) {
        _c_cleanup_(match_registry_by_interface_unrefp) MatchRegistryByInterface *registry_by_interface = NULL;
        CRBNode **slot, *parent;
        int r;

        slot = c_rbtree_find_slot(&registry->interface_tree, match_registry_by_interface_compare, rule->keys.filter.interface, &parent);
        if (!slot) {
                registry_by_interface = match_registry_by_interface_ref(c_rbnode_entry(parent, MatchRegistryByInterface, registry_node));
        } else {
                r = match_registry_by_interface_new(&registry_by_interface, rule->keys.filter.interface);
                if (r)
                        return error_trace(r);

                match_registry_by_interface_link(registry_by_interface, registry, parent, slot);
        }

        r = match_rule_link_by_interface(rule, registry_by_interface);
        if (r)
                return error_trace(r);

        return 0;
}

/**
 * match_rule_link() - XXX
 */
int match_rule_link(MatchRule *rule, MatchCounters *counters, MatchRegistry *registry, bool monitor) {
        _c_cleanup_(match_registry_by_path_unrefp) MatchRegistryByPath *registry_by_path = NULL;
        CRBTree *tree;
        CRBNode **slot, *parent;
        int r;

        if (rule->registry) {
                c_assert(registry == rule->registry);
                c_assert(c_list_is_linked(&rule->registry_link));
                c_assert(counters == rule->counters);

                return 0;
        }

        if (monitor)
                tree = &registry->monitor_tree;
        else
                tree = &registry->subscription_tree;

        slot = c_rbtree_find_slot(tree, match_registry_by_path_compare, rule->keys.filter.path, &parent);
        if (!slot) {
                registry_by_path = match_registry_by_path_ref(c_rbnode_entry(parent, MatchRegistryByPath, registry_node));
        } else {
                r = match_registry_by_path_new(&registry_by_path, rule->keys.filter.path);
                if (r)
                        return error_trace(r);

                match_registry_by_path_link(registry_by_path, tree, parent, slot);
        }

        r = match_rule_link_by_path(rule, registry_by_path);
        if (r)
                return error_trace(r);

        rule->registry = registry;
        rule->counters = counters;

        if (counters) {
                ++counters->n_subscriptions;
                ++rule->owner->n_owner_subscriptions;
                util_peak_update(&counters->n_subscriptions_peak, counters->n_subscriptions);
                util_peak_update(&counters->n_owner_subscriptions_peak, rule->owner->n_owner_subscriptions);
        }

        return 0;
}

/**
 * match_rule_unlink() - XXX
 */
void match_rule_unlink(MatchRule *rule) {
        if (rule->registry) {
                if (rule->counters) {
                        --rule->owner->n_owner_subscriptions;
                        --rule->counters->n_subscriptions;
                }

                c_list_unlink(&rule->registry_link);
                rule->registry_by_keys = match_registry_by_keys_unref(rule->registry_by_keys);
                rule->counters = NULL;
                rule->registry = NULL;
        }
}

/**
 * match_owner_init() - XXX
 */
void match_owner_init(MatchOwner *owner) {
        *owner = (MatchOwner)MATCH_OWNER_INIT(*owner);
}

/**
 * match_owner_deinit() - XXX
 */
void match_owner_deinit(MatchOwner *owner) {
        c_assert(c_rbtree_is_empty(&owner->rule_tree));
        c_assert(!c_list_is_linked(&owner->destinations_link));
}

/**
 * match_owner_get_stats() - XXX
 */
void match_owner_get_stats(MatchOwner *owner, unsigned int *n_bytesp, unsigned int *n_matchesp) {
        MatchRule *rule;
        unsigned int n_bytes = 0, n_matches = 0;

        c_rbtree_for_each_entry(rule, &owner->rule_tree, owner_node) {
                n_bytes += rule->charge[0].charge;
                n_matches += rule->charge[1].charge;
        }

        *n_bytesp = n_bytes;
        *n_matchesp = n_matches;
}

/**
 * match_owner_move() - XXX
 */
void match_owner_move(MatchOwner *to, MatchOwner *from) {
        c_rbtree_move(&to->rule_tree, &from->rule_tree);
}

/**
 * match_owner_ref_rule() - XXX
 */
int match_owner_ref_rule(MatchOwner *owner, MatchRule **rulep, User *user, const char *rule_string, bool allow_eavesdrop) {
        CRBNode **slot, *parent;
        MatchRule *rule;
        int r;

        r = match_rule_new(&rule, owner, user, rule_string, allow_eavesdrop);
        if (r)
                return error_trace(r);

        ++rule->n_user_refs;

        slot = c_rbtree_find_slot(&owner->rule_tree, match_rule_compare, &rule->keys, &parent);
        if (!slot) {
                /* one already exists, take a ref on that instead and drop the one we created */
                match_rule_user_unref(rule);
                rule = match_rule_user_ref(c_container_of(parent, MatchRule, owner_node));
        } else {
                /* link the new rule into the rbtree */
                c_rbtree_add(&owner->rule_tree, parent, slot, &rule->owner_node);
        }

        if (rulep)
                *rulep = rule;
        return 0;
}

/**
 * match_owner_find_rule() - XXX
 */
int match_owner_find_rule(MatchOwner *owner, MatchRule **rulep, const char *rule_string) {
        _c_cleanup_(match_keys_freep) MatchKeys *keys = NULL;
        int r;

        r = match_keys_new(&keys, rule_string);
        if (r)
                return error_trace(r);

        *rulep = c_rbtree_find_entry(&owner->rule_tree, match_rule_compare, keys, MatchRule, owner_node);
        return 0;
}

/**
 * match_registry_init() - XXX
 */
void match_registry_init(MatchRegistry *registry) {
        *registry = (MatchRegistry)MATCH_REGISTRY_INIT(*registry);
}

/**
 * match_registry_deinit() - XXX
 */
void match_registry_deinit(MatchRegistry *registry) {
        c_assert(c_rbtree_is_empty(&registry->subscription_tree));
        c_assert(c_rbtree_is_empty(&registry->monitor_tree));
}

static void match_registry_by_keys_get_destinations(MatchRegistryByKeys *registry, CList *destinations) {
        MatchRule *rule;

        c_list_for_each_entry(rule, &registry->rule_list, registry_link) {
                if (c_list_is_linked(&rule->owner->destinations_link))
                        /* only link a destination once, despite matching in several different ways */
                        continue;

                c_list_link_tail(destinations, &rule->owner->destinations_link);
        }
}

static void match_registry_by_member_get_destinations(MatchRegistryByMember *registry, CList *destinations, MessageMetadata *metadata) {
        MatchRegistryByKeys *registry_by_keys;

        c_rbtree_for_each_entry_postorder(registry_by_keys, &registry->keys_tree, registry_node) {
                if (!match_keys_match_metadata(&registry_by_keys->keys, metadata))
                        continue;

                match_registry_by_keys_get_destinations(registry_by_keys, destinations);
        }
}

static void match_registry_by_interface_get_destinations(MatchRegistryByInterface *registry, CList *destinations, MessageMetadata *metadata) {
        MatchRegistryByMember *registry_by_member;

        registry_by_member = c_rbtree_find_entry(&registry->member_tree, match_registry_by_member_compare, NULL, MatchRegistryByMember, registry_node);
        if (registry_by_member)
                match_registry_by_member_get_destinations(registry_by_member, destinations, metadata);

        if (metadata->fields.member) {
                registry_by_member = c_rbtree_find_entry(&registry->member_tree, match_registry_by_member_compare, metadata->fields.member, MatchRegistryByMember, registry_node);
                if (registry_by_member)
                        match_registry_by_member_get_destinations(registry_by_member, destinations, metadata);
        }
}

static void match_registry_by_path_get_destinations(MatchRegistryByPath *registry, CList *destinations, MessageMetadata *metadata) {
        MatchRegistryByInterface *registry_by_interface;

        registry_by_interface = c_rbtree_find_entry(&registry->interface_tree, match_registry_by_interface_compare, NULL, MatchRegistryByInterface, registry_node);
        if (registry_by_interface)
                match_registry_by_interface_get_destinations(registry_by_interface, destinations, metadata);

        if (metadata->fields.interface) {
                registry_by_interface = c_rbtree_find_entry(&registry->interface_tree, match_registry_by_interface_compare, metadata->fields.interface, MatchRegistryByInterface, registry_node);
                if (registry_by_interface)
                        match_registry_by_interface_get_destinations(registry_by_interface, destinations, metadata);
        }

}

static void match_registry_get_destinations(CRBTree *tree, CList *destinations, MessageMetadata *metadata) {
        MatchRegistryByPath *registry_by_path;

        registry_by_path = c_rbtree_find_entry(tree, match_registry_by_path_compare, NULL, MatchRegistryByPath, registry_node);
        if (registry_by_path)
                match_registry_by_path_get_destinations(registry_by_path, destinations, metadata);

        if (metadata->fields.path) {
                registry_by_path = c_rbtree_find_entry(tree, match_registry_by_path_compare, metadata->fields.path, MatchRegistryByPath, registry_node);
                if (registry_by_path)
                        match_registry_by_path_get_destinations(registry_by_path, destinations, metadata);
        }

}

void match_registry_get_subscribers(MatchRegistry *registry, CList *destinations, MessageMetadata *metadata) {
        match_registry_get_destinations(&registry->subscription_tree, destinations, metadata);
}

void match_registry_get_monitors(MatchRegistry *registry, CList *destinations, MessageMetadata *metadata) {
        match_registry_get_destinations(&registry->monitor_tree, destinations, metadata);
}

static void match_registry_by_keys_flush(MatchRegistryByKeys *registry) {
        MatchRule *rule, *rule_safe;

        c_list_for_each_entry_safe(rule, rule_safe, &registry->rule_list, registry_link)
                match_rule_unlink(rule);

        c_assert(c_list_is_empty(&registry->rule_list));
}

static void match_registry_by_member_flush(MatchRegistryByMember *registry) {
        MatchRegistryByKeys *registry_by_keys, *registry_by_keys_safe;

        c_rbtree_for_each_entry_safe(registry_by_keys, registry_by_keys_safe, &registry->keys_tree, registry_node) {
                match_registry_by_keys_ref(registry_by_keys);
                match_registry_by_keys_flush(registry_by_keys);
                match_registry_by_keys_unref(registry_by_keys);
        }

        c_assert(c_rbtree_is_empty(&registry->keys_tree));
}

static void match_registry_by_interface_flush(MatchRegistryByInterface *registry) {
        MatchRegistryByMember *registry_by_member, *registry_by_member_safe;

        c_rbtree_for_each_entry_safe(registry_by_member, registry_by_member_safe, &registry->member_tree, registry_node) {
                match_registry_by_member_ref(registry_by_member);
                match_registry_by_member_flush(registry_by_member);
                match_registry_by_member_unref(registry_by_member);
        }

        c_assert(c_rbtree_is_empty(&registry->member_tree));
}

static void match_registry_by_path_flush(MatchRegistryByPath *registry) {
        MatchRegistryByInterface *registry_by_interface, *registry_by_interface_safe;

        c_rbtree_for_each_entry_safe(registry_by_interface, registry_by_interface_safe, &registry->interface_tree, registry_node) {
                match_registry_by_interface_ref(registry_by_interface);
                match_registry_by_interface_flush(registry_by_interface);
                match_registry_by_interface_unref(registry_by_interface);
        }

        c_assert(c_rbtree_is_empty(&registry->interface_tree));
}

/**
 * match_registry_flush() - flush all links in this registry
 * @registry:           registry to operate on
 *
 * This flushes all links in this registry. Usually, the match owner still
 * holds a reference, so the matches will likely stay around. The registry
 * object merely holds the remote links for fast lookup. Once those are
 * dropped, this registry object will no longer yield any results on lookup.
 *
 * Note that the match objects are not relinked by this function. Once you call
 * this, the match objects will be unlinked and thus cannot be yielded by
 * lookups anymore. Usually, you only want to call this when the owning object
 * of this registry goes away, and all the linked matches are meant to be
 * stale from this point on.
 */
void match_registry_flush(MatchRegistry *registry) {
        CRBTree *trees[] = {
                &registry->subscription_tree,
                &registry->monitor_tree,
        };
        MatchRegistryByPath *registry_by_path, *registry_by_path_safe;
        size_t i;

        for (i = 0; i < C_ARRAY_SIZE(trees); ++i) {
                c_rbtree_for_each_entry_safe(registry_by_path, registry_by_path_safe, trees[i], registry_node) {
                        match_registry_by_path_ref(registry_by_path);
                        match_registry_by_path_flush(registry_by_path);
                        match_registry_by_path_unref(registry_by_path);
                }

                c_assert(c_rbtree_is_empty(trees[i]));
        }
}
