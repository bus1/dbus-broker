/*
 * D-Bus Policy
 */

#include <c-macro.h>
#include <c-rbtree.h>
#include <expat.h>
#include <stdlib.h>
#include "policy.h"
#include "util/error.h"

typedef struct PolicyParser PolicyParser;

struct PolicyParser {
        XML_Parser parser;
        const char *filename;
        int level;
        bool needs_linebreak;
};

#define POLICY_PARSER_NULL {}

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

int connection_policy_set_uid_wildcard(ConnectionPolicy *policy, bool deny, uint64_t priority) {
        if (policy->uid_wildcard.priority > priority)
                return 0;

        policy->uid_wildcard.deny = deny;
        policy->uid_wildcard.priority = priority;

        return 0;
}

int connection_policy_set_gid_wildcard(ConnectionPolicy *policy, bool deny, uint64_t priority) {
        if (policy->gid_wildcard.priority > priority)
                return 0;

        policy->gid_wildcard.deny = deny;
        policy->gid_wildcard.priority = priority;

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

int connection_policy_check_allowed(ConnectionPolicy *policy, uid_t uid) {
        PolicyDecision decision;

        if (policy->uid_wildcard.priority > policy->gid_wildcard.priority)
                decision = policy->uid_wildcard;
        else
                decision = policy->gid_wildcard;

        connection_policy_update_decision(&policy->uid_tree, uid, &decision);

        /* XXX: check the groups too */

        return decision.deny ? POLICY_E_ACCESS_DENIED : 0;
}

/* parser */
static void policy_parser_handler_policy(PolicyParser *parser, const XML_Char **attributes) {
        if (parser->needs_linebreak)
                fprintf(stderr, "\n");

        fprintf(stderr, "<policy");

        while (*attributes) {
                fprintf(stderr, " %s", *(attributes++));
                fprintf(stderr, "=%s", *(attributes++));
        }

        fprintf(stderr, ">\n");

        parser->needs_linebreak = false;
}

static void policy_parser_handler_deny(PolicyParser *parser, const XML_Char **attributes) {
        if (parser->needs_linebreak)
                fprintf(stderr, "\n");

        fprintf(stderr, "    DENY:\n");

        while (*attributes) {
                fprintf(stderr, "        %s", *(attributes++));
                fprintf(stderr, "=%s\n", *(attributes++));
        }

        parser->needs_linebreak = true;
}

static void policy_parser_handler_allow(PolicyParser *parser, const XML_Char **attributes) {
        if (parser->needs_linebreak)
                fprintf(stderr, "\n");

        fprintf(stderr, "    ALLOW:\n");

        while (*attributes) {
                fprintf(stderr, "        %s", *(attributes++));
                fprintf(stderr, "=%s\n", *(attributes++));
        }

        parser->needs_linebreak = true;
}

static void policy_parser_handler_start(void *userdata, const XML_Char *name, const XML_Char **attributes) {
        PolicyParser *parser = userdata;

        switch (parser->level++) {
                case 1:
                        if (!strcmp(name, "policy"))
                                policy_parser_handler_policy(parser, attributes);
                        break;
                case 2:
                        if (!strcmp(name, "deny"))
                                policy_parser_handler_deny(parser, attributes);
                        else if (!strcmp(name, "allow"))
                                policy_parser_handler_allow(parser, attributes);
                        break;
                default:
                        break;
        }
}

static void policy_parser_handler_end(void *userdata, const XML_Char *name) {
        PolicyParser *parser = userdata;

        if (--parser->level == 1 &&
            !strcmp(name, "policy")) {
                fprintf(stderr, "</policy>\n");
                parser->needs_linebreak = true;
        }
}

static void policy_parser_init(PolicyParser *parser) {
        parser->parser = XML_ParserCreate(NULL);
        XML_SetUserData(parser->parser, parser);
        XML_SetElementHandler(parser->parser, policy_parser_handler_start, policy_parser_handler_end);
}

static void policy_parser_deinit(PolicyParser *parser) {
        XML_ParserFree(parser->parser);
        *parser = (PolicyParser)POLICY_PARSER_NULL;
}

static int policy_parser_parse_file(PolicyParser *parser, const char *filename) {
        _c_cleanup_(c_fclosep) FILE *file = NULL;
        char buffer[1024];
        size_t len;
        int r;

        file = fopen(filename, "r");
        if (!file)
                return error_origin(-EIO);

        parser->filename = filename;

        do {
                len = fread(buffer, sizeof(char), sizeof(buffer), file);
                if (!len && ferror(file))
                        return error_origin(-EIO);

                r = XML_Parse(parser->parser, buffer, len, XML_FALSE);
                if (r != XML_STATUS_OK)
                        return POLICY_E_INVALID_XML;
        } while (len == sizeof(buffer));

        return 0;
}

static int policy_parser_finalize(PolicyParser *parser) {
        int r;

        r = XML_Parse(parser->parser, NULL, 0, XML_TRUE);
        if (r != XML_STATUS_OK)
                return POLICY_E_INVALID_XML;

        return 0;
}

static void policy_print_parsing_error(PolicyParser *parser) {
        fprintf(stderr, "%s +%lu: %s\n",
                parser->filename,
                XML_GetCurrentLineNumber(parser->parser),
                XML_ErrorString(XML_GetErrorCode(parser->parser)));
}

int policy_parse(void) {
        PolicyParser parser = (PolicyParser)POLICY_PARSER_NULL;
        /* XXX: only makes sense for the system bus */
        const char *filename = "/usr/share/dbus-1/system.conf";
        int r;

        policy_parser_init(&parser);

        r = policy_parser_parse_file(&parser, filename);
        if (r) {
                if (r == POLICY_E_INVALID_XML)
                        policy_print_parsing_error(&parser);
                else
                        return error_fold(r);
        }

        r = policy_parser_finalize(&parser);
        if (r) {
                if (r == POLICY_E_INVALID_XML)
                        policy_print_parsing_error(&parser);
                else
                        return error_fold(r);
        }

        policy_parser_deinit(&parser);

        return 0;
}
