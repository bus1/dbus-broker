/*
 * D-Bus Policy Parser
 */

#include <c-macro.h>
#include <c-rbtree.h>
#include <expat.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include "dbus/protocol.h"
#include "name.h"
#include "policy.h"
#include "policy-parser.h"
#include "util/error.h"

#define POLICY_PRIORITY_INCREMENT       (((uint64_t)-1) / 5)
#define POLICY_PRIORITY_BASE_DEFAULT    (POLICY_PRIORITY_INCREMENT * 0)
#define POLICY_PRIORITY_BASE_USER       (POLICY_PRIORITY_INCREMENT * 1)
#define POLICY_PRIORITY_BASE_GROUP      (POLICY_PRIORITY_INCREMENT * 2)
#define POLICY_PRIORITY_BASE_CONSOLE    (POLICY_PRIORITY_INCREMENT * 3)
#define POLICY_PRIORITY_BASE_MANDATORY  (POLICY_PRIORITY_INCREMENT * 4)

typedef struct PolicyParser PolicyParser;

struct PolicyParser {
        PolicyParserRegistry *registry;
        PolicyParser *parent;
        XML_Parser parser;
        const char *filename;
        bool busconfig;
        bool includedir;
        char characterdata[PATH_MAX + 1];
        size_t n_characterdata;
        size_t level;

        Policy *policy;
        uint64_t priority;
        uint64_t priority_base;
};

#define POLICY_PARSER_NULL {                            \
                .priority_base = (uint64_t) -1,         \
        }

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

                r = policy_parser_registry_from_file(parent->registry, filename, parent);
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

                if (!strcmp(*attributes, "default")) {
                        parser->policy = &parser->registry->default_policy;
                        parser->priority_base = POLICY_PRIORITY_BASE_DEFAULT;
                } else if (!strcmp(*attributes, "mandatory")) {
                        parser->policy = &parser->registry->mandatory_policy;
                        parser->priority_base = POLICY_PRIORITY_BASE_MANDATORY;
                } else {
                        goto error;
                }
        } else if (!strcmp(*attributes, "user")) {
                struct passwd *passwd;

                if (!*(++attributes))
                        goto error;

                passwd = getpwnam(*attributes);
                if (!passwd)
                        return error_origin(-errno);

                r = policy_registry_get_policy_by_uid(&parser->registry->registry, &parser->policy, passwd->pw_uid);
                if (r)
                        return error_trace(r);

                parser->priority_base = POLICY_PRIORITY_BASE_USER;
        } else if (!strcmp(*attributes, "group")) {
                struct group *group;

                if (!*(++attributes))
                        goto error;

                group = getgrnam(*attributes);
                if (!group)
                        return error_origin(-errno);

                r = policy_registry_get_policy_by_gid(&parser->registry->registry, &parser->policy, group->gr_gid);
                if (r)
                        return error_trace(r);

                parser->priority_base = POLICY_PRIORITY_BASE_GROUP;
        } else if (!strcmp(*attributes, "at_console")) {
                if (!*(++attributes))
                        goto error;

                if (!strcmp(*attributes, "true")) {
                        parser->policy = NULL;
                        parser->priority_base = (uint64_t)-1;
                } else if (!strcmp(*attributes, "false")) {
                        parser->policy = &parser->registry->console_policy;
                        parser->priority_base = POLICY_PRIORITY_BASE_CONSOLE;
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
                                r = ownership_policy_set_wildcard(&parser->policy->ownership_policy, deny,
                                                                  parser->priority_base + parser->priority ++);
                                if (r)
                                        return error_trace(r);
                        } else {
                                r = ownership_policy_add_name(&parser->policy->ownership_policy, value, deny,
                                                              parser->priority_base + parser->priority ++);
                                if (r)
                                        return error_trace(r);
                        }
                        continue;
                } else if (!strcmp(key, "own_prefix")) {
                        r = ownership_policy_add_prefix(&parser->policy->ownership_policy, value, deny,
                                                        parser->priority_base + parser->priority ++);
                        if (r)
                                return error_trace(r);
                        continue;
                } else if (!strcmp(key, "user")) {
                        if (!strcmp(value, "*")) {
                                r = connection_policy_set_wildcard(&parser->registry->registry.connection_policy, deny,
                                                                   parser->priority_base + parser->priority ++);
                                if (r)
                                        return error_trace(r);
                        } else {
                                struct passwd *passwd;

                                passwd = getpwnam(value);
                                if (!passwd)
                                        return error_origin(-errno);

                                r = connection_policy_add_uid(&parser->registry->registry.connection_policy, passwd->pw_uid, deny,
                                                              parser->priority_base + parser->priority ++);
                                if (r)
                                        return error_trace(r);
                        }
                        continue;
                } else if (!strcmp(key, "group")) {
                        if (!strcmp(value, "*")) {
                                r = connection_policy_set_wildcard(&parser->registry->registry.connection_policy, deny,
                                                                   parser->priority_base + parser->priority ++);
                                if (r)
                                        return error_trace(r);
                        } else {
                                struct group *group;

                                group = getgrnam(value);
                                if (!group)
                                        return error_origin(-errno);

                                r = connection_policy_add_gid(&parser->registry->registry.connection_policy, group->gr_gid, deny,
                                                              parser->priority_base + parser->priority ++);
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
                r = transmission_policy_add_entry(transmission_policy, name, interface, member, path, type, deny,
                                                  parser->priority_base + parser->priority ++);
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

static void policy_parser_init(PolicyParser *parser, PolicyParserRegistry *registry, PolicyParser *parent, const char *filename) {
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

static int policy_parser_registry_init(PolicyParserRegistry *registry) {
        int r;

        *registry = (PolicyParserRegistry)POLICY_PARSER_REGISTRY_NULL(*registry);

        r = policy_registry_init(&registry->registry);
        if (r)
                return error_trace(r);

        return 0;
}

int policy_parser_registry_from_file(PolicyParserRegistry *registry, const char *filename, PolicyParser *parent) {
        _c_cleanup_(policy_parser_deinit) PolicyParser parser = (PolicyParser)POLICY_PARSER_NULL;
        _c_cleanup_(c_fclosep) FILE *file = NULL;
        char buffer[1024];
        size_t len;
        int r;

        if (filename[0] == '\0')
                return 0;

        for (PolicyParser *p = parent; p; p = p->parent)
                if (!strcmp(p->filename, filename))
                        return POLICY_PARSER_E_CIRCULAR_INCLUDE;

        file = fopen(filename, "r");
        if (!file) {
                if (errno == ENOENT)
                        return 0;

                return error_origin(-errno);
        }

        r = policy_parser_registry_init(registry);
        if (r)
                return error_trace(r);

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

        return 0;
error:
        fprintf(stderr, "%s +%lu: %s\n",
                parser.filename,
                XML_GetCurrentLineNumber(parser.parser),
                XML_ErrorString(XML_GetErrorCode(parser.parser)));
        return POLICY_PARSER_E_INVALID_XML;
}

void policy_parser_registry_deinit(PolicyParserRegistry *registry) {
        policy_deinit(&registry->mandatory_policy);
        policy_deinit(&registry->console_policy);
        policy_registry_deinit(&registry->registry);
        policy_deinit(&registry->default_policy);
}
