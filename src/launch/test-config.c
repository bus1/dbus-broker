/*
 * Test Config Parser
 */

#include <c-list.h>
#include <c-macro.h>
#include <stdlib.h>
#include "launch/config.h"
#include "launch/nss-cache.h"
#include "util/dirwatch.h"

static const char *test_type2str[_CONFIG_NODE_N] = {
        [CONFIG_NODE_BUSCONFIG]         = "busconfig",
        [CONFIG_NODE_USER]              = "user",
        [CONFIG_NODE_TYPE]              = "type",
        [CONFIG_NODE_FORK]              = "fork",
        [CONFIG_NODE_SYSLOG]            = "syslog",
        [CONFIG_NODE_KEEP_UMASK]        = "keep_umask",
        [CONFIG_NODE_LISTEN]            = "listen",
        [CONFIG_NODE_PIDFILE]           = "pidfile",
        [CONFIG_NODE_INCLUDEDIR]        = "includedir",
        [CONFIG_NODE_STANDARD_SESSION_SERVICEDIRS] = "standard_session_servicedirs",
        [CONFIG_NODE_STANDARD_SYSTEM_SERVICEDIRS] = "standard_system_servicedirs",
        [CONFIG_NODE_SERVICEDIR]        = "servicedir",
        [CONFIG_NODE_SERVICEHELPER]     = "servicehelper",
        [CONFIG_NODE_AUTH]              = "auth",
        [CONFIG_NODE_INCLUDE]           = "include",
        [CONFIG_NODE_POLICY]            = "policy",
        [CONFIG_NODE_LIMIT]             = "limit",
        [CONFIG_NODE_SELINUX]           = "selinux",
        [CONFIG_NODE_APPARMOR]          = "apparmor",
        [CONFIG_NODE_ALLOW]             = "allow",
        [CONFIG_NODE_DENY]              = "deny",
        [CONFIG_NODE_ASSOCIATE]         = "associate",
};

static void print_config(const char *path) {
        _c_cleanup_(config_parser_deinit) ConfigParser parser = CONFIG_PARSER_NULL(parser);
        _c_cleanup_(config_root_freep) ConfigRoot *root = NULL;
        _c_cleanup_(nss_cache_deinit) NSSCache nss_cache = NSS_CACHE_INIT;
        _c_cleanup_(dirwatch_freep) Dirwatch *dirwatch = NULL;
        ConfigNode *i_node;
        int r;

        r = dirwatch_new(&dirwatch);
        assert(!r);

        config_parser_init(&parser);

        r = config_parser_read(&parser, &root, path, &nss_cache, dirwatch);
        assert(!r);

        c_list_for_each_entry(i_node, &root->node_list, root_link) {
                fprintf(stderr, "<%s>\n", test_type2str[i_node->type]);
        }
}

static void test_config(void) {
        _c_cleanup_(config_parser_deinit) ConfigParser parser = CONFIG_PARSER_NULL(parser);

        config_parser_init(&parser);
        config_parser_deinit(&parser);
}

int main(int argc, char **argv) {
        if (argc < 2)
                test_config();
        else
                print_config(argv[1]);

        return 0;
}
