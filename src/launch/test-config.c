/*
 * Test Config Parser
 */

#undef NDEBUG
#include <c-list.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include "launch/config.h"
#include "launch/nss-cache.h"
#include "util/dirwatch.h"
#include "util/misc.h"

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
        [CONFIG_NODE_USER_QUOTA]        = "user_quota",
};

static int config_memfd(const char *data) {
        ssize_t n;
        int fd;

        fd = misc_memfd("dbus-broker-test-config", MISC_MFD_NOEXEC_SEAL, 0);
        c_assert(fd >= 0);
        n = write(fd, data, strlen(data));
        c_assert(n == (ssize_t)strlen(data));

        return fd;
}

static int parse_config(ConfigRoot **rootp, const char *path) {
        _c_cleanup_(config_parser_deinit) ConfigParser parser = CONFIG_PARSER_NULL(parser);
        _c_cleanup_(config_root_freep) ConfigRoot *root = NULL;
        _c_cleanup_(nss_cache_deinit) NSSCache nss_cache = NSS_CACHE_INIT;
        _c_cleanup_(dirwatch_freep) Dirwatch *dirwatch = NULL;
        int r;

        r = dirwatch_new(&dirwatch);
        c_assert(!r);

        config_parser_init(&parser);

        r = config_parser_read(&parser, &root, path, &nss_cache, dirwatch);
        if (r)
                return r;

        *rootp = root;
        root = NULL;
        return 0;
}

static int parse_config_inline(ConfigRoot **rootp, const char *data) {
        _c_cleanup_(c_closep) int fd = -1;
        _c_cleanup_(c_freep) char *path = NULL;
        int r;

        fd = config_memfd(data);
        r = asprintf(&path, "/proc/self/fd/%d", fd);
        c_assert(r > 0);

        return parse_config(rootp, path);
}

static void print_config(const char *path) {
        _c_cleanup_(config_root_freep) ConfigRoot *root = NULL;
        ConfigNode *i_node;
        int r;

        r = parse_config(&root, path);
        c_assert(!r);

        c_list_for_each_entry(i_node, &root->node_list, root_link) {
                fprintf(stderr, "<%s>\n", test_type2str[i_node->type]);
        }
}

static void test_config_base(void) {
        _c_cleanup_(config_parser_deinit) ConfigParser parser = CONFIG_PARSER_NULL(parser);

        config_parser_init(&parser);
        config_parser_deinit(&parser);
}

static void test_config_sample0(void) {
        _c_cleanup_(config_root_freep) ConfigRoot *root = NULL;
        const char *data;
        int r;

        data =
"<?xml version=\"1.0\"?> <!--*-nxml-*-->\
<!DOCTYPE g PUBLIC \"-/N\"\
	\"htt\">\
<busconfig>\
	<policy user=\"root\">\
		<allow own_prefix=\"oramd\"/>\
		<allow send_interface=\"d\"/>\
	</policy>\
		<user ix=\"d\"/>\
	</cy>";

        r = parse_config_inline(&root, data);
        c_assert(r == CONFIG_E_INVALID);
}

static void test_config_sample1(void) {
        _c_cleanup_(config_root_freep) ConfigRoot *root = NULL;
        const char *data;
        int r;

        data =
"<?xml version=\"1.0\"?> <!--*-nxml-*-->\
<!DOCTYPE g PUBLIC \"-/N\"\
	\"htt\">\
<busconfig>\
	<policy user=\"root\">\
		<allow own_prefix=\"oramd\"/>\
		<allow send_interface=\"d\"/>\
	</policy>\
	<policy context=\"default\"/>		<user ix=\"d\"/>\
	</policy>\
</busconfig>";

        r = parse_config_inline(&root, data);
        c_assert(r == CONFIG_E_INVALID);
}

static void test_config_user_quota(void) {
        _c_cleanup_(config_root_freep) ConfigRoot *root = NULL;
        ConfigNode *node;
        const char *data;
        bool found_quota = false;
        int r;

        /* Valid user_quota element for root (uid 0, always resolvable). */
        data =
"<?xml version=\"1.0\"?>\
<busconfig>\
  <user_quota user=\"root\" max_bytes=\"10485760\" max_fds=\"256\" max_matches=\"2048\" max_objects=\"4096\"/>\
</busconfig>";

        r = parse_config_inline(&root, data);
        c_assert(!r);

        c_list_for_each_entry(node, &root->node_list, root_link) {
                if (node->type != CONFIG_NODE_USER_QUOTA)
                        continue;

                /* root UID is always 0 and resolvable */
                c_assert(node->user_quota.uid_valid);
                c_assert(node->user_quota.uid == 0);
                c_assert(node->user_quota.max_bytes == 10485760);
                c_assert(node->user_quota.max_fds == 256);
                c_assert(node->user_quota.max_matches == 2048);
                c_assert(node->user_quota.max_objects == 4096);
                found_quota = true;
        }

        c_assert(found_quota);
        config_root_free(root);
        root = NULL;

        /* Multiple user_quota elements are all collected. */
        data =
"<?xml version=\"1.0\"?>\
<busconfig>\
  <user_quota user=\"root\" max_bytes=\"1024\" max_fds=\"16\" max_matches=\"128\" max_objects=\"256\"/>\
  <user_quota user=\"root\" max_bytes=\"2048\" max_fds=\"32\" max_matches=\"256\" max_objects=\"512\"/>\
</busconfig>";

        r = parse_config_inline(&root, data);
        c_assert(!r);

        {
                unsigned int n_quota = 0;
                c_list_for_each_entry(node, &root->node_list, root_link) {
                        if (node->type == CONFIG_NODE_USER_QUOTA)
                                ++n_quota;
                }
                c_assert(n_quota == 2);
        }

        config_root_free(root);
        root = NULL;

        /* Unknown user resolves with uid_valid=false but does not fail the parse. */
        data =
"<?xml version=\"1.0\"?>\
<busconfig>\
  <user_quota user=\"no-such-user-xyz\" max_bytes=\"1024\" max_fds=\"16\" max_matches=\"128\" max_objects=\"256\"/>\
</busconfig>";

        r = parse_config_inline(&root, data);
        c_assert(!r);

        c_list_for_each_entry(node, &root->node_list, root_link) {
                if (node->type != CONFIG_NODE_USER_QUOTA)
                        continue;

                c_assert(!node->user_quota.uid_valid);
        }
}

int main(int argc, char **argv) {
        if (argc > 1) {
                print_config(argv[1]);
                return 0;
        }

        test_config_base();
        test_config_sample0();
        test_config_sample1();
        test_config_user_quota();

        return 0;
}
