/*
 * D-Bus Broker Main Entry
 */

#include <c-macro.h>
#include <getopt.h>
#include <stdlib.h>
#include "main.h"
#include "manager.h"

bool main_arg_verbose;

static void help(void) {
        printf("%s [GLOBALS...] ...\n\n"
               "Linux D-Bus Message Broker\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "  -v --verbose          Print progress to terminal\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
        };
        static const struct option options[] = {
                { "help",       no_argument,    NULL,   'h'             },
                { "version",    no_argument,    NULL,   ARG_VERSION     },
                { "verbose",    no_argument,    NULL,   'v'             },
                {}
        };
        int c;

        while ((c = getopt_long(argc, argv, "hv", options, NULL)) >= 0) {
                switch (c) {
                case 'h':
                        help();
                        return MAIN_EXIT;

                case ARG_VERSION:
                        printf("dbus-broker %d\n", PACKAGE_VERSION);
                        return MAIN_EXIT;

                case 'v':
                        main_arg_verbose = true;
                        break;

                case '?':
                        /* getopt_long() prints warning */
                        return MAIN_FAILED;

                default:
                        assert(0);
                        return -EINVAL;
                }
        }

        if (optind != argc) {
                fprintf(stderr, "%s: invalid arguments -- '%s'\n", program_invocation_name, argv[optind]);
                return MAIN_FAILED;
        }

        return 0;
}

static int run(void) {
        _c_cleanup_(manager_freep) Manager *manager = NULL;
        int r;

        r = manager_new(&manager);
        if (r)
                return r;

        return manager_run(manager);
}

int main(int argc, char **argv) {
        int r;

        r = parse_argv(argc, argv);
        if (r)
                goto exit;

        r = run();

exit:
        if (r < 0 && main_arg_verbose)
                fprintf(stderr, "Exiting due to fatal error: %d\n", r);
        return (r == 0 || r == MAIN_EXIT) ? 0 : 1;
}
