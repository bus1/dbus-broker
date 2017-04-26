/*
 * D-Bus Broker Main Entry
 */

#include <c-macro.h>
#include <getopt.h>
#include <limits.h>
#include <stdlib.h>
#include "main.h"
#include "manager.h"

int main_arg_controller = 3;
bool main_arg_verbose = false;

static void help(void) {
        printf("%s [GLOBALS...] ...\n\n"
               "Linux D-Bus Message Broker\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "  -v --verbose          Print progress to terminal\n"
               "     --controller FD    Change controller file-descriptor\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_CONTROLLER,
        };
        static const struct option options[] = {
                { "help",               no_argument,            NULL,   'h'                     },
                { "version",            no_argument,            NULL,   ARG_VERSION             },
                { "verbose",            no_argument,            NULL,   'v'                     },
                { "controller",         required_argument,      NULL,   ARG_CONTROLLER          },
                {}
        };
        int r, c;

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

                case ARG_CONTROLLER: {
                        unsigned long vul;
                        char *end;

                        errno = 0;
                        vul = strtoul(optarg, &end, 10);
                        if (errno != 0 || *end || optarg == end || vul > INT_MAX) {
                                fprintf(stderr, "%s: invalid controller file-descriptor -- '%s'\n", program_invocation_name, optarg);
                                return MAIN_FAILED;
                        }

                        main_arg_controller = vul;
                        break;
                }

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

        /*
         * Verify that the controller-fd exists. Preferably, we would not care
         * and simply fail when it is used. However, the FD-number might be
         * used by one of our other FDs (signalfd, epollfd, ...), and thus we
         * might trigger assertions on their behavior, which we better avoid.
         */
        {
                char path[sizeof("/proc/self/fd/") + C_DECIMAL_MAX(int)];

                r = snprintf(path, sizeof(path), "/proc/self/fd/%d", main_arg_controller);
                assert(r < sizeof(path));

                r = access(path, F_OK);
                if (r < 0) {
                        fprintf(stderr, "%s: bad controller file-descriptor -- '%d'\n", program_invocation_name, main_arg_controller);
                        return MAIN_FAILED;
                }
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
