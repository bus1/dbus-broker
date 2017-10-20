/*
 * D-Bus Broker Main Entry
 */

#include <c-macro.h>
#include <getopt.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "broker/broker.h"
#include "broker/main.h"
#include "util/audit.h"
#include "util/error.h"
#include "util/selinux.h"

bool main_arg_audit = false;
int main_arg_controller = 3;
int main_arg_log = -1;
uint64_t main_arg_max_bytes = 16 * 1024 * 1024;
uint64_t main_arg_max_fds = 64;
uint64_t main_arg_max_matches = 10 * 1024;
uint64_t main_arg_max_objects = 10 * 1024;
bool main_arg_verbose = false;

static void help(void) {
        printf("%s [GLOBALS...] ...\n\n"
               "Linux D-Bus Message Broker\n\n"
               "  -h --help                     Show this help\n"
               "     --version                  Show package version\n"
               "  -v --verbose                  Print progress to terminal\n"
               "     --audit                    Log to the audit subsystem\n"
               "     --log FD                   Change log socket\n"
               "     --controller FD            Change controller file-descriptor\n"
               "     --max-bytes BYTES          The maximum number of bytes each user may own in the broker\n"
               "     --max-fds FDS              The maximum number of file descriptors each user may own in the broker\n"
               "     --max-matches MATCHES      The maximum number of match rules each user may own in the broker\n"
               "     --max-objects OBJECTS      The maximum total number of names, peers, pending replies, etc each user may own in the broker\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_AUDIT,
                ARG_CONTROLLER,
                ARG_LOG,
                ARG_MAX_BYTES,
                ARG_MAX_FDS,
                ARG_MAX_MATCHES,
                ARG_MAX_OBJECTS,
        };
        static const struct option options[] = {
                { "help",               no_argument,            NULL,   'h'                     },
                { "version",            no_argument,            NULL,   ARG_VERSION             },
                { "verbose",            no_argument,            NULL,   'v'                     },
                { "audit",              no_argument,            NULL,   ARG_AUDIT               },
                { "log",                required_argument,      NULL,   ARG_LOG                 },
                { "controller",         required_argument,      NULL,   ARG_CONTROLLER          },
                { "max-bytes",          required_argument,      NULL,   ARG_MAX_BYTES           },
                { "max-fds",            required_argument,      NULL,   ARG_MAX_FDS             },
                { "max-matches",        required_argument,      NULL,   ARG_MAX_MATCHES         },
                { "max-objects",        required_argument,      NULL,   ARG_MAX_OBJECTS         },
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

                case ARG_AUDIT:
                        main_arg_audit = true;
                        break;

                case ARG_LOG: {
                        unsigned long vul;
                        char *end;

                        errno = 0;
                        vul = strtoul(optarg, &end, 10);
                        if (errno != 0 || *end || optarg == end || vul > INT_MAX) {
                                fprintf(stderr, "%s: invalid log file-descriptor -- '%s'\n", program_invocation_name, optarg);
                                return MAIN_FAILED;
                        }

                        main_arg_log = vul;
                        break;
                }

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

                case ARG_MAX_BYTES: {
                        unsigned long long vul;
                        char *end;

                        errno = 0;
                        vul = strtoull(optarg, &end, 10);
                        if (errno != 0 || *end || optarg == end) {
                                fprintf(stderr, "%s: invalid max number of bytes -- '%s'\n", program_invocation_name, optarg);
                                return MAIN_FAILED;
                        }

                        main_arg_max_bytes = vul;
                        break;
                }

                case ARG_MAX_FDS: {
                        unsigned long long vul;
                        char *end;

                        errno = 0;
                        vul = strtoull(optarg, &end, 10);
                        if (errno != 0 || *end || optarg == end) {
                                fprintf(stderr, "%s: invalid max number of fds -- '%s'\n", program_invocation_name, optarg);
                                return MAIN_FAILED;
                        }

                        main_arg_max_fds = vul;
                        break;
                }

                case ARG_MAX_MATCHES: {
                        unsigned long long vul;
                        char *end;

                        errno = 0;
                        vul = strtoull(optarg, &end, 10);
                        if (errno != 0 || *end || optarg == end) {
                                fprintf(stderr, "%s: invalid max number of matches -- '%s'\n", program_invocation_name, optarg);
                                return MAIN_FAILED;
                        }

                        main_arg_max_matches = vul;
                        break;
                }

                case ARG_MAX_OBJECTS: {
                        unsigned long long vul;
                        char *end;

                        errno = 0;
                        vul = strtoull(optarg, &end, 10);
                        if (errno != 0 || *end || optarg == end) {
                                fprintf(stderr, "%s: invalid max number of objects -- '%s'\n", program_invocation_name, optarg);
                                return MAIN_FAILED;
                        }

                        main_arg_max_objects = vul;
                        break;
                }

                case '?':
                        /* getopt_long() prints warning */
                        return MAIN_FAILED;

                default:
                        return error_origin(-EINVAL);
                }
        }

        if (optind != argc) {
                fprintf(stderr, "%s: invalid arguments -- '%s'\n", program_invocation_name, argv[optind]);
                return MAIN_FAILED;
        }

        /*
         * Verify that the passed FDs exist. Preferably, we would not care
         * and simply fail later on. However, the FD-number might be
         * used by one of our other FDs (signalfd, epollfd, ...), and thus we
         * might trigger assertions on their behavior, which we better avoid.
         */

        /* verify log-fd is DGRAM or STREAM */
        if (main_arg_log >= 0) {
                socklen_t n;
                int v1, v2;

                n = sizeof(v1);
                r = getsockopt(main_arg_log, SOL_SOCKET, SO_DOMAIN, &v1, &n);
                n = sizeof(v2);
                r = r ?: getsockopt(main_arg_log, SOL_SOCKET, SO_TYPE, &v2, &n);

                if (r < 0) {
                        if (errno != EBADF && errno != ENOTSOCK)
                                return error_origin(-errno);

                        fprintf(stderr, "%s: log file-descriptor not a socket -- '%d'\n", program_invocation_name, main_arg_log);
                        return MAIN_FAILED;
                } else if (v1 != AF_UNIX || (v2 != SOCK_DGRAM && v2 != SOCK_STREAM)) {
                        fprintf(stderr, "%s: socket type of log file-descriptor not supported -- '%d'\n", program_invocation_name, main_arg_log);
                        return MAIN_FAILED;
                }
        }

        /* verify controller-fd is STREAM */
        {
                socklen_t n;
                int v1, v2;

                n = sizeof(v1);
                r = getsockopt(main_arg_controller, SOL_SOCKET, SO_DOMAIN, &v1, &n);
                n = sizeof(v2);
                r = r ?: getsockopt(main_arg_controller, SOL_SOCKET, SO_TYPE, &v2, &n);

                if (r < 0) {
                        if (errno != EBADF && errno != ENOTSOCK)
                                return error_origin(-errno);

                        fprintf(stderr, "%s: controller file-descriptor not a socket -- '%d'\n", program_invocation_name, main_arg_controller);
                        return MAIN_FAILED;
                } else if (v1 != AF_UNIX || v2 != SOCK_STREAM) {
                        fprintf(stderr, "%s: socket type of controller file-descriptor not supported -- '%d'\n", program_invocation_name, main_arg_controller);
                        return MAIN_FAILED;
                }
        }

        return 0;
}

static int run(void) {
        _c_cleanup_(broker_freep) Broker *broker = NULL;
        int r;

        r = broker_new(&broker, main_arg_log, main_arg_controller, main_arg_max_bytes, main_arg_max_fds, main_arg_max_matches, main_arg_max_objects);
        if (!r)
                r = broker_run(broker);

        return error_trace(r);
}

int main(int argc, char **argv) {
        int r;

        r = parse_argv(argc, argv);
        if (r)
                goto exit;

        if (main_arg_audit) {
                r = util_audit_init_global();
                if (r)
                        return error_fold(r);
        }

        r = bus_selinux_init_global();
        if (r)
                return error_fold(r);

        r = run();

exit:
        bus_selinux_deinit_global();
        util_audit_deinit_global();

        r = error_trace(r);
        if (r < 0 && main_arg_verbose)
                fprintf(stderr, "Exiting due to fatal error: %d\n", r);

        return (r == 0 || r == MAIN_EXIT) ? 0 : 1;
}
