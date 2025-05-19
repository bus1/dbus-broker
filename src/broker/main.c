/*
 * D-Bus Broker Main Entry
 */

#include <c-stdaux.h>
#include <getopt.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "broker/broker.h"
#include "broker/main.h"
#include "util/audit.h"
#include "util/error.h"
#include "util/log.h"
#include "util/selinux.h"
#include "util/string.h"

bool main_arg_audit = false;
int main_arg_controller = 3;
int main_arg_log = -1;
const char *main_arg_machine_id = NULL;
uint64_t main_arg_max_bytes = 512 * 1024 * 1024;
uint64_t main_arg_max_fds = 128;
uint64_t main_arg_max_matches = 16 * 1024;
uint64_t main_arg_max_objects = 16 * 1024 * 1024;

static void help(void) {
        printf("%s [GLOBALS...] ...\n\n"
               "Linux D-Bus Message Broker\n\n"
               "  -h --help                     Show this help\n"
               "     --version                  Show package version\n"
               "     --audit                    Log to the audit subsystem\n"
               "     --controller FD            Specify controller file-descriptor\n"
               "     --log FD                   Provide logging socket\n"
               "     --machine-id MACHINE_ID    Machine ID of the current machine\n"
               "     --max-bytes BYTES          Maximum number of bytes each user may allocate in the broker\n"
               "     --max-fds FDS              Maximum number of file descriptors each user may allocate in the broker\n"
               "     --max-matches MATCHES      Maximum number of match rules each user may allocate in the broker\n"
               "     --max-objects OBJECTS      Maximum total number of names, peers, pending replies, etc each user may allocate in the broker\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_AUDIT,
                ARG_CONTROLLER,
                ARG_LOG,
                ARG_MACHINE_ID,
                ARG_MAX_BYTES,
                ARG_MAX_FDS,
                ARG_MAX_MATCHES,
                ARG_MAX_OBJECTS,
        };
        static const struct option options[] = {
                { "help",               no_argument,            NULL,   'h'                     },
                { "version",            no_argument,            NULL,   ARG_VERSION             },
                { "audit",              no_argument,            NULL,   ARG_AUDIT               },
                { "controller",         required_argument,      NULL,   ARG_CONTROLLER          },
                { "log",                required_argument,      NULL,   ARG_LOG                 },
                { "machine-id",         required_argument,      NULL,   ARG_MACHINE_ID          },
                { "max-bytes",          required_argument,      NULL,   ARG_MAX_BYTES           },
                { "max-fds",            required_argument,      NULL,   ARG_MAX_FDS             },
                { "max-matches",        required_argument,      NULL,   ARG_MAX_MATCHES         },
                { "max-objects",        required_argument,      NULL,   ARG_MAX_OBJECTS         },
                {}
        };
        int r, c;

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {
                switch (c) {
                case 'h':
                        help();
                        return MAIN_EXIT;

                case ARG_VERSION:
                        printf("dbus-broker %d\n", PACKAGE_VERSION);
                        return MAIN_EXIT;

                case ARG_AUDIT:
                        main_arg_audit = true;
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

                case ARG_MACHINE_ID: {
                        if (strlen(optarg) != 32) {
                                fprintf(stderr, "%s: invalid machine ID -- '%s'\n", program_invocation_name, optarg);
                                return MAIN_FAILED;
                        }

                        main_arg_machine_id = optarg;
                        break;
                }

                case ARG_MAX_BYTES:
                        r = util_strtou64(&main_arg_max_bytes, optarg);
                        if (r) {
                                fprintf(stderr, "%s: invalid max number of bytes -- '%s'\n", program_invocation_name, optarg);
                                return MAIN_FAILED;
                        }

                        break;

                case ARG_MAX_FDS:
                        r = util_strtou64(&main_arg_max_fds, optarg);
                        if (r) {
                                fprintf(stderr, "%s: invalid max number of fds -- '%s'\n", program_invocation_name, optarg);
                                return MAIN_FAILED;
                        }

                        break;

                case ARG_MAX_MATCHES:
                        r = util_strtou64(&main_arg_max_matches, optarg);
                        if (r) {
                                fprintf(stderr, "%s: invalid max number of matches -- '%s'\n", program_invocation_name, optarg);
                                return MAIN_FAILED;
                        }

                        break;

                case ARG_MAX_OBJECTS:
                        r = util_strtou64(&main_arg_max_objects, optarg);
                        if (r) {
                                fprintf(stderr, "%s: invalid max number of objects -- '%s'\n", program_invocation_name, optarg);
                                return MAIN_FAILED;
                        }

                        break;

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

        /* verify that a machine ID was passed */
        {
                if (!main_arg_machine_id) {
                        fprintf(stderr, "%s: the machine ID argument is mandatory\n", program_invocation_name);
                        return MAIN_FAILED;
                }
        }

        return 0;
}

static int setup(Log *logp) {
        socklen_t z;
        int r, log_type;

        /*
         * We never spawn external applications from within the broker itself,
         * so clear the ambient set, as it is never needed. This is meant as
         * safety measure to guarantee our capabilities are not inherited by
         * possible exploits.
         */
        r = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
        if (r < 0)
                return error_origin(-errno);

        if (main_arg_log >= 0) {
                z = sizeof(log_type);
                r = getsockopt(main_arg_log, SOL_SOCKET, SO_TYPE, &log_type, &z);
                if (r < 0)
                        return error_origin(-errno);
        }

        if (main_arg_log < 0)
                log_init(logp);
        else if (log_type == SOCK_STREAM)
                log_init_stderr(logp, main_arg_log);
        else if (log_type == SOCK_DGRAM)
                log_init_journal(logp, main_arg_log);
        else
                return error_origin(-ENOTRECOVERABLE);

        /* XXX: make this run-time optional */
        log_set_lossy(logp, true);

        return 0;
}

static int run(Log *log) {
        _c_cleanup_(broker_freep) Broker *broker = NULL;
        int r;

        r = broker_new(&broker, log, main_arg_machine_id, main_arg_controller, main_arg_max_bytes, main_arg_max_fds, main_arg_max_matches, main_arg_max_objects);
        if (!r)
                r = broker_run(broker);

        return error_trace(r);
}

int main(int argc, char **argv) {
        Log log = LOG_NULL;
        int r;

        r = parse_argv(argc, argv);
        if (r)
                goto exit;

        r = setup(&log);
        if (r)
                goto exit;

        if (main_arg_audit) {
                r = util_audit_init_global();
                if (r) {
                        r = error_fold(r);
                        goto exit;
                }
        }

        r = bus_selinux_init_global(&log);
        if (r) {
                r = error_fold(r);
                goto exit;
        }

        r = run(&log);

exit:
        bus_selinux_deinit_global();
        util_audit_deinit_global();
        log_deinit(&log);

        r = error_trace(r);
        return (r == 0 || r == MAIN_EXIT) ? 0 : 1;
}
