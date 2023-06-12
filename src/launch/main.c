/*
 * D-Bus Broker Launch Main Entry
 */

#include <c-stdaux.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-bus.h>
#include "launch/launcher.h"
#include "util/error.h"
#include "util/proc.h"

enum {
        _MAIN_SUCCESS,
        MAIN_EXIT,
        MAIN_FAILED,
};

static bool             main_arg_audit = false;
static const char *     main_arg_configfile = NULL;
static bool             main_arg_user_scope = false;
static int              main_fd_listen = -1;
static bool             main_arg_cmd_reexec = false;
static int              main_arg_controller_fd = 0;
static pid_t            main_arg_broker_pid = -1;

static void help(void) {
        printf("%s [GLOBALS...] ...\n\n"
               "Linux D-Bus Message Broker Launcher\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "     --audit            Enable audit support\n"
               "     --config-file PATH Specify path to configuration file\n"
               "     --scope SCOPE      Scope of message bus\n"
               "     --reexec           Restart dbus with peers connected\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_VERBOSE,
                ARG_AUDIT,
                ARG_CONFIG,
                ARG_SCOPE,
                ARG_CONTROLLER_FD,
                ARG_BROKER_PID,
                ARG_REEXEC,
        };
        static const struct option options[] = {
                { "help",               no_argument,            NULL,   'h'                     },
                { "version",            no_argument,            NULL,   ARG_VERSION             },
                { "verbose",            no_argument,            NULL,   ARG_VERBOSE             },
                { "audit",              no_argument,            NULL,   ARG_AUDIT               },
                { "config-file",        required_argument,      NULL,   ARG_CONFIG              },
                { "scope",              required_argument,      NULL,   ARG_SCOPE               },
                { "controller-fd",      required_argument,      NULL,   ARG_CONTROLLER_FD       },
                { "broker-pid",         required_argument,      NULL,   ARG_BROKER_PID          },
                { "reexec",             no_argument,            NULL,   ARG_REEXEC              },
                {}
        };
        int c;

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {
                switch (c) {
                case 'h':
                        help();
                        return MAIN_EXIT;

                case ARG_VERSION:
                        printf("dbus-broker-launch %d\n", PACKAGE_VERSION);
                        return MAIN_EXIT;

                /* noop for backward compatibility */
                case ARG_VERBOSE:
                        break;

                case ARG_AUDIT:
                        main_arg_audit = true;
                        break;

                case ARG_CONFIG:
                        main_arg_configfile = optarg;
                        break;

                case ARG_SCOPE:
                        if (!strcmp(optarg, "system")) {
                                main_arg_user_scope = false;
                        } else if (!strcmp(optarg, "user")) {
                                main_arg_user_scope = true;
                        } else {
                                fprintf(stderr, "%s: invalid message bus scope -- '%s'\n", program_invocation_name, optarg);
                                return MAIN_FAILED;
                        }
                        break;

                case ARG_CONTROLLER_FD: {
                        unsigned long vul;
                        char *end;

                        errno = 0;
                        vul = strtoul(optarg, &end, 10);
                        if (errno != 0 || *end || optarg == end || vul > INT_MAX) {
                                fprintf(stderr, "%s: invalid controller fd -- '%s'\n", program_invocation_name, optarg);
                                return MAIN_FAILED;
                        }

                        main_arg_controller_fd = vul;
                        break;
                }

                case ARG_BROKER_PID: {
                        unsigned long vul;
                        char *end;

                        errno = 0;
                        vul = strtoul(optarg, &end, 10);
                        if (errno != 0 || *end || optarg == end || vul > INT_MAX) {
                                fprintf(stderr, "%s: invalid broker pid -- '%s'\n", program_invocation_name, optarg);
                                return MAIN_FAILED;
                        }

                        main_arg_broker_pid = (pid_t) vul;
                        break;
                }

                case ARG_REEXEC:
                        main_arg_cmd_reexec = true;
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

        return 0;
}

static int inherit_fds(void) {
        int s, r, n;

        n = sd_listen_fds(true);
        if (n < 0)
                return error_origin(n);

        if (n == 0) {
                fprintf(stderr, "No listener socket inherited\n");
                return MAIN_FAILED;
        }
        if (n > 1) {
                fprintf(stderr, "More than one listener socket passed\n");
                return MAIN_FAILED;
        }

        s = SD_LISTEN_FDS_START;

        r = sd_is_socket(s, PF_UNIX, SOCK_STREAM, 1);
        if (r < 0)
                return error_origin(r);

        if (!r) {
                fprintf(stderr, "Non unix-domain-socket passed as listener\n");
                return MAIN_FAILED;
        }

        r = fcntl(s, F_GETFL);
        if (r < 0)
                return error_origin(-errno);

        r = fcntl(s, F_SETFL, r | O_NONBLOCK);
        if (r < 0)
                return error_origin(-errno);

        main_fd_listen = s;
        return 0;
}

static int run(void) {
        _c_cleanup_(launcher_freep) Launcher *launcher = NULL;
        int r;

        r = launcher_new(&launcher, main_fd_listen, main_arg_audit, main_arg_configfile,
                         main_arg_user_scope, main_arg_controller_fd, main_arg_broker_pid);
        if (r)
                return error_fold(r);

        r = launcher_run(launcher);
        return error_fold(r);
}

static int ready_signal_dispatch(sd_bus_message *message, void *userdata, sd_bus_error *errorp) {
        int *reexec_ready = (int *) userdata;
        *reexec_ready = 1;
        return 0;
}

static int trigger_reexecute(void) {
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r, reexec_ready = 0;

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_match_signal(bus, NULL, NULL, "/org/bus1/DBus/Controller",
                                "org.bus1.DBus.Controller",
                                "Ready",
                                ready_signal_dispatch,
                                &reexec_ready);
        if (r < 0) {
                fprintf(stderr, "Failed to add match signal: %s\n", strerror(-r));
                goto finish;
        }

        r = sd_bus_message_new_method_call(bus, &m, "org.freedesktop.DBus",
                                           "/org/freedesktop/DBus",
                                           "org.freedesktop.DBus",
                                           "Reexecute");
        if (r < 0)
                return error_origin(r);

        r = sd_bus_call(bus, m, 0, &error, NULL);

        if (r < 0) {
                fprintf(stderr, "Failed to reexecute dbus-broker due to fatal error: %s\n", strerror(-r));
                goto finish;
        }

        for (;;) {
                r = sd_bus_process(bus, NULL);
                if (r < 0) {
                        fprintf(stderr, "Failed to process bus: %s\n", strerror(-r));
                        goto finish;
                }

                if (reexec_ready)
                        break;

                if (r > 0)
                        continue;

                r = sd_bus_wait(bus, (uint64_t) -1);
                if (r < 0) {
                        fprintf(stderr, "Failed to wait on bus: %s\n", strerror(-r));
                        goto finish;
                }
        }

        r = 0;
finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

int main(int argc, char **argv) {
        sigset_t mask_new, mask_old;
        int r;

        r = parse_argv(argc, argv);
        if (r)
                goto exit;

        if (main_arg_cmd_reexec)
                return trigger_reexecute();

        r = inherit_fds();
        if (r)
                goto exit;

        sigemptyset(&mask_new);
        sigaddset(&mask_new, SIGCHLD);
        sigaddset(&mask_new, SIGTERM);
        sigaddset(&mask_new, SIGINT);
        sigaddset(&mask_new, SIGHUP);

        sigprocmask(SIG_BLOCK, &mask_new, &mask_old);
        r = run();
        sigprocmask(SIG_SETMASK, &mask_old, NULL);

exit:
        r = error_trace(r);
        if (r < 0)
                fprintf(stderr, "Exiting due to fatal error: %d\n", r);
        return (r == 0 || r == MAIN_EXIT) ? 0 : 1;
}
