/*
 * D-Bus Broker Launch Main Entry
 */

#include <c-stdaux.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <systemd/sd-daemon.h>
#include "launch/launcher.h"
#include "util/error.h"
#include "util/misc.h"
#include "util/string.h"

enum {
        _MAIN_SUCCESS,
        MAIN_EXIT,
        MAIN_FAILED,
};

static bool             main_arg_audit = false;
static const char *     main_arg_configfile = NULL;
static bool             main_arg_user_scope = false;
static int              main_fd_listen = -1;
static int              main_fd_metrics = -1;

static void help(void) {
        printf("%s [GLOBALS...] ...\n\n"
               "Linux D-Bus Message Broker Launcher\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "     --audit            Enable audit support\n"
               "     --config-file PATH Specify path to configuration file\n"
               "     --scope SCOPE      Scope of message bus\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_VERBOSE,
                ARG_AUDIT,
                ARG_CONFIG,
                ARG_SCOPE,
        };
        static const struct option options[] = {
                { "help",               no_argument,            NULL,   'h'                     },
                { "version",            no_argument,            NULL,   ARG_VERSION             },
                { "verbose",            no_argument,            NULL,   ARG_VERBOSE             },
                { "audit",              no_argument,            NULL,   ARG_AUDIT               },
                { "config-file",        required_argument,      NULL,   ARG_CONFIG,             },
                { "scope",              required_argument,      NULL,   ARG_SCOPE               },
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
        _c_cleanup_(misc_vfreep) char **names = NULL;
        size_t i, n;
        int r, fd;
        char *name;

        r = sd_listen_fds_with_names(true, &names);
        if (r < 0)
                return error_origin(r);
        n = r;

        for (i = 0; i < n; ++i) {
                fd = SD_LISTEN_FDS_START + i;
                name = names[i];

                if (string_equal(name, "dbus.socket")) {
                        if (main_fd_listen >= 0) {
                                fprintf(stderr, "Ignoring additional inherited listener socket #%d (%s)\n", fd, name);
                                c_close(fd);
                                continue;
                        }

                        r = sd_is_socket(fd, PF_UNIX, SOCK_STREAM, 1);
                        if (r < 0)
                                return error_origin(r);

                        if (!r) {
                                fprintf(stderr, "Ignoring inherited non-unix listener socket #%d (%s)\n", fd, name);
                                c_close(fd);
                                continue;
                        }

                        r = fcntl(fd, F_GETFL);
                        if (r < 0)
                                return error_origin(-errno);

                        r = fcntl(fd, F_SETFL, r | O_NONBLOCK);
                        if (r < 0)
                                return error_origin(-errno);

                        main_fd_listen = fd;
                } else if (string_equal(name, "dbus-metrics.socket")) {
                        if (main_fd_metrics >= 0) {
                                fprintf(stderr, "Ignoring additional inherited metrics socket #%d (%s)\n", fd, name);
                                c_close(fd);
                                continue;
                        }

                        r = sd_is_socket(fd, PF_UNIX, SOCK_STREAM, 1);
                        if (r < 0)
                                return error_origin(r);

                        if (!r) {
                                fprintf(stderr, "Ignoring inherited non-unix metrics socket #%d (%s)\n", fd, name);
                                c_close(fd);
                                continue;
                        }

                        r = fcntl(fd, F_GETFL);
                        if (r < 0)
                                return error_origin(-errno);

                        r = fcntl(fd, F_SETFL, r | O_NONBLOCK);
                        if (r < 0)
                                return error_origin(-errno);

                        main_fd_metrics = fd;
                } else {
                        /*
                         * Close any FDs we get passed but do not recognize.
                         * This can happen on live downgrades, if the newer
                         * version used the FD store of systemd, or added new
                         * socket units.
                         */
                        fprintf(stderr, "Ignoring unknown inherited file-descriptor #%d (%s)\n", fd, name);
                        c_close(fd);
                }
        }

        if (main_fd_listen < 0) {
                fprintf(stderr, "No suitable listener socket inherited\n");
                return MAIN_FAILED;
        }

        return 0;
}

static int run(void) {
        _c_cleanup_(launcher_freep) Launcher *launcher = NULL;
        int r;

        r = launcher_new(
                &launcher,
                main_fd_listen,
                main_fd_metrics,
                main_arg_audit,
                main_arg_configfile,
                main_arg_user_scope
        );
        if (r)
                return error_fold(r);

        r = launcher_run(launcher);
        return error_fold(r);
}

int main(int argc, char **argv) {
        sigset_t mask_new, mask_old;
        int r;

        r = parse_argv(argc, argv);
        if (r)
                goto exit;

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
