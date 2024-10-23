/*
 * D-Bus Broker Launch Main Entry
 */

#include "launch/launcher.h"
#include "util/error.h"
#include <c-stdaux.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <spawn.h>
#include <systemd/sd-daemon.h>

#include <sys/auxv.h>
#include <sys/un.h>

enum {
        _MAIN_SUCCESS,
        MAIN_EXIT,
        MAIN_FAILED,
};

static bool             main_arg_audit = false;
static const char *     main_arg_configfile = NULL;
static bool             main_arg_user_scope = false;
static int              main_fd_listen = -1;

#define SESSION_TOOL "dbus-broker-session"

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

static void help_session(void) {
        printf("%s [GLOBALS...] ...\n\n"
               "Initiate a D-Bus session with a new session controller\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "     --config-file PATH Specify path to configuration file\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[], bool as_session) {
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
        static const struct option options_session[] = {
                { "help",               no_argument,            NULL,   'h'                     },
                { "version",            no_argument,            NULL,   ARG_VERSION             },
                { "config-file",        required_argument,      NULL,   ARG_CONFIG,             },
                {}
        };
        int c;

        while ((c = getopt_long(argc, argv, "h", as_session ? options_session : options, NULL)) >= 0) {
                switch (c) {
                case 'h':
                        as_session ? help_session() : help();
                        return MAIN_EXIT;

                case ARG_VERSION:
                        printf("%s %d\n", as_session ? SESSION_TOOL : "dbus-broker-launch", PACKAGE_VERSION);
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

        if (as_session)
        {
                if (optind >= argc) {
                        fprintf(stderr, "%s: a non-option argument is required\n", program_invocation_name);
                        return MAIN_FAILED;
                }
        } else {
                if (optind != argc) {
                        fprintf(stderr, "%s: invalid arguments -- '%s'\n", program_invocation_name, argv[optind]);
                        return MAIN_FAILED;
                }
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

struct app_data
{
        char **argv;
        pid_t pid;
        int exit_code;
        Launcher *launcher;
};
typedef struct app_data app_data;
static int launcher_on_controller_start(sd_event_source *source, void *userdata);

static int run(app_data *app) {
        _c_cleanup_(launcher_freep) Launcher *launcher = NULL;
        int r;

        r = launcher_new(&launcher, main_fd_listen, main_arg_audit, main_arg_configfile, main_arg_user_scope);
        if (r)
                return error_fold(r);

        if (app) {
                app->launcher = launcher;
                r = sd_event_add_defer(launcher->event, NULL, launcher_on_controller_start, app);
                if (r)
                        return error_fold(r);
        }

        r = launcher_run(launcher);
        return error_fold(r);
}

static int launch_main(int argc, char **argv) {
        sigset_t mask_new, mask_old;
        int r;

        r = parse_argv(argc, argv, false);
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
        r = run(NULL);
        sigprocmask(SIG_SETMASK, &mask_old, NULL);

exit:
        r = error_trace(r);
        if (r < 0)
                fprintf(stderr, "Exiting due to fatal error: %d\n", r);
        return (r == 0 || r == MAIN_EXIT) ? 0 : 1;
}

static int exit_event_loop(sd_event_source *source, int r, void *userdata) {
        app_data *app = userdata;
        app->exit_code = r;
        return sd_event_exit(sd_event_source_get_event(source), 0);
}

static int launcher_on_controller_exit(sd_event_source *source, const siginfo_t *si, void *userdata) {
        app_data *app = userdata;
        app->pid = -1;
        return exit_event_loop(source, (si->si_code == CLD_EXITED) ? si->si_status : 128 + si->si_status, userdata);
}

static int launcher_on_controller_start(sd_event_source *source, void *userdata) {
        app_data *app = userdata;
        Launcher *launcher = app->launcher;

        pid_t pid;
        sigset_t sigs;
        posix_spawnattr_t spawnat;
        sigemptyset ( &sigs);
        posix_spawnattr_init(&spawnat);
        posix_spawnattr_setflags(&spawnat, POSIX_SPAWN_SETSIGMASK);
        posix_spawnattr_setsigmask(&spawnat, &sigs);
        int r = posix_spawnp(&pid, app->argv[0], NULL, &spawnat, app->argv, environ);
        posix_spawnattr_destroy(&spawnat);
        if (r) {
                error_fold(r);
                exit_event_loop(source, 1, userdata);
        }

        app->pid = pid;
        r = sd_event_add_child(launcher->event, NULL, pid, WEXITED, launcher_on_controller_exit, app);

        return error_fold(r);
}

static int open_socket(int *pfd, struct sockaddr_un *p_addr) {
        struct sockaddr_un addr = {AF_UNIX};
        unsigned long random_bytes;
        int fd, r;
        void *random = (void*)getauxval(AT_RANDOM);

        c_assert(random);
        c_memcpy(&random_bytes, random, sizeof(random_bytes));

        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0)
                return error_fold(fd);
        *pfd = fd;

        snprintf(addr.sun_path, sizeof(addr.sun_path) - 1, "/tmp/dbus-%02lx", random_bytes);
        r = bind(fd, (const struct sockaddr*)&addr, sizeof(addr));
        if (r)
                return error_fold(r);
        *p_addr = addr;
        r = listen(fd, 4096);
        if (r)
                return error_fold(r);
        return fd;
}

static int prepare_session(struct sockaddr_un *socket_path) {
        static const char *const unset_env[] = {
                "DBUS_SESSION_BUS_PID",
                "DBUS_SESSION_BUS_WINDOWID",
                "DBUS_STARTER_ADDRESS",
                "DBUS_STARTER_BUS_TYPE",
        };
        char buffer[sizeof(socket_path->sun_path) + 16];
        int fd = -1;
        int r = open_socket(&fd, socket_path);

        if (r < 0) {
                if (fd >= 0)
                        close(fd);
                return r;
        }
        main_fd_listen = fd;
        for (unsigned i = 0; i < C_ARRAY_SIZE(unset_env); ++i)
                unsetenv(unset_env[i]);

        snprintf(buffer, sizeof(buffer), "unix:path=%s", socket_path->sun_path);
        r = setenv("DBUS_SESSION_BUS_ADDRESS", buffer, 1);
        return error_fold(r);
}

static int session_main(int argc, char **argv) {
        /*
         * Returns 127 if bus could not be spawned
         * returns 127 if app could not be forked
         * returns 127 on commandline sparsing
         * returns 1 if app exec fails
         * returns 128 + signo if app exited by signal
         * returns app exit_code else
         */
        // https://gitlab.freedesktop.org/dbus/dbus/-/blob/master/tools/dbus-run-session.c
        sigset_t mask_new, mask_old;
        struct sockaddr_un socket_path = {0};
        app_data app = {};
        int r;

        main_arg_user_scope = true;
        r = parse_argv(argc, argv, true);
        if (r)
                goto exit;

        app.argv = &argv[optind];
        r = prepare_session(&socket_path);
        if (r)
                goto exit;

        sigemptyset(&mask_new);
        sigaddset(&mask_new, SIGCHLD);
        sigaddset(&mask_new, SIGTERM);
        sigaddset(&mask_new, SIGINT);
        sigaddset(&mask_new, SIGHUP);

        sigprocmask(SIG_BLOCK, &mask_new, &mask_old);
        r = run(&app);
        sigprocmask(SIG_SETMASK, &mask_old, NULL);

        if (app.pid > 0)
                kill(app.pid, SIGTERM);
        if (socket_path.sun_path[0] != '\0')
                unlink(socket_path.sun_path);
exit:
        r = error_trace(r);
        if (r < 0)
                fprintf(stderr, "Exiting due to fatal error: %d\n", r);

        return r == 0 ? app.exit_code : 127;
}

int main(int argc, char **argv) {
        const char *p_last_path = strrchr(argv[0], '/');
        if (strcmp(p_last_path ? p_last_path + 1 : argv[0], SESSION_TOOL) == 0)
                return session_main(argc, argv);
        return launch_main(argc, argv);
}
