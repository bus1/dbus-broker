/*
 * D-Bus Broker Launcher
 */

#include <c-macro.h>
#include <c-string.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>
#include "util/error.h"

typedef struct Manager Manager;

enum {
        _MAIN_SUCCESS,
        MAIN_EXIT,
        MAIN_FAILED,
};

struct Manager {
        sd_event *event;
        sd_bus *bus;
        int fd_listen;
};

static bool main_arg_verbose = false;
static const char *main_arg_listen = "/var/run/dbus/system_bus_socket";
static bool main_arg_force = false;

static Manager *manager_free(Manager *manager) {
        if (!manager)
                return NULL;

        c_close(manager->fd_listen);
        sd_bus_unref(manager->bus);
        sd_event_unref(manager->event);
        free(manager);

        return NULL;
}

C_DEFINE_CLEANUP(Manager *, manager_free);

static int manager_new(Manager **managerp) {
        _c_cleanup_(manager_freep) Manager *manager = NULL;
        int r;

        manager = calloc(1, sizeof(*manager));
        if (!manager)
                return error_origin(-ENOMEM);

        manager->fd_listen = -1;

        r = sd_event_default(&manager->event);
        if (r < 0)
                return error_origin(r);

        r = sd_event_add_signal(manager->event, NULL, SIGTERM, NULL, NULL);
        if (r < 0)
                return error_origin(r);

        r = sd_event_add_signal(manager->event, NULL, SIGINT, NULL, NULL);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_new(&manager->bus);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_attach_event(manager->bus, manager->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return error_origin(r);

        *managerp = manager;
        manager = NULL;
        return 0;
}

static int manager_listen(Manager *manager, const char *path) {
        _c_cleanup_(c_closep) int s = -1;
        struct sockaddr_un addr = {};
        int r;

        assert(manager->fd_listen < 0);

        s = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (s < 0)
                return error_origin(-errno);

        addr.sun_family = AF_UNIX;
        memcpy(addr.sun_path, path, strlen(path));
        r = bind(s, (struct sockaddr *)&addr, offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1);
        if (r < 0)
                return error_origin(-errno);

        r = listen(s, 256);
        if (r < 0)
                return error_origin(-errno);

        manager->fd_listen = s;
        s = -1;
        return 0;
}

static noreturn void manager_run_child(Manager *manager, int fd_controller) {
        char str_controller[C_DECIMAL_MAX(int) + 1];
        char *argv[] = {
                "dbus-broker",
                "-v",
                "--controller",
                str_controller,
        };
        int r;

        r = prctl(PR_SET_PDEATHSIG, SIGTERM);
        if (r) {
                r = error_origin(-errno);
                goto exit;
        }

        r = fcntl(fd_controller, F_GETFD);
        if (r < 0) {
                r = error_origin(-errno);
                goto exit;
        }

        r = fcntl(fd_controller, F_SETFD, r & ~FD_CLOEXEC);
        if (r < 0) {
                r = error_origin(-errno);
                goto exit;
        }

        r = snprintf(str_controller, sizeof(str_controller), "%d", fd_controller);
        assert(r < (ssize_t)sizeof(str_controller));

        r = execve(argv[0], argv, environ);
        r = error_origin(-errno);

exit:
        _exit(1);
}

static int manager_on_child_exit(sd_event_source *source, const siginfo_t *si, void *userdata) {
        if (main_arg_verbose)
                fprintf(stderr, "Caught SIGCHLD of broker\n");

        return sd_event_exit(sd_event_source_get_event(source), 0);
}

static int manager_fork(Manager *manager, int fd_controller) {
        pid_t pid;
        int r;

        pid = fork();
        if (pid < 0)
                return error_origin(-errno);

        if (!pid)
                manager_run_child(manager, fd_controller);

        r = sd_event_add_child(manager->event, NULL, pid, WEXITED, manager_on_child_exit, manager);
        if (r < 0)
                return error_origin(-errno);

        close(fd_controller);
        return 0;
}

static int manager_on_name_activate(Manager *manager, sd_bus_message *m, const char *name) {
        return 0;
}

static int manager_on_message(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Manager *manager = userdata;
        const char *path, *suffix;
        int r = 0;

        path = sd_bus_message_get_path(m);
        if (!path)
                return 0;

        suffix = c_string_prefix(path, "/org/bus1/DBus/Name/");
        if (suffix) {
                if (sd_bus_message_is_signal(m, "org.bus1.DBus.Name", "Activate"))
                        r = manager_on_name_activate(manager, m, suffix);
        }

        return r;
}

static int manager_run(Manager *manager) {
        int r, controller[2];

        assert(manager->fd_listen >= 0);

        r = socketpair(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, controller);
        if (r < 0)
                return error_origin(-errno);

        /* consumes FD controller[0] */
        r = sd_bus_set_fd(manager->bus, controller[0], controller[0]);
        if (r < 0) {
                close(controller[0]);
                close(controller[1]);
                return error_origin(r);
        }

        /* consumes FD controller[1] */
        r = manager_fork(manager, controller[1]);
        if (r < 0) {
                close(controller[1]);
                return error_fold(r);
        }

        r = sd_bus_add_filter(manager->bus, NULL, manager_on_message, manager);
        if (r < 0)
                return error_fold(r);

        r = sd_bus_start(manager->bus);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_call_method(manager->bus,
                               NULL,
                               "/org/bus1/DBus/Broker",
                               "org.bus1.DBus.Broker",
                               "AddListener",
                               NULL,
                               NULL,
                               "oh",
                               "/org/bus1/DBus/Listener/0",
                               manager->fd_listen);
        if (r < 0)
                return error_origin(r);

        r = sd_event_loop(manager->event);
        if (r < 0)
                return error_origin(r);

        return 0;
}

static void help(void) {
        printf("%s [GLOBALS...] ...\n\n"
               "Linux D-Bus Message Broker Launcher\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "  -v --verbose          Print progress to terminal\n"
               "     --listen PATH      Specify path of listener socket\n"
               "  -f --force            Ignore existing listener sockets\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_LISTEN,
        };
        static const struct option options[] = {
                { "help",               no_argument,            NULL,   'h'                     },
                { "version",            no_argument,            NULL,   ARG_VERSION             },
                { "verbose",            no_argument,            NULL,   'v'                     },
                { "listen",             required_argument,      NULL,   ARG_LISTEN              },
                { "force",              no_argument,            NULL,   'f'                     },
                {}
        };
        int c;

        while ((c = getopt_long(argc, argv, "hvf", options, NULL)) >= 0) {
                switch (c) {
                case 'h':
                        help();
                        return MAIN_EXIT;

                case ARG_VERSION:
                        printf("dbus-broker-launch %d\n", PACKAGE_VERSION);
                        return MAIN_EXIT;

                case 'v':
                        main_arg_verbose = true;
                        break;

                case ARG_LISTEN:
                        main_arg_listen = optarg;
                        break;

                case 'f':
                        main_arg_force = true;
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

static int run(void) {
        _c_cleanup_(manager_freep) Manager *manager = NULL;
        int r;

        r = manager_new(&manager);
        if (r)
                return error_trace(r);

        if (main_arg_force) {
                r = unlink(main_arg_listen);
                if (r < 0) {
                        if (errno != ENOENT)
                                return error_origin(-errno);
                        else if (main_arg_verbose)
                                fprintf(stderr, "No conflict on socket '%s'\n", main_arg_listen);
                } else if (main_arg_verbose) {
                        fprintf(stderr, "Forcibly removed conflicting socket '%s'\n", main_arg_listen);
                }
        }

        r = manager_listen(manager, main_arg_listen);
        if (r)
                return error_trace(r);

        r = manager_run(manager);
        if (r)
                return error_trace(r);

        r = unlink(main_arg_listen);
        if (r < 0)
                return error_origin(-errno);

        if (main_arg_verbose)
                fprintf(stderr, "Cleaned up listener socket '%s'\n", main_arg_listen);

        return 0;
}

int main(int argc, char **argv) {
        sigset_t mask_new, mask_old;
        int r;

        r = parse_argv(argc, argv);
        if (r)
                goto exit;

        sigemptyset(&mask_new);
        sigaddset(&mask_new, SIGCHLD);
        sigaddset(&mask_new, SIGTERM);
        sigaddset(&mask_new, SIGINT);

        sigprocmask(SIG_BLOCK, &mask_new, &mask_old);
        r = run();
        sigprocmask(SIG_SETMASK, &mask_old, NULL);

exit:
        r = error_trace(r);
        if (r < 0 && main_arg_verbose)
                fprintf(stderr, "Exiting due to fatal error: %d\n", r);
        return (r == 0 || r == MAIN_EXIT) ? 0 : 1;
}
