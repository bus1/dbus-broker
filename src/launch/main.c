/*
 * D-Bus Broker Launcher
 */

#include <c-macro.h>
#include <c-ini.h>
#include <c-rbtree.h>
#include <c-shquote.h>
#include <c-string.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>
#include <systemd/sd-id128.h>
#include <unistd.h>
#include "launch/config.h"
#include "launch/nss-cache.h"
#include "launch/policy.h"
#include "util/apparmor.h"
#include "util/audit.h"
#include "util/dirwatch.h"
#include "util/error.h"
#include "util/log.h"
#include "util/misc.h"

typedef struct Manager Manager;
typedef struct Service Service;

enum {
        _MAIN_SUCCESS,
        MAIN_EXIT,
        MAIN_FAILED,
};

enum {
        _MANAGER_E_SUCCESS,

        MANAGER_E_INVALID_CONFIG,
        MANAGER_E_INVALID_SERVICE_FILE,
};

typedef enum {
        SERVICE_STATE_PENDING,
        SERVICE_STATE_CURRENT,
        SERVICE_STATE_DEFUNCT,
} ServiceState;

struct Service {
        Manager *manager;
        ServiceState state;
        bool not_found;
        sd_bus_slot *slot;
        CRBNode rb;
        CRBNode rb_by_name;
        char *name;
        char *unit;
        size_t argc;
        char **argv;
        char *user;
        uid_t uid;
        uint64_t instance;
        char id[];
};

struct Manager {
        sd_event *event;
        sd_bus *bus_controller;
        sd_bus *bus_regular;
        int fd_listen;
        Dirwatch *dirwatch;
        sd_event_source *dirwatch_src;
        CRBTree services;
        CRBTree services_by_name;
        uint64_t service_ids;
        uint32_t uid;
        uint32_t gid;
        uint64_t max_bytes;
        uint64_t max_fds;
        uint64_t max_matches;
};

/*
 * These are the default limits used when spawning dbus-broker. They are
 * similar to the limits used by dbus-daemon(1) (specified here in parentheses)
 * but slightly lowered to avoid DoS. We should be fine, since dbus-broker
 * employs a dynamically adjusted quota-based share distribution of resources.
 */
static const uint64_t main_max_outgoing_bytes = 8 * 1024 * 1024; /* 127MiB */
static const uint64_t main_max_outgoing_unix_fds = 64;
static const uint64_t main_max_connections_per_user = 64; /* 256 */
static const uint64_t main_max_match_rules_per_connection = 256;

static bool             main_arg_audit = false;
static const char *     main_arg_broker = BINDIR "/dbus-broker";
static const char *     main_arg_configfile = NULL;
static bool             main_arg_user_scope = false;
static Log              main_log = LOG_NULL;

static sd_bus *bus_close_unref(sd_bus *bus) {
        /*
         * It is not sufficient to simply call sd_bus_unref(), as messages
         * in the bus' queues may pin the bus itself. Also,
         * sd_bus_flush_close_unref() is not always appropriate as it would
         * block in poll waiting for messages to be flushed to the socket.
         *
         * In some cases all we really want to do is close the socket and
         * release all the memory, ignoring whether or not it has been
         * flushed to the kernel (typically in error paths).
         */
        if (!bus)
                return NULL;

        sd_bus_close(bus);

        return sd_bus_unref(bus);
}

static int service_compare(CRBTree *t, void *k, CRBNode *n) {
        Service *service = c_container_of(n, Service, rb);

        return strcmp(k, service->id);
}

static int service_compare_by_name(CRBTree *t, void *k, CRBNode *n) {
        Service *service = c_container_of(n, Service, rb_by_name);

        return strcmp(k, service->name);
}

static Service *service_free(Service *service) {
        if (!service)
                return NULL;

        c_rbnode_unlink(&service->rb_by_name);
        c_rbnode_unlink(&service->rb);
        free(service->user);
        for (size_t i = 0; i < service->argc; ++i)
                free(service->argv[i]);
        free(service->argv);
        free(service->unit);
        free(service->name);
        sd_bus_slot_unref(service->slot);
        free(service);

        return NULL;
}

C_DEFINE_CLEANUP(Service *, service_free);

static int service_update(Service *service, const char *unit, size_t argc, char **argv, const char *user, uid_t uid) {
        service->unit = c_free(service->unit);
        service->argc = 0;
        service->argv = c_free(service->argv);
        service->user = c_free(service->user);
        service->uid = uid;

        if (unit) {
                service->unit = strdup(unit);
                if (!service->unit)
                        return error_origin(-ENOMEM);
        }

        if (argc > 0) {
                service->argv = calloc(1, argc * sizeof(char*));
                if (!service->argv)
                        return error_origin(-ENOMEM);

                service->argc = argc;

                for (size_t i = 0; i < argc; ++i) {
                        service->argv[i] = strdup(argv[i]);
                        if (!service->argv[i])
                                return error_origin(-ENOMEM);
                }
        }

        if (user) {
                service->user = strdup(user);
                if (!service->user)
                        return error_origin(-ENOMEM);
        }

        return 0;
}

static int service_new(Service **servicep,
                       Manager *manager,
                       const char *name,
                       CRBNode **slot_by_name,
                       CRBNode *parent_by_name,
                       const char *unit,
                       size_t argc,
                       char **argv,
                       const char *user,
                       uid_t uid) {
        _c_cleanup_(service_freep) Service *service = NULL;
        CRBNode **slot, *parent;
        int r;

        service = calloc(1, sizeof(*service) + C_DECIMAL_MAX(uint64_t) + 1);
        if (!service)
                return error_origin(-ENOMEM);

        service->manager = manager;
        service->rb = (CRBNode)C_RBNODE_INIT(service->rb);
        service->rb_by_name = (CRBNode)C_RBNODE_INIT(service->rb_by_name);
        sprintf(service->id, "%" PRIu64, ++manager->service_ids);

        service->name = strdup(name);
        if (!service->name)
                return error_origin(-ENOMEM);

        r = service_update(service, unit, argc, argv, user, uid);
        if (r)
                return error_trace(r);

        slot = c_rbtree_find_slot(&manager->services, service_compare, service->id, &parent);
        assert(slot);
        c_rbtree_add(&manager->services, parent, slot, &service->rb);
        c_rbtree_add(&manager->services_by_name, parent_by_name, slot_by_name, &service->rb_by_name);

        *servicep = service;
        service = NULL;
        return 0;
}

static Manager *manager_free(Manager *manager) {
        Service *service, *safe;

        if (!manager)
                return NULL;

        c_rbtree_for_each_entry_safe_postorder_unlink(service, safe, &manager->services, rb)
                service_free(service);
        assert(c_rbtree_is_empty(&manager->services_by_name));

        sd_event_source_unref(manager->dirwatch_src);
        dirwatch_free(manager->dirwatch);
        c_close(manager->fd_listen);
        bus_close_unref(manager->bus_regular);
        bus_close_unref(manager->bus_controller);
        sd_event_unref(manager->event);
        free(manager);

        return NULL;
}

C_DEFINE_CLEANUP(Manager *, manager_free);

static int manager_reload_config(Manager *manager);

static int manager_on_sighup(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *manager = userdata;
        int r;

        fprintf(stderr, "Caught SIGHUP\n");

        r = manager_reload_config(manager);
        if (r) {
                if (r == MANAGER_E_INVALID_CONFIG)
                        fprintf(stderr, "Invalid configuration, ignored.\n");
                else
                        return error_fold(r);
        }

        return 1;
}

static int manager_on_dirwatch(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *manager = userdata;
        int r;

        r = dirwatch_dispatch(manager->dirwatch);
        if (r != DIRWATCH_E_TRIGGERED)
                return error_fold(r);

        fprintf(stderr, "Noticed file-system modification, trigger reload\n");

        r = manager_reload_config(manager);
        if (r) {
                if (r == MANAGER_E_INVALID_CONFIG)
                        fprintf(stderr, "Invalid configuration, ignored.\n");
                else
                        return error_fold(r);
        }

        return 1;
}

static int manager_new(Manager **managerp) {
        _c_cleanup_(manager_freep) Manager *manager = NULL;
        int r;

        manager = calloc(1, sizeof(*manager));
        if (!manager)
                return error_origin(-ENOMEM);

        manager->fd_listen = -1;
        manager->uid = -1;
        manager->gid = -1;

        r = sd_event_default(&manager->event);
        if (r < 0)
                return error_origin(r);

        r = sd_event_add_signal(manager->event, NULL, SIGTERM, NULL, NULL);
        if (r < 0)
                return error_origin(r);

        r = sd_event_add_signal(manager->event, NULL, SIGINT, NULL, NULL);
        if (r < 0)
                return error_origin(r);

        r = sd_event_add_signal(manager->event, NULL, SIGHUP, manager_on_sighup, manager);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_new(&manager->bus_controller);
        if (r < 0)
                return error_origin(r);

        *managerp = manager;
        manager = NULL;
        return 0;
}

static int manager_listen_inherit(Manager *manager) {
        _c_cleanup_(c_closep) int s = -1;
        int r, n;

        assert(manager->fd_listen < 0);

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

        manager->fd_listen = s;
        s = -1;
        return 0;
}

static noreturn void manager_run_child(Manager *manager, int fd_log, int fd_controller) {
        sd_id128_t machine_id;
        char str_log[C_DECIMAL_MAX(int) + 1],
             str_controller[C_DECIMAL_MAX(int) + 1],
             str_machine_id[33],
             str_max_bytes[C_DECIMAL_MAX(uint64_t)],
             str_max_fds[C_DECIMAL_MAX(uint64_t)],
             str_max_matches[C_DECIMAL_MAX(uint64_t)];
        const char * const argv[] = {
                "dbus-broker",
                "--log",
                str_log,
                "--controller",
                str_controller,
                "--machine-id",
                str_machine_id,
                "--max-bytes",
                str_max_bytes,
                "--max-fds",
                str_max_fds,
                "--max-matches",
                str_max_matches,
                main_arg_audit ? "--audit" : NULL, /* note that this needs to be the last argument to work */
                NULL,
        };
        int r;

        if (manager->uid != (uint32_t)-1) {
                r = util_audit_drop_permissions(manager->uid, manager->gid);
                if (r)
                        goto exit;
        }

        r = prctl(PR_SET_PDEATHSIG, SIGTERM);
        if (r) {
                r = error_origin(-errno);
                goto exit;
        }

        r = fcntl(fd_log, F_GETFD);
        if (r < 0) {
                r = error_origin(-errno);
                goto exit;
        }

        r = fcntl(fd_log, F_SETFD, r & ~FD_CLOEXEC);
        if (r < 0) {
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

        r = sd_id128_get_machine(&machine_id);
        if (r < 0) {
                r = error_origin(r);
                goto exit;
        }

        sd_id128_to_string(machine_id, str_machine_id);

        r = snprintf(str_log, sizeof(str_log), "%d", fd_log);
        assert(r < (ssize_t)sizeof(str_log));

        r = snprintf(str_controller, sizeof(str_controller), "%d", fd_controller);
        assert(r < (ssize_t)sizeof(str_controller));

        r = snprintf(str_max_bytes, sizeof(str_max_bytes), "%"PRIu64, manager->max_bytes);
        assert(r < (ssize_t)sizeof(str_max_bytes));

        r = snprintf(str_max_fds, sizeof(str_max_fds), "%"PRIu64, manager->max_fds);
        assert(r < (ssize_t)sizeof(str_max_fds));

        r = snprintf(str_max_matches, sizeof(str_max_matches), "%"PRIu64, manager->max_matches);
        assert(r < (ssize_t)sizeof(str_max_matches));

        r = execve(main_arg_broker, (char * const *)argv, environ);
        r = error_origin(-errno);

exit:
        _exit(1);
}

static int manager_on_child_exit(sd_event_source *source, const siginfo_t *si, void *userdata) {
        fprintf(stderr, "Caught SIGCHLD of broker\n");

        return sd_event_exit(sd_event_source_get_event(source),
                             (si->si_code == CLD_EXITED) ? si->si_status : EXIT_FAILURE);
}

static int manager_fork(Manager *manager, int fd_controller) {
        pid_t pid;
        int r;

        pid = fork();
        if (pid < 0)
                return error_origin(-errno);

        if (!pid)
                manager_run_child(manager, log_get_fd(&main_log), fd_controller);

        r = sd_event_add_child(manager->event, NULL, pid, WEXITED, manager_on_child_exit, manager);
        if (r < 0)
                return error_origin(-errno);

        close(fd_controller);
        return 0;
}

static int manager_start_unit_handler(sd_bus_message *message, void *userdata, sd_bus_error *errorp) {
        _c_cleanup_(c_freep) char *object_path = NULL;
        const sd_bus_error *error;
        Service *service = userdata;
        int r;

        service->slot = sd_bus_slot_unref(service->slot);

        error = sd_bus_message_get_error(message);
        if (!error)
                /* unit started successfully */
                return 1;

        /*
         * We always forward activation failure to the broker, which then
         * forwards it as error reply to all pending messages on that
         * activation. We augment this with a detailed error message in all
         * cases where we consider the error non-recoverable. In case of
         * recoverable situations, we want to stay silent and simply forward
         * the information to the sender of the activation message.
         */
        if (strcmp(error->name, "org.freedesktop.systemd1.TransactionIsDestructive") != 0) {
                /*
                 * We currently use a whitelist of situations where we consider
                 * the activation failure recoverable. These currently include:
                 *
                 *  * `TransactionIsDestructive` from systemd tells us that the
                 *    start request was valid, but was denied because a
                 *    non-recoverable conflicting stop request is currently
                 *    pending. Most common scenario is the service manager
                 *    shutting down, but any systemd-job can theoretically
                 *    select this mode.
                 *    Since this indicates that our request was valid and
                 *    properly configured, we treat this as recoverable error.
                 *  * `NoSuchUnit` from systemd tells us that the unit file
                 *    was not found. This may indicate that the service was
                 *    disabled, which is a supported configuration. In this
                 *    case we only log once.
                 *
                 * In any other situation we log an error message, since these
                 * are non-recoverable and indicate system configuration
                 * errors.
                 */
                if (strcmp(error->name, "org.freedesktop.systemd1.NoSuchUnit") == 0) {
                        if (!service->not_found) {
                                service->not_found = true;
                                fprintf(stderr, "Activation request for '%s' failed. The corresponding systemd unit may not be enabled: %s\n", service->name, error->message);
                        }
                } else {
                        fprintf(stderr, "Activation request for '%s' failed: %s\n", service->name, error->message);
                }
        }


        /* unit failed, so reset pending activation requsets in the broker */
        r = asprintf(&object_path, "/org/bus1/DBus/Name/%s", service->id);
        if (r < 0)
                return error_origin(-errno);

        /* XXX: We should forward error-information to the activator. */
        r = sd_bus_call_method(service->manager->bus_controller,
                               NULL,
                               object_path,
                               "org.bus1.DBus.Name",
                               "Reset",
                               NULL,
                               NULL,
                               "");
        if (r < 0)
                return error_origin(r);

        return 1;
}

static int manager_start_unit(Manager *manager, Service *service) {
        _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *method_call = NULL;
        int r;

        service->slot = sd_bus_slot_unref(service->slot);

        r = sd_bus_message_new_method_call(manager->bus_regular, &method_call,
                                           "org.freedesktop.systemd1",
                                           "/org/freedesktop/systemd1",
                                           "org.freedesktop.systemd1.Manager",
                                           "StartUnit");
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_append(method_call, "ss", service->unit, "replace");
        if (r < 0)
                return error_origin(r);

        r = sd_bus_call_async(manager->bus_regular, &service->slot, method_call, manager_start_unit_handler, service, -1);
        if (r < 0)
                return error_origin(r);

        return 0;
}

static int manager_start_transient_unit(Manager *manager, Service *service) {
        _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *method_call = NULL;
        _c_cleanup_(c_freep) char *unit = NULL;
        const char *unique_name;
        int r;

        service->slot = sd_bus_slot_unref(service->slot);

        r = sd_bus_get_unique_name(manager->bus_regular, &unique_name);
        if (r < 0)
                return error_origin(r);

        r = asprintf(&unit, "dbus-%s-%s@%"PRIu64".service", unique_name, service->name, service->instance++);
        if (r < 0)
                return error_origin(-errno);

        r = sd_bus_message_new_method_call(manager->bus_regular, &method_call,
                                           "org.freedesktop.systemd1",
                                           "/org/freedesktop/systemd1",
                                           "org.freedesktop.systemd1.Manager",
                                           "StartTransientUnit");
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_append(method_call, "ss", unit, "replace");
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_open_container(method_call, 'a', "(sv)");
        if (r < 0)
                return error_origin(r);

        {
                r = sd_bus_message_open_container(method_call, 'r', "sv");
                if (r < 0)
                        return error_origin(r);

                {
                        r = sd_bus_message_append(method_call, "s", "ExecStart");
                        if (r < 0)
                                return error_origin(r);

                        r = sd_bus_message_open_container(method_call, 'v', "a(sasb)");
                        if (r < 0)
                                return error_origin(r);

                        {
                                r = sd_bus_message_open_container(method_call, 'a', "(sasb)");
                                if (r < 0)
                                        return error_origin(r);

                                {
                                        r = sd_bus_message_open_container(method_call, 'r', "sasb");
                                        if (r < 0)
                                                return error_origin(r);

                                        {
                                                r = sd_bus_message_append(method_call, "s", service->argv[0]);
                                                if (r < 0)
                                                        return error_origin(r);

                                                r = sd_bus_message_open_container(method_call, 'a', "s");
                                                if (r < 0)
                                                        return error_origin(r);

                                                {
                                                        for (size_t i = 0; i < service->argc; ++i) {
                                                                r = sd_bus_message_append(method_call, "s", service->argv[i]);
                                                                if (r < 0)
                                                                        return error_origin(r);
                                                        }
                                                }

                                                r = sd_bus_message_close_container(method_call);
                                                if (r < 0)
                                                        return error_origin(r);

                                                r = sd_bus_message_append(method_call, "b", true);
                                                if (r < 0)
                                                        return error_origin(r);
                                        }

                                        r = sd_bus_message_close_container(method_call);
                                        if (r < 0)
                                                return error_origin(r);
                                }

                                r = sd_bus_message_close_container(method_call);
                                if (r < 0)
                                        return error_origin(r);
                        }

                        r = sd_bus_message_close_container(method_call);
                        if (r < 0)
                                return error_origin(r);
                }

                r = sd_bus_message_close_container(method_call);
                if (r < 0)
                        return error_origin(r);

                r = sd_bus_message_open_container(method_call, 'r', "sv");
                if (r < 0)
                        return error_origin(r);

                {
                        r = sd_bus_message_append(method_call, "s", "KillMode");
                        if (r < 0)
                                return error_origin(r);

                        r = sd_bus_message_open_container(method_call, 'v', "s");
                        if (r < 0)
                                return error_origin(r);

                        {
                                r = sd_bus_message_append(method_call, "s", "process");
                                if (r < 0)
                                        return error_origin(r);
                        }

                        r = sd_bus_message_close_container(method_call);
                        if (r < 0)
                                return error_origin(r);
                }

                r = sd_bus_message_close_container(method_call);
                if (r < 0)
                        return error_origin(r);

                if (service->user) {
                        /*
                         * Ideally we would unconditionally pass the UID
                         * we are accounting on to systemd to run the service
                         * under. However, in the case of the user instance,
                         * systemd fails to start a transient unit if a user
                         * is provided due to lack of permission. In practice
                         * this works out ok, as in this case we would have
                         * provided our own UID, which is systemd's UID, so
                         * it would ammount to a no-op. It would have been
                         * better if systemd could detect this case and not
                         * fail, but in practice this is perfectly fine.
                         */
                        r = sd_bus_message_open_container(method_call, 'r', "sv");
                        if (r < 0)
                                return error_origin(r);

                        {
                                r = sd_bus_message_append(method_call, "s", "User");
                                if (r < 0)
                                        return error_origin(r);

                                r = sd_bus_message_open_container(method_call, 'v', "s");
                                if (r < 0)
                                        return error_origin(r);

                                {
                                        _c_cleanup_(c_freep) char *uid = NULL;

                                        /*
                                         * Pass the UID we parsed, rather than the
                                         * original username. This should resolve
                                         * to the same, but out of an abundance of
                                         * caution, we try to avoid any
                                         * inconsistencies.
                                         */
                                        r = asprintf(&uid, "%"PRIu32, service->uid);
                                        if (r < 0)
                                                return error_origin(-errno);

                                        r = sd_bus_message_append(method_call, "s", uid);
                                        if (r < 0)
                                                return error_origin(r);
                                }

                                r = sd_bus_message_close_container(method_call);
                                if (r < 0)
                                        return error_origin(r);
                        }

                        r = sd_bus_message_close_container(method_call);
                        if (r < 0)
                                return error_origin(r);
                }
        }

        r = sd_bus_message_close_container(method_call);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_append(method_call, "a(sa(sv))", 0);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_call_async(manager->bus_regular, &service->slot, method_call, manager_start_unit_handler, service, -1);
        if (r < 0)
                return error_origin(r);

        return 0;
}

static int manager_on_name_activate(Manager *manager, sd_bus_message *m, const char *id) {
        Service *service;
        int r;

        service = c_rbtree_find_entry(&manager->services,
                                      service_compare,
                                      id,
                                      Service,
                                      rb);
        if (!service) {
                fprintf(stderr, "Activation request on unknown name '%s'\n", id);
                return 0;
        } else if (!strcmp(service->name, "org.freedesktop.systemd1")) {
                /* pid1 activation requests are silently ignored */
                return 0;
        }

        if (service->unit) {
                r = manager_start_unit(manager, service);
                if (r)
                        return error_trace(r);
        } else {
                r = manager_start_transient_unit(manager, service);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

static int manager_set_environment_handler(sd_bus_message *message, void *userdata, sd_bus_error *errorp) {
        const sd_bus_error *error;

        error = sd_bus_message_get_error(message);
        if (!error)
                /* environment set successfully */
                return 1;

        fprintf(stderr, "Updating activation environment failed: %s\n", error->message);

        return 1;
}

static int manager_on_set_activation_environment(Manager *manager, sd_bus_message *m) {
        _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *method_call = NULL;
        int r;

        r = sd_bus_message_new_method_call(manager->bus_regular, &method_call,
                                           "org.freedesktop.systemd1",
                                           "/org/freedesktop/systemd1",
                                           "org.freedesktop.systemd1.Manager",
                                           "SetEnvironment");
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_enter_container(m, 'a', "{ss}");
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_open_container(method_call, 'a', "s");
        if (r < 0)
                return error_origin(r);

        while (!sd_bus_message_at_end(m, false)) {
                _c_cleanup_(c_freep) char *entry = NULL;
                const char *key, *value;

                r = sd_bus_message_read(m, "{ss}", &key, &value);
                if (r < 0)
                        return error_origin(r);

                r = asprintf(&entry, "%s=%s", key, value);
                if (r < 0)
                        return error_origin(-errno);

                r = sd_bus_message_append(method_call, "s", entry);
                if (r < 0)
                        return error_origin(r);
        }

        r = sd_bus_message_close_container(method_call);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_call_async(manager->bus_regular, NULL, method_call, manager_set_environment_handler, NULL, -1);
        if (r < 0)
                return error_origin(r);

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
        } else if (strcmp(path, "/org/bus1/DBus/Broker") == 0) {
                if (sd_bus_message_is_signal(m, "org.bus1.DBus.Broker", "SetActivationEnvironment"))
                        r = manager_on_set_activation_environment(manager, m);
        }

        return error_trace(r);
}

static int manager_ini_reader_parse_file(CIniGroup **groupp, const char *path) {
        _c_cleanup_(c_closep) int fd = -1;
        _c_cleanup_(c_ini_reader_freep) CIniReader *reader = NULL;
        _c_cleanup_(c_ini_domain_unrefp) CIniDomain *domain = NULL;
        CIniGroup *group;
        ssize_t len;
        int r;

        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
                /*
                 * For compatibility reasons we have to accept any failure
                 * during open(2). dbus-daemon(1) simply ignores those errors
                 * and skips the service file in question.
                 *
                 * We would very much prefer to whitelist specific error codes
                 * here, but we would be playing whack-a-mole, so lets just
                 * treat it as soft-error.
                 */
                if (errno == ENOENT)
                        fprintf(stderr, "Original source was unlinked while parsing service file '%s'\n", path);
                else if (errno == EACCES)
                        fprintf(stderr, "Read access denied for service file '%s'\n", path);
                else
                        fprintf(stderr, "Unable to open service file '%s' (%d): %m\n", path, errno);

                return MANAGER_E_INVALID_SERVICE_FILE;
        }

        r = c_ini_reader_new(&reader);
        if (r)
                return error_origin(r);

        c_ini_reader_set_mode(reader,
                              C_INI_MODE_EXTENDED_WHITESPACE |
                              C_INI_MODE_MERGE_GROUPS |
                              C_INI_MODE_OVERRIDE_ENTRIES);

        for (;;) {
                uint8_t buf[1024];

                len = read(fd, buf, sizeof(buf));
                if (len < 0)
                        return error_origin(-errno);
                else if (len == 0)
                        break;

                r = c_ini_reader_feed(reader, buf, len);
                if (r)
                        return error_origin(r);
        }

        r = c_ini_reader_seal(reader, &domain);
        if (r)
                return error_origin(r);

        group = c_ini_domain_find(domain, "D-BUS Service", -1);
        if (!group) {
                fprintf(stderr, "Missing 'D-Bus Service' section in service file '%s'\n", path);
                return MANAGER_E_INVALID_SERVICE_FILE;
        }

        *groupp = c_ini_group_ref(group);
        return 0;
}

static int manager_load_service_file(Manager *manager, const char *path, NSSCache *nss_cache) {
        _c_cleanup_(c_ini_group_unrefp) CIniGroup *group = NULL;
        _c_cleanup_(c_freep) char **argv = NULL;
        _c_cleanup_(service_freep) Service *service = NULL;
        CIniEntry *name_entry = NULL, *unit_entry = NULL, *exec_entry = NULL, *user_entry = NULL;
        const char *name = NULL, *unit = NULL, *exec = NULL, *user = NULL;
        size_t argc = 0, n_exec;
        CRBNode **slot, *parent;
        uid_t uid;
        int r;

        r = manager_ini_reader_parse_file(&group, path);
        if (r)
                return error_trace(r);

        name_entry = c_ini_group_find(group, "Name", -1);
        unit_entry = c_ini_group_find(group, "SystemdService", -1);
        exec_entry = c_ini_group_find(group, "Exec", -1);
        user_entry = c_ini_group_find(group, "User", -1);

        if (!name_entry) {
                fprintf(stderr, "Missing name in service file '%s'\n", path);
                return MANAGER_E_INVALID_SERVICE_FILE;
        }

        if (!unit_entry && !exec_entry) {
                fprintf(stderr, "Missing exec or unit in service file '%s'\n", path);
                return MANAGER_E_INVALID_SERVICE_FILE;
        }

        name = c_ini_entry_get_value(name_entry, NULL);

        if (unit_entry)
                unit = c_ini_entry_get_value(unit_entry, NULL);

        if (exec_entry) {
                exec = c_ini_entry_get_value(exec_entry, &n_exec);

                r = c_shquote_parse_argv(&argv, &argc, exec, n_exec);
                if (r) {
                        if (r == C_SHQUOTE_E_BAD_QUOTING || r == C_SHQUOTE_E_CONTAINS_NULL) {
                                fprintf(stderr, "Invalid exec '%s' in service file '%s'\n", exec, path);
                                return MANAGER_E_INVALID_SERVICE_FILE;
                        }

                        return error_origin(r);
                }
        }

        if (user_entry) {
                user = c_ini_entry_get_value(user_entry, NULL);

                r = nss_cache_get_uid(nss_cache, &uid, NULL, user);
                if (r) {
                        if (r == NSS_CACHE_E_INVALID_NAME) {
                                fprintf(stderr, "Invalid user name '%s' in service file '%s'\n", user, path);
                                return MANAGER_E_INVALID_SERVICE_FILE;
                        }

                        return error_fold(r);
                }

        } else {
                uid = getuid();
        }

        slot = c_rbtree_find_slot(&manager->services_by_name, service_compare_by_name, name, &parent);
        if (slot) {
                r = service_new(&service, manager, name, slot, parent, unit, argc, argv, user, uid);
                if (r)
                        return error_trace(r);
        } else {
                Service *old_service = c_container_of(parent, Service, rb_by_name);

                if (old_service->state == SERVICE_STATE_DEFUNCT) {
                        old_service->state = SERVICE_STATE_CURRENT;
                        r = service_update(old_service, unit, argc, argv, user, uid);
                        if (r)
                                return error_trace(r);
                } else {
                        fprintf(stderr, "Ignoring duplicate name '%s' in service file '%s'\n", name, path);
                        return MANAGER_E_INVALID_SERVICE_FILE;
                }
        }

        service = NULL;
        return 0;
}

static int manager_load_service_dir(Manager *manager, const char *dirpath, NSSCache *nss_cache) {
        const char suffix[] = ".service";
        _c_cleanup_(c_closedirp) DIR *dir = NULL;
        struct dirent *de;
        char *path;
        size_t n;
        int r;

        dir = opendir(dirpath);
        if (!dir) {
                if (errno == ENOENT || errno == ENOTDIR)
                        return 0;
                else
                        return error_origin(-errno);
        }

        r = dirwatch_add(manager->dirwatch, dirpath);
        if (r)
                return error_fold(r);

        for (errno = 0, de = readdir(dir);
             de;
             errno = 0, de = readdir(dir)) {
                if (de->d_name[0] == '.')
                        continue;

                n = strlen(de->d_name);
                if (n <= strlen(suffix))
                        continue;
                if (strcmp(de->d_name + n - strlen(suffix), suffix))
                        continue;

                r = asprintf(&path, "%s/%s", dirpath, de->d_name);
                if (r < 0)
                        return error_origin(-ENOMEM);

                r = manager_load_service_file(manager, path, nss_cache);
                free(path);
                if (r && r != MANAGER_E_INVALID_SERVICE_FILE)
                        return error_trace(r);
        }
        if (errno > 0)
                return error_origin(-errno);

        return 0;
}

static int manager_add_services(Manager *manager) {
        Service *service;
        int r;

        c_rbtree_for_each_entry(service, &manager->services, rb) {
                _c_cleanup_(c_freep) char *object_path = NULL;

                if (service->state != SERVICE_STATE_PENDING)
                        continue;

                r = asprintf(&object_path, "/org/bus1/DBus/Name/%s", service->id);
                if (r < 0)
                        return error_origin(-ENOMEM);

                r = sd_bus_call_method(manager->bus_controller,
                                       NULL,
                                       "/org/bus1/DBus/Broker",
                                       "org.bus1.DBus.Broker",
                                       "AddName",
                                       NULL,
                                       NULL,
                                       "osu",
                                       object_path,
                                       service->name,
                                       service->uid);
                if (r < 0)
                        return error_origin(r);

                service->state = SERVICE_STATE_CURRENT;
        }

        return 0;
}

static int manager_remove_services(Manager *manager) {
        Service *service, *service_safe;
        int r;

        c_rbtree_for_each_entry_safe(service, service_safe, &manager->services, rb) {
                _c_cleanup_(c_freep) char *object_path = NULL;

                if (service->state != SERVICE_STATE_DEFUNCT)
                        continue;

                r = asprintf(&object_path, "/org/bus1/DBus/Name/%s", service->id);
                if (r < 0)
                        return error_origin(-ENOMEM);

                r = sd_bus_call_method(manager->bus_controller,
                                       NULL,
                                       object_path,
                                       "org.bus1.DBus.Name",
                                       "Release",
                                       NULL,
                                       NULL,
                                       "");
                if (r < 0)
                        return error_origin(r);

                service_free(service);
        }

        return 0;
}

static int manager_load_standard_session_services(Manager *manager, NSSCache *nss_cache) {
        const char *suffix = "dbus-1/services";
        int r;

        /*
         * $XDG_RUNTIME_DIR/dbus-1/services is used in user-scope to
         * load transient units. dbus-daemon(1) actually creates this
         * path, we don't. It is incompatible with socket-activation of
         * dbus-daemon(1), so you must already be able to deal with
         * creating the directory yourself. But if the directory is
         * there, we load units from it.
         */
        {
                _c_cleanup_(c_freep) char *dirpath = NULL;
                const char *runtime_dir;

                runtime_dir = getenv("XDG_RUNTIME_DIR");
                if (!runtime_dir) {
                        fprintf(stderr, "Cannot figure out service runtime directory\n");
                } else {
                        r = asprintf(&dirpath, "%s/%s", runtime_dir, suffix);
                        if (r < 0)
                                return error_origin(-ENOMEM);

                        r = manager_load_service_dir(manager, dirpath, nss_cache);
                        if (r)
                                return error_trace(r);
                }
        }

        /*
         * $HOME/.local/share/dbus-1/services is used for user buses
         * additionally to the above mentioned directories. Note that
         * it can be modified via the XDG_DATA_HOME env-variable.
         */
        {
                _c_cleanup_(c_freep) char *data_home_dir = NULL;
                struct passwd *passwd;
                const char *dir;

                dir = getenv("XDG_DATA_HOME");
                if (dir) {
                        r = asprintf(&data_home_dir, "%s/%s", dir, suffix);
                        if (r < 0)
                                return error_origin(-ENOMEM);
                } else {
                        passwd = getpwuid(getuid());
                        if (passwd && passwd->pw_dir) {
                                r = asprintf(&data_home_dir, "%s/.local/share/%s", passwd->pw_dir, suffix);
                                if (r < 0)
                                        return error_origin(-ENOMEM);
                        }
                }
                if (!data_home_dir) {
                        fprintf(stderr, "Cannot figure out service home directory\n");
                } else {
                        r = manager_load_service_dir(manager, data_home_dir, nss_cache);
                        if (r)
                                return error_trace(r);
                }
        }

        /*
         * As last step, XDG_DATA_DIRS (or its default) are searched for
         * service files. ./dbus-1/services/ is appended to each path found in
         * XDG_DATA_DIRS.
         */
        {
                const char *data_dirs, *sep;
                size_t n;

                data_dirs = getenv("XDG_DATA_DIRS") ?:
                            "/usr/local/share:/usr/share";

                while (*data_dirs) {
                        sep = strchr(data_dirs, ':');
                        n = sep ? (size_t)(sep - data_dirs) : strlen(data_dirs);

                        if (n) {
                                _c_cleanup_(c_freep) char *dirpath = NULL;

                                r = asprintf(&dirpath, "%.*s/%s", (int)n, data_dirs, suffix);
                                if (r < 0)
                                        return error_origin(-ENOMEM);

                                r = manager_load_service_dir(manager, dirpath, nss_cache);
                                if (r)
                                        return error_trace(r);
                        }

                        data_dirs += n + !!sep;
                }
        }

        return 0;
}

static int manager_load_standard_system_services(Manager *manager, NSSCache *nss_cache) {
        static const char *default_data_dirs[] = {
                "/usr/local/share",
                "/usr/share",
                "/lib",
                NULL,
        };
        const char *suffix = "dbus-1/system-services";
        size_t i;
        int r;

        /*
         * In system scope, the default data directories are used. They
         * cannot be modified via env-variables!
         *
         * dbus-daemon(1) also supports /lib, which we don't. If there
         * is need, add it later.
         *
         * The order in which the directories are parsed follows the order
         * of dbus-daemon(1).
         */

        for (i = 0; default_data_dirs[i]; ++i) {
                _c_cleanup_(c_freep) char *dirpath = NULL;

                r = asprintf(&dirpath, "%s/%s", default_data_dirs[i], suffix);
                if (r < 0)
                        return error_origin(-ENOMEM);

                r = manager_load_service_dir(manager, dirpath, nss_cache);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

static int manager_load_services(Manager *manager, ConfigRoot *config, NSSCache *nss_cache) {
        ConfigNode *cnode;
        int r;

        c_list_for_each_entry(cnode, &config->node_list, root_link) {
                switch (cnode->type) {
                case CONFIG_NODE_STANDARD_SESSION_SERVICEDIRS:
                        r = manager_load_standard_session_services(manager, nss_cache);
                        if (r)
                                return error_trace(r);

                        break;
                case CONFIG_NODE_STANDARD_SYSTEM_SERVICEDIRS:
                        r = manager_load_standard_system_services(manager, nss_cache);
                        if (r)
                                return error_trace(r);

                        break;
                case CONFIG_NODE_SERVICEDIR:
                        r = manager_load_service_dir(manager, cnode->servicedir.path, nss_cache);
                        if (r)
                                return error_trace(r);

                        break;
                default:
                        /* ignored */
                        break;
                }

        }

        return 0;
}

static int manager_parse_config(Manager *manager, ConfigRoot **rootp, NSSCache *nss_cache) {
        _c_cleanup_(config_parser_deinit) ConfigParser parser = CONFIG_PARSER_NULL(parser);
        _c_cleanup_(dirwatch_freep) Dirwatch *dirwatch = NULL;
        uint64_t max_match_rules_per_connection = main_max_match_rules_per_connection;
        uint64_t max_connections_per_user = main_max_connections_per_user;
        uint64_t max_outgoing_unix_fds = main_max_outgoing_unix_fds;
        uint64_t max_outgoing_bytes = main_max_outgoing_bytes;
        const char *configfile;
        ConfigNode *cnode;
        int r;

        r = dirwatch_new(&dirwatch);
        if (r)
                return error_fold(r);

        if (main_arg_configfile)
                configfile = main_arg_configfile;
        else if (main_arg_user_scope)
                configfile = "/usr/share/dbus-1/session.conf";
        else
                configfile = "/usr/share/dbus-1/system.conf";

        config_parser_init(&parser);

        r = config_parser_read(&parser, rootp, configfile, nss_cache, dirwatch);
        if (r) {
                if (r == CONFIG_E_INVALID)
                        return MANAGER_E_INVALID_CONFIG;

                return error_fold(r);
        }

        manager->dirwatch = dirwatch_free(manager->dirwatch);
        manager->dirwatch_src = sd_event_source_unref(manager->dirwatch_src);

        manager->dirwatch = dirwatch;
        dirwatch = NULL;

        r = sd_event_add_io(manager->event,
                            &manager->dirwatch_src,
                            dirwatch_get_fd(manager->dirwatch),
                            EPOLLIN,
                            manager_on_dirwatch,
                            manager);
        if (r)
                return error_origin(r);

        c_list_for_each_entry(cnode, &(*rootp)->node_list, root_link) {
                switch (cnode->type) {
                case CONFIG_NODE_USER:
                        if (cnode->user.valid) {
                                manager->uid = cnode->user.uid;
                                manager->gid = cnode->user.gid;
                        }

                        break;
                case CONFIG_NODE_LIMIT:
                        switch (cnode->limit.name) {
                        case CONFIG_LIMIT_MAX_OUTGOING_BYTES:
                                max_outgoing_bytes = cnode->limit.value;
                                break;
                        case CONFIG_LIMIT_MAX_OUTGOING_UNIX_FDS:
                                max_outgoing_unix_fds = cnode->limit.value;
                                break;
                        case CONFIG_LIMIT_MAX_CONNECTIONS_PER_USER:
                                max_connections_per_user = cnode->limit.value;
                                break;
                        case CONFIG_LIMIT_MAX_MATCH_RULES_PER_CONNECTION:
                                max_match_rules_per_connection = cnode->limit.value;
                                break;
                        }

                        break;
                default:
                        /* ignored */
                        break;
                }
        }

        /* Convert the per-connection limits into per-user limits. */
        manager->max_bytes = util_umul64_saturating(max_connections_per_user, max_outgoing_bytes);
        manager->max_fds = util_umul64_saturating(max_connections_per_user, max_outgoing_unix_fds);
        manager->max_matches = util_umul64_saturating(max_connections_per_user, max_match_rules_per_connection);

        return 0;
}

static int manager_load_policy(Manager *manager, ConfigRoot *root, Policy *policy) {
        int r;

        r = policy_import(policy, root);
        if (r)
                return error_fold(r);

        policy_optimize(policy);

        return 0;
}

static int manager_add_listener(Manager *manager, Policy *policy, uint32_t *system_console_users, size_t n_system_console_users) {
        _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        r = sd_bus_message_new_method_call(manager->bus_controller,
                                           &m,
                                           NULL,
                                           "/org/bus1/DBus/Broker",
                                           "org.bus1.DBus.Broker",
                                           "AddListener");
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_append(m, "oh",
                                  "/org/bus1/DBus/Listener/0",
                                  manager->fd_listen);
        if (r < 0)
                return error_origin(r);

        r = policy_export(policy, m, system_console_users, n_system_console_users);
        if (r)
                return error_fold(r);

        r = sd_bus_call(manager->bus_controller, m, 0, NULL, NULL);
        if (r < 0)
                return error_origin(r);

        return 0;
}

static int manager_set_policy(Manager *manager, Policy *policy, uint32_t *system_console_users, size_t n_system_console_users) {
        _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        r = sd_bus_message_new_method_call(manager->bus_controller,
                                           &m,
                                           NULL,
                                           "/org/bus1/DBus/Listener/0",
                                           "org.bus1.DBus.Listener",
                                           "SetPolicy");
        if (r < 0)
                return error_origin(r);

        r = policy_export(policy, m, system_console_users, n_system_console_users);
        if (r)
                return error_fold(r);

        r = sd_bus_call(manager->bus_controller, m, 0, NULL, NULL);
        if (r < 0)
                return error_origin(r);

        return 0;
}

static int manager_reload_config(Manager *manager) {
        _c_cleanup_(config_root_freep) ConfigRoot *root = NULL;
        _c_cleanup_(policy_deinit) Policy policy = POLICY_INIT(policy);
        _c_cleanup_(nss_cache_deinit) NSSCache nss_cache = NSS_CACHE_INIT;
        _c_cleanup_(c_freep) uint32_t *system_console_users = NULL;
        size_t n_system_console_users;
        Service *service;
        int r, res;

        r = sd_notify(false, "RELOADING=1");
        if (r < 0)
                return error_origin(r);

        c_rbtree_for_each_entry(service, &manager->services, rb)
                service->state = SERVICE_STATE_DEFUNCT;

        r = nss_cache_populate(&nss_cache);
        if (r)
                goto out;

        r = manager_parse_config(manager, &root, &nss_cache);
        if (r)
                goto out;

        r = nss_cache_resolve_system_console_users(&nss_cache,
                                                   &system_console_users,
                                                   &n_system_console_users);
        if (r)
                return error_trace(r);

        r = manager_load_services(manager, root, &nss_cache);
        if (r)
                goto out;

        r = manager_load_policy(manager, root, &policy);
        if (r)
                goto out;

        switch (policy.apparmor_mode) {
        case CONFIG_APPARMOR_ENABLED: {
                bool enabled;

                /* XXX: See comments in manager_run() */

                r = bus_apparmor_is_enabled(&enabled);
                if (r)
                        return error_fold(r);

                if (enabled)
                        fprintf(stderr, "AppArmor enabled, but not supported. Ignoring.\n");

                policy.apparmor_mode = CONFIG_APPARMOR_DISABLED;
                break;
        }
        case CONFIG_APPARMOR_REQUIRED:
                fprintf(stderr, "AppArmor required, but not supported. Exiting.\n");

                r = sd_event_exit(manager->event, 0);
                if (r < 0)
                        return error_fold(r);

                return 0;
        }

        r = manager_remove_services(manager);
        if (r)
                goto out;

        r = manager_set_policy(manager, &policy, system_console_users, n_system_console_users);
        if (r)
                goto out;

        r = manager_add_services(manager);
        if (r)
                goto out;

out:
        res = sd_notify(false, "READY=1");
        if (res < 0)
                return error_origin(res);

        return error_trace(r);
}

static int manager_connect(Manager *manager) {
        int r;

        assert(!manager->bus_regular);

        if (main_arg_user_scope) {
                r = sd_bus_open_user(&manager->bus_regular);
                if (r < 0)
                        return error_origin(r);
        } else {
                r = sd_bus_open_system(&manager->bus_regular);
                if (r < 0)
                        return error_origin(r);
        }

        return 0;
}

static int bus_method_reload_config(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *manager = userdata;
        int r;

        r = manager_reload_config(manager);
        if (r) {
                if (r == MANAGER_E_INVALID_CONFIG)
                        return sd_bus_reply_method_errorf(message, "org.bus1.DBus.Controller.Error.InvalidConfig", "Invalid configuration. Reload ignored.");
                else
                        return error_fold(r);
        }

        return sd_bus_reply_method_return(message, NULL);
}

const sd_bus_vtable manager_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_METHOD("ReloadConfig", NULL, NULL, bus_method_reload_config, 0),

        SD_BUS_VTABLE_END
};

static int manager_run(Manager *manager) {
        _c_cleanup_(config_root_freep) ConfigRoot *root = NULL;
        _c_cleanup_(policy_deinit) Policy policy = POLICY_INIT(policy);
        _c_cleanup_(nss_cache_deinit) NSSCache nss_cache = NSS_CACHE_INIT;
        _c_cleanup_(c_freep) uint32_t *system_console_users = NULL;
        size_t n_system_console_users;
        int r, controller[2];

        r = nss_cache_populate(&nss_cache);
        if (r)
                return error_fold(r);

        r = manager_parse_config(manager, &root, &nss_cache);
        if (r)
                return error_trace(r);

        r = nss_cache_resolve_system_console_users(&nss_cache,
                                                   &system_console_users,
                                                   &n_system_console_users);
        if (r)
                return error_trace(r);

        r = manager_load_services(manager, root, &nss_cache);
        if (r)
                return error_trace(r);

        r = sd_notify(false, "READY=1");
        if (r < 0)
                return error_origin(r);

        r = manager_load_policy(manager, root, &policy);
        if (r)
                return error_trace(r);

        switch (policy.apparmor_mode) {
        case CONFIG_APPARMOR_ENABLED: {
                bool enabled;

                r = bus_apparmor_is_enabled(&enabled);
                if (r)
                        return error_fold(r);

                if (enabled)
                        fprintf(stderr, "AppArmor enabled, but not supported. Ignoring.\n");

                /* XXX: once the broker supports AppArmor, set this to DISABLED if and only if
                 *      it is disabled in the kernel. */
                policy.apparmor_mode = CONFIG_APPARMOR_DISABLED;
                break;
        }
        case CONFIG_APPARMOR_REQUIRED:
                fprintf(stderr, "AppArmor required, but not supported. Exiting.\n");

                /* XXX: once the broker supports AppArmor, set this to enabled if and only
                 *      if it is enabled in the kernel, and exit the launcher otherwise. */
                return 0;
        }

        assert(manager->fd_listen >= 0);

        r = socketpair(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, controller);
        if (r < 0)
                return error_origin(-errno);

        /* consumes FD controller[0] */
        r = sd_bus_set_fd(manager->bus_controller, controller[0], controller[0]);
        if (r < 0) {
                close(controller[0]);
                close(controller[1]);
                return error_origin(r);
        }

        /* consumes FD controller[1] */
        r = manager_fork(manager, controller[1]);
        if (r) {
                close(controller[1]);
                return error_trace(r);
        }

        r = sd_bus_add_object_vtable(manager->bus_controller, NULL, "/org/bus1/DBus/Controller", "org.bus1.DBus.Controller", manager_vtable, manager);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_add_filter(manager->bus_controller, NULL, manager_on_message, manager);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_start(manager->bus_controller);
        if (r < 0)
                return error_origin(r);

        r = manager_add_services(manager);
        if (r)
                return error_trace(r);

        r = manager_add_listener(manager, &policy, system_console_users, n_system_console_users);
        if (r)
                return error_trace(r);

        r = manager_connect(manager);
        if (r)
                return error_trace(r);

        r = sd_bus_attach_event(manager->bus_controller, manager->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_attach_event(manager->bus_regular, manager->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return error_origin(r);

        if (manager->uid != (uint32_t)-1) {
                r = util_drop_permissions(manager->uid, manager->gid);
                if (r)
                        return error_fold(r);
        }

        r = sd_event_loop(manager->event);
        if (r < 0)
                return error_origin(r);
        else if (r > 0)
                return MAIN_FAILED;

        return 0;
}

static int open_log(void) {
        _c_cleanup_(c_closep) int fd = -1;
        struct sockaddr_un address = {
                .sun_family = AF_UNIX,
                .sun_path = "/run/systemd/journal/socket",
        };
        int r;

        fd = socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
                return error_origin(-errno);

        r = connect(fd,
                    (struct sockaddr *)&address,
                    offsetof(struct sockaddr_un, sun_path) + strlen(address.sun_path));
        if (r < 0)
                return error_origin(-errno);

        log_init_journal_consume(&main_log, fd);
        fd = -1;
        return 0;
}

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

static int run(void) {
        _c_cleanup_(manager_freep) Manager *manager = NULL;
        int r;

        r = manager_new(&manager);
        if (r)
                return error_trace(r);

        r = manager_listen_inherit(manager);
        if (r)
                return error_trace(r);

        r = manager_run(manager);
        r = error_trace(r);

        return r;

}

int main(int argc, char **argv) {
        sigset_t mask_new, mask_old;
        int r;

        r = open_log();
        if (r)
                goto exit;

        r = parse_argv(argc, argv);
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
