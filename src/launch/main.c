/*
 * D-Bus Broker Launcher
 */

#include <c-macro.h>
#include <c-rbtree.h>
#include <c-string.h>
#include <fcntl.h>
#include <getopt.h>
#include <glib.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>
#include "launch/config.h"
#include "launch/nss-cache.h"
#include "launch/policy.h"
#include "util/error.h"
#include "util/log.h"

typedef struct Manager Manager;
typedef struct Service Service;

enum {
        _MAIN_SUCCESS,
        MAIN_EXIT,
        MAIN_FAILED,
};

typedef enum {
        SERVICE_STATE_PENDING,
        SERVICE_STATE_CURRENT,
        SERVICE_STATE_DEFUNCT,
} ServiceState;

struct Service {
        Manager *manager;
        ServiceState state;
        sd_bus_slot *slot;
        CRBNode rb;
        CRBNode rb_by_name;
        char *name;
        char *unit;
        char **exec;
        size_t n_exec;
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
        CRBTree services;
        CRBTree services_by_name;
        uint64_t service_ids;
};

static const char *     main_arg_broker = BINDIR "/dbus-broker";
static bool             main_arg_force = false;
static const char *     main_arg_listen = NULL;
static const char *     main_arg_scope = "system";
static const char *     main_arg_policypath = NULL;
static bool             main_arg_verbose = false;
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

C_DEFINE_CLEANUP(sd_bus *, bus_close_unref);

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
        for (size_t i = 0; i < service->n_exec; ++i)
                free(service->exec[i]);
        free(service->exec);
        free(service->unit);
        free(service->name);
        sd_bus_slot_unref(service->slot);
        free(service);

        return NULL;
}

C_DEFINE_CLEANUP(Service *, service_free);

static int service_update(Service *service, const char *unit, char **exec, size_t n_exec, const char *user, uid_t uid) {
        service->unit = c_free(service->unit);
        service->exec = c_free(service->exec);
        service->n_exec = 0;
        service->user = c_free(service->user);
        service->uid = uid;

        if (unit) {
                service->unit = strdup(unit);
                if (!service->unit)
                        return error_origin(-ENOMEM);
        }

        if (exec) {
                service->exec = calloc(1, n_exec * sizeof(char*));
                if (!service->exec)
                        return error_origin(-ENOMEM);

                service->n_exec = n_exec;

                for (size_t i = 0; i < n_exec; ++i) {
                        service->exec[i] = strdup(exec[i]);
                        if (!service->exec[i])
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
                       char **exec,
                       size_t n_exec,
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

        r = service_update(service, unit, exec, n_exec, user, uid);
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

        if (main_arg_verbose)
                fprintf(stderr, "Caught SIGHUP\n");

        r = manager_reload_config(manager);
        if (r)
                return error_fold(r);

        return 1;
}

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

static int manager_listen_path(Manager *manager, const char *path) {
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

        /*
         * The backlog parameter selects the maximum number of pending
         * connections on a listener socket. Unfortunately, there is no fair
         * queue sharing available, so any malicious peer can easily exhaust
         * this limit.
         *
         * On linux, this limit is capped to `net/core/somaxconn` sysctl, which
         * is 1024 by default. We simply use the same default value due to lack
         * of any other reasonable choice.
         *
         * Preferably, we would tie this to our quota-infrastructure somehow.
         * Unfortunately, there is still no mechanism to control this. Hence,
         * we simply stick to the same limits everyone else uses on AF_UNIX.
         */
        r = listen(s, 1024);
        if (r < 0)
                return error_origin(-errno);

        manager->fd_listen = s;
        s = -1;
        return 0;
}

static noreturn void manager_run_child(Manager *manager, int fd_log, int fd_controller, bool audit) {
        char str_log[C_DECIMAL_MAX(int) + 1], str_controller[C_DECIMAL_MAX(int) + 1];
        const char * const argv[] = {
                "dbus-broker",
                "-v",
                "--log",
                str_log,
                "--controller",
                str_controller,
                audit ? "--audit" : NULL, /* note that this needs to be the last argument to work */
                NULL,
        };
        int r;

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

        r = snprintf(str_log, sizeof(str_log), "%d", fd_log);
        assert(r < (ssize_t)sizeof(str_log));

        r = snprintf(str_controller, sizeof(str_controller), "%d", fd_controller);
        assert(r < (ssize_t)sizeof(str_controller));

        r = execve(main_arg_broker, (char * const *)argv, environ);
        r = error_origin(-errno);

exit:
        _exit(1);
}

static int manager_on_child_exit(sd_event_source *source, const siginfo_t *si, void *userdata) {
        if (main_arg_verbose)
                fprintf(stderr, "Caught SIGCHLD of broker\n");

        return sd_event_exit(sd_event_source_get_event(source),
                             (si->si_code == CLD_EXITED) ? si->si_status : EXIT_FAILURE);
}

static int manager_fork(Manager *manager, int fd_controller, bool audit) {
        pid_t pid;
        int r;

        pid = fork();
        if (pid < 0)
                return error_origin(-errno);

        if (!pid)
                manager_run_child(manager, log_get_fd(&main_log), fd_controller, audit);

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

        fprintf(stderr, "Activation request for '%s' failed: %s\n", service->name, error->message);

        /* unit failed, so reset pending activation requsets in the broker */
        r = asprintf(&object_path, "/org/bus1/DBus/Name/%s", service->id);
        if (r < 0)
                return error_origin(-errno);

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

        r = sd_bus_message_append(method_call, "ss", service->unit, "fail");
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
        int r;

        service->slot = sd_bus_slot_unref(service->slot);

        r = asprintf(&unit, "dbus-%s@%"PRIu64".service", service->name, service->instance++);
        if (r < 0)
                return error_origin(-errno);

        r = sd_bus_message_new_method_call(manager->bus_regular, &method_call,
                                           "org.freedesktop.systemd1",
                                           "/org/freedesktop/systemd1",
                                           "org.freedesktop.systemd1.Manager",
                                           "StartTransientUnit");
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_append(method_call, "ss", unit, "fail");
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
                                                r = sd_bus_message_append(method_call, "s", service->exec[0]);
                                                if (r < 0)
                                                        return error_origin(r);

                                                r = sd_bus_message_open_container(method_call, 'a', "s");
                                                if (r < 0)
                                                        return error_origin(r);

                                                {
                                                        for (size_t i = 0; i < service->n_exec; ++i) {
                                                                r = sd_bus_message_append(method_call, "s", service->exec[i]);
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

static int manager_load_service_file(Manager *manager, const char *path, NSSCache *nss_cache) {
        gchar *name = NULL, *user = NULL, *unit = NULL, **exec = NULL;
        gsize n_exec = 0;
        _c_cleanup_(service_freep) Service *service = NULL;
        GKeyFile *f;
        CRBNode **slot, *parent;
        uid_t uid;
        int r;

        /*
         * There seems to be no trivial way to properly parse D-Bus service
         * files. Hence, we resort to glib GKeyFile to parse it as a Desktop
         * File compatible ini-file.
         *
         * Preferably, we'd not have the glib dependency here, but it does not
         * hurt much either. If anyone cares, feel free to provide `c-ini'.
         */

        f = g_key_file_new();

        if (!g_key_file_load_from_file(f, path, G_KEY_FILE_NONE, NULL)) {
                fprintf(stderr, "Cannot load service file '%s'\n", path);
                r = 0;
                goto exit;
        }

        name = g_key_file_get_string(f, "D-BUS Service", "Name", NULL);
        user = g_key_file_get_string(f, "D-BUS Service", "User", NULL);
        unit = g_key_file_get_string(f, "D-BUS Service", "SystemdService", NULL);

        g_key_file_set_list_separator(f, ' ');
        exec = g_key_file_get_string_list(f, "D-BUS Service", "Exec", &n_exec, NULL);

        if (!name) {
                fprintf(stderr, "Missing name in service file '%s'\n", path);
                r = 0;
                goto exit;
        }

        if (!unit && !exec) {
                fprintf(stderr, "Missing exec or unit in service file '%s'\n", path);
                r = 0;
                goto exit;
        }

        if (user) {
                r = nss_cache_get_uid(nss_cache, &uid, user);
                if (r) {
                        if (r == NSS_CACHE_E_INVALID_NAME) {
                                fprintf(stderr, "Invalid user name '%s' in service file '%s'\n", user, path);
                                r = 0;
                                goto exit;
                        }
                }

        } else {
                uid = getuid();
        }

        slot = c_rbtree_find_slot(&manager->services_by_name, service_compare_by_name, name, &parent);
        if (slot) {
                r = service_new(&service, manager, name, slot, parent, unit, exec, n_exec, user, uid);
                if (r) {
                        r = error_trace(r);
                        goto exit;
                }
        } else {
                Service *old_service = c_container_of(parent, Service, rb_by_name);

                if (old_service->state == SERVICE_STATE_DEFUNCT) {
                        old_service->state = SERVICE_STATE_CURRENT;
                        r = service_update(old_service, unit, exec, n_exec, user, uid);
                        if (r)
                                r = error_trace(r);
                } else {
                        fprintf(stderr, "Ignoring duplicate name '%s' in service file '%s'\n", name, path);
                        r = 0;
                }
                goto exit;
        }

        service = NULL;
        r = 0;

exit:
        g_free(unit);
        g_free(user);
        g_free(name);
        g_strfreev(exec);
        g_key_file_free(f);
        return r;
}

static int manager_load_service_dir(Manager *manager, const char *dirpath, const char *subdir, NSSCache *nss_cache) {
        const char suffix[] = ".service";
        _c_cleanup_(c_freep) char *full_dir = NULL;
        _c_cleanup_(c_closedirp) DIR *dir = NULL;
        struct dirent *de;
        char *path;
        size_t n;
        int r;

        r = asprintf(&full_dir, "%s/%s", dirpath, subdir);
        if (r < 0)
                return error_origin(-ENOMEM);

        dir = opendir(full_dir);
        if (!dir) {
                if (errno == ENOENT || errno == ENOTDIR)
                        return 0;
                else
                        return error_origin(-errno);
        }

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

                r = asprintf(&path, "%s/%s", full_dir, de->d_name);
                if (r < 0)
                        return error_origin(-ENOMEM);

                r = manager_load_service_file(manager, path, nss_cache);
                free(path);
                if (r)
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

static int manager_load_services(Manager *manager, NSSCache *nss_cache) {
        static const char *default_data_dirs[] = {
                "/usr/local/share",
                "/usr/share",
                NULL,
        };
        _c_cleanup_(c_freep) char *data_home_dir = NULL;
        const char **dirs, *dir, *suffix, *runtime_dir = NULL;
        struct passwd *passwd;
        size_t i;
        int r;

        if (!strcmp(main_arg_scope, "user")) {
                /*
                 * dbus-daemon(1) allows the default search path to be modified
                 * via the XDG_DATA_DIRS env-variable. We do not implement this
                 * so far. If there is need, we can add it later.
                 */
                suffix = "dbus-1/services";
                dirs = default_data_dirs;

                /*
                 * $HOME/.local/share/dbus-1/services is used for user buses
                 * additionally to the above mentioned directories. Note that
                 * it can be modified via the XDG_DATA_HOME env-variable.
                 */
                dir = secure_getenv("XDG_DATA_HOME");
                if (dir) {
                        data_home_dir = strdup(dir);
                        if (!data_home_dir)
                                return error_origin(-ENOMEM);
                } else {
                        passwd = getpwuid(getuid());
                        if (passwd && passwd->pw_dir) {
                                r = asprintf(&data_home_dir, "%s/.local/share", passwd->pw_dir);
                                if (r < 0)
                                        return error_origin(-ENOMEM);
                        }
                }
                if (!data_home_dir)
                        fprintf(stderr, "Cannot figure out service home directory\n");

                /*
                 * $XDG_RUNTIME_DIR/dbus-1/services is used in user-scope to
                 * load transient units. dbus-daemon(1) actually creates this
                 * path, we don't. It is incompatible with socket-activation of
                 * dbus-daemon(1), so you must already be able to deal with
                 * creating the directory yourself. But if the directory is
                 * there, we load units from it.
                 */
                runtime_dir = secure_getenv("XDG_RUNTIME_DIR");
                if (!runtime_dir)
                        fprintf(stderr, "Cannot figure out service runtime directory\n");
        } else if (!strcmp(main_arg_scope, "system")) {
                /*
                 * In system scope, the default data directories are used. They
                 * cannot be modified via env-variables!
                 *
                 * dbus-daemon(1) also supports /lib, which we don't. If there
                 * is need, add it later.
                 */
                suffix = "dbus-1/system-services";
                dirs = default_data_dirs;
        } else {
                return error_origin(-ENOTRECOVERABLE);
        }

        /*
         * Now parse all the directories and read the stored service files. The
         * order in which these are parsed follows the order of dbus-daemon(1).
         */

        if (runtime_dir) {
                r = manager_load_service_dir(manager, runtime_dir, suffix, nss_cache);
                if (r)
                        return error_trace(r);
        }

        if (data_home_dir) {
                r = manager_load_service_dir(manager, data_home_dir, suffix, nss_cache);
                if (r)
                        return error_trace(r);
        }

        for (i = 0; dirs[i]; ++i) {
                r = manager_load_service_dir(manager, dirs[i], suffix, nss_cache);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

static int manager_load_policy(Manager *manager, ConfigRoot **rootp, Policy *policy, NSSCache *nss_cache) {
        _c_cleanup_(config_parser_deinit) ConfigParser parser = CONFIG_PARSER_NULL(parser);
        const char *policypath;
        int r;

        if (main_arg_policypath)
                policypath = main_arg_policypath;
        else if (!strcmp(main_arg_scope, "user"))
                policypath = "/usr/share/dbus-1/session.conf";
        else if (!strcmp(main_arg_scope, "system"))
                policypath = "/usr/share/dbus-1/system.conf";
        else
                return error_origin(-ENOTRECOVERABLE);

        config_parser_init(&parser);

        r = config_parser_read(&parser, rootp, policypath, nss_cache);
        if (r)
                return error_fold(r);

        r = policy_import(policy, *rootp);
        if (r)
                return error_fold(r);

        policy_optimize(policy);

        return 0;
}

static int manager_add_listener(Manager *manager, Policy *policy) {
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

        r = policy_export(policy, m);
        if (r)
                return error_fold(r);

        r = sd_bus_call(manager->bus_controller, m, 0, NULL, NULL);
        if (r < 0)
                return error_origin(r);

        return 0;
}

static int manager_set_policy(Manager *manager, Policy *policy) {
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

        r = policy_export(policy, m);
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
        _c_cleanup_(nss_cache_deinit) NSSCache nss_cache = (NSSCache)NSS_CACHE_INIT;
        Service *service;
        int r;

        c_rbtree_for_each_entry(service, &manager->services, rb)
                service->state = SERVICE_STATE_DEFUNCT;

        r = manager_load_services(manager, &nss_cache);
        if (r)
                return error_trace(r);

        r = manager_load_policy(manager, &root, &policy, &nss_cache);
        if (r)
                return error_trace(r);

        r = manager_remove_services(manager);
        if (r)
                return error_trace(r);

        r = manager_set_policy(manager, &policy);
        if (r)
                return error_trace(r);

        r = manager_add_services(manager);
        if (r)
                return error_trace(r);

        return 0;
}

static int manager_connect(Manager *manager) {
        _c_cleanup_(bus_close_unrefp) sd_bus *b = NULL;
        _c_cleanup_(c_closep) int s = -1;
        struct sockaddr_un addr;
        socklen_t n_addr = sizeof(addr);
        int r;

        assert(!manager->bus_regular);

        s = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (s < 0)
                return error_origin(-errno);

        r = getsockname(manager->fd_listen, (struct sockaddr *)&addr, &n_addr);
        if (r < 0)
                return error_origin(-r);

        r = connect(s, (struct sockaddr *)&addr, n_addr);
        if (r < 0)
                return error_origin(-r);

        r = sd_bus_new(&b);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_set_fd(b, s, s);
        if (r < 0)
                return error_origin(r);

        s = -1;

        r = sd_bus_set_bus_client(b, true);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_start(b);
        if (r < 0)
                return error_origin(r);

        manager->bus_regular = b;
        b = NULL;
        return 0;
}

static int bus_method_reload_config(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *manager = userdata;
        int r;

        r = manager_reload_config(manager);
        if (r)
                return error_fold(r);

        return sd_bus_reply_method_return(message, NULL);
}

const sd_bus_vtable manager_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_METHOD("ReloadConfig", NULL, NULL, bus_method_reload_config, 0),

        SD_BUS_VTABLE_END
};

static int manager_run(Manager *manager, bool audit) {
        _c_cleanup_(config_root_freep) ConfigRoot *root = NULL;
        _c_cleanup_(policy_deinit) Policy policy = POLICY_INIT(policy);
        _c_cleanup_(nss_cache_deinit) NSSCache nss_cache = NSS_CACHE_INIT;
        int r, controller[2];

        r = manager_load_services(manager, &nss_cache);
        if (r)
                return error_trace(r);

        r = manager_load_policy(manager, &root, &policy, &nss_cache);
        if (r)
                return error_trace(r);

        r = sd_notify(false, "READY=1");
        if (r < 0)
                return error_origin(r);

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
        r = manager_fork(manager, controller[1], audit);
        if (r) {
                close(controller[1]);
                return error_trace(r);
        }

        r = sd_bus_add_object_vtable(manager->bus_controller, NULL, "/org/bus1/DBus/Launcher", "org.bus1.DBus.Launcher", manager_vtable, manager);
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

        r = manager_add_listener(manager, &policy);
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
               "  -v --verbose          Print progress to terminal\n"
               "     --listen PATH      Specify path of listener socket\n"
               "  -f --force            Ignore existing listener sockets\n"
               "     --scope SCOPE      Scope of message bus\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_LISTEN,
                ARG_SCOPE,
        };
        static const struct option options[] = {
                { "help",               no_argument,            NULL,   'h'                     },
                { "version",            no_argument,            NULL,   ARG_VERSION             },
                { "verbose",            no_argument,            NULL,   'v'                     },
                { "listen",             required_argument,      NULL,   ARG_LISTEN              },
                { "force",              no_argument,            NULL,   'f'                     },
                { "scope",              required_argument,      NULL,   ARG_SCOPE               },
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

                case ARG_SCOPE:
                        if (strcmp(optarg, "system") &&
                            strcmp(optarg, "user")) {
                                fprintf(stderr, "%s: invalid message bus scope -- '%s'\n", program_invocation_name, optarg);
                                return MAIN_FAILED;
                        }

                        main_arg_scope = optarg;
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
        _c_cleanup_(c_freep) char *listen_path = NULL;
        const char *t, *path = NULL, *unlink_path = NULL;
        int r;

        r = manager_new(&manager);
        if (r)
                return error_trace(r);

        if (main_arg_listen) {
                path = main_arg_listen;
        } else if (!strcmp(main_arg_scope, "user")) {
                t = getenv("XDG_RUNTIME_DIR");
                if (t)
                        r = asprintf(&listen_path, "%s/bus", t);
                else
                        r = asprintf(&listen_path, "/var/run/user/%u/bus", getuid());
                if (r < 0)
                        return error_origin(-ENOMEM);

                path = listen_path;
        } else if (!strcmp(main_arg_scope, "system")) {
                path = "/var/run/dbus/system_bus_socket";
        } else {
                return error_origin(-ENOTRECOVERABLE);
        }

        if (!strcmp(path, "inherit")) {
                r = manager_listen_inherit(manager);
                if (r)
                        return error_trace(r);

                if (main_arg_verbose)
                        fprintf(stderr, "Listening on inherited socket\n");
        } else if (path[0] == '/') {
                if (main_arg_force) {
                        r = unlink(path);
                        if (r < 0) {
                                if (errno != ENOENT)
                                        return error_origin(-errno);
                                else if (main_arg_verbose)
                                        fprintf(stderr, "No conflict on socket '%s'\n", path);
                        } else if (main_arg_verbose) {
                                fprintf(stderr, "Forcibly removed conflicting socket '%s'\n", path);
                        }
                }

                r = manager_listen_path(manager, path);
                if (r)
                        return error_trace(r);

                unlink_path = path;

                if (main_arg_verbose)
                        fprintf(stderr, "Listening on socket '%s'\n", path);
        } else {
                fprintf(stderr, "Invalid listener socket '%s'\n", path);
                return MAIN_FAILED;
        }

        r = manager_run(manager, !strcmp(main_arg_scope, "system"));
        r = error_trace(r);

        if (unlink_path) {
                r = unlink(unlink_path);
                if (r < 0)
                        return error_origin(-errno);
        }

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
        if (r < 0 && main_arg_verbose)
                fprintf(stderr, "Exiting due to fatal error: %d\n", r);
        return (r == 0 || r == MAIN_EXIT) ? 0 : 1;
}
