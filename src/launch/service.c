/*
 * D-Bus Service
 *
 * A D-Bus service represents the connection between a DBus name and a systemd
 * service.
 *
 * Calling add or remove on a service adds or removes an activatable name in
 * the broker. Calling activate on a service starts the corresponding systemd
 * service.
 *
 * D-Bus services can specify a systemd service to start, or alternatively the
 * executable to be started. In the latter case, a transient unit is generated
 * based on the information in the D-Bus service.
 */

#include <c-rbtree.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>
#include "catalog/catalog-ids.h"
#include "launch/service.h"
#include "util/error.h"
#include "util/log.h"

static void log_append_bus_error(Log *log, const sd_bus_error *error) {
        log_appendf(log, "DBUS_BROKER_LAUNCH_BUS_ERROR_NAME=%s\n", error->name);
        log_appendf(log, "DBUS_BROKER_LAUNCH_BUS_ERROR_MESSAGE=%s\n", error->message);
}

static void log_append_service_path(Log *log, const char *path) {
        if (path)
                log_appendf(log, "DBUS_BROKER_LAUNCH_SERVICE_PATH=%s\n", path);
}

static void log_append_service_name(Log *log, const char *name) {
        if (name)
                log_appendf(log, "DBUS_BROKER_LAUNCH_SERVICE_NAME=%s\n", name);
}

static void log_append_service_unit(Log *log, const char *unit) {
        if (unit)
                log_appendf(log, "DBUS_BROKER_LAUNCH_SERVICE_UNIT=%s\n", unit);
}

static void log_append_service_user(Log *log, const char *user) {
        if (user)
                log_appendf(log, "DBUS_BROKER_LAUNCH_SERVICE_USER=%s\n", user);
}

static void log_append_service(Log *log, Service *service) {
        log_append_service_path(log, service->path);
        log_append_service_name(log, service->name);
        log_append_service_unit(log, service->unit);
        log_append_service_user(log, service->user);

        log_appendf(log, "DBUS_BROKER_LAUNCH_SERVICE_UID=%"PRIu32"\n", service->uid);
        log_appendf(log, "DBUS_BROKER_LAUNCH_SERVICE_INSTANCE=%"PRIu64"\n", service->instance);
        log_appendf(log, "DBUS_BROKER_LAUNCH_SERVICE_ID=%s\n", service->id);

        for (size_t i = 0; i < service->argc; ++i)
                log_appendf(log, "DBUS_BROKER_LAUNCH_ARG%zu=%s\n", i, service->argv[i]);
}

int service_compare(CRBTree *t, void *k, CRBNode *n) {
        Service *service = c_container_of(n, Service, rb);

        return strcmp(k, service->id);
}

int service_compare_by_name(CRBTree *t, void *k, CRBNode *n) {
        Service *service = c_container_of(n, Service, rb_by_name);

        return strcmp(k, service->name);
}

Service *service_free(Service *service) {
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
        free(service->path);
        sd_bus_slot_unref(service->slot);
        free(service);

        return NULL;
}

int service_update(Service *service, const char *path, const char *unit, size_t argc, char **argv, const char *user, uid_t uid) {
        service->path = c_free(service->path);
        service->unit = c_free(service->unit);
        service->argc = 0;
        service->argv = c_free(service->argv);
        service->user = c_free(service->user);
        service->uid = uid;

        if (path) {
                service->path = strdup(path);
                if (!service->path)
                        return error_origin(-ENOMEM);
        }

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

int service_new(Service **servicep,
                Launcher *launcher,
                const char *name,
                CRBNode **slot_by_name,
                CRBNode *parent_by_name,
                const char *path,
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

        service->launcher = launcher;
        service->rb = (CRBNode)C_RBNODE_INIT(service->rb);
        service->rb_by_name = (CRBNode)C_RBNODE_INIT(service->rb_by_name);
        sprintf(service->id, "%" PRIu64, ++launcher->service_ids);

        service->name = strdup(name);
        if (!service->name)
                return error_origin(-ENOMEM);

        r = service_update(service, path, unit, argc, argv, user, uid);
        if (r)
                return error_trace(r);

        slot = c_rbtree_find_slot(&launcher->services, service_compare, service->id, &parent);
        c_assert(slot);
        c_rbtree_add(&launcher->services, parent, slot, &service->rb);
        c_rbtree_add(&launcher->services_by_name, parent_by_name, slot_by_name, &service->rb_by_name);

        *servicep = service;
        service = NULL;
        return 0;
}

static int service_start_unit_handler(sd_bus_message *message, void *userdata, sd_bus_error *errorp) {
        Service *service = userdata;
        Launcher *launcher = service->launcher;
        _c_cleanup_(c_freep) char *object_path = NULL;
        const sd_bus_error *error;
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
                 *    pending. Most common scenario is the service launcher
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
                        if (!service->n_missing_unit++) {
                                log_append_here(&launcher->log, LOG_WARNING, 0, DBUS_BROKER_CATALOG_ACTIVATE_NO_UNIT);
                                log_append_bus_error(&launcher->log, error);
                                log_append_service(&launcher->log, service);

                                r = log_commitf(&launcher->log,
                                                "Activation request for '%s' failed: The systemd unit '%s' could not be found.\n",
                                                service->name,
                                                service->unit);
                                if (r)
                                        return error_fold(r);
                        }
                } else {
                        log_append_here(&launcher->log, LOG_ERR, 0, NULL);
                        log_append_bus_error(&launcher->log, error);
                        log_append_service(&launcher->log, service);

                        r = log_commitf(&launcher->log,
                                        "Activation request for '%s' failed.\n",
                                        service->name);
                        if (r)
                                return error_fold(r);
                }
        }


        /* unit failed, so reset pending activation requsets in the broker */
        r = asprintf(&object_path, "/org/bus1/DBus/Name/%s", service->id);
        if (r < 0)
                return error_origin(-errno);

        /* XXX: We should forward error-information to the activator. */
        r = sd_bus_call_method(service->launcher->bus_controller,
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

static int service_start_unit(Service *service) {
        Launcher *launcher = service->launcher;
        _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *method_call = NULL;
        int r;

        service->slot = sd_bus_slot_unref(service->slot);

        r = sd_bus_message_new_method_call(launcher->bus_regular, &method_call,
                                           "org.freedesktop.systemd1",
                                           "/org/freedesktop/systemd1",
                                           "org.freedesktop.systemd1.Manager",
                                           "StartUnit");
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_append(method_call, "ss", service->unit, "replace");
        if (r < 0)
                return error_origin(r);

        r = sd_bus_call_async(launcher->bus_regular, &service->slot, method_call, service_start_unit_handler, service, -1);
        if (r < 0)
                return error_origin(r);

        return 0;
}

static int service_start_transient_unit(Service *service) {
        Launcher *launcher = service->launcher;
        _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *method_call = NULL;
        _c_cleanup_(c_freep) char *unit = NULL;
        const char *unique_name;
        int r;

        service->slot = sd_bus_slot_unref(service->slot);

        r = sd_bus_get_unique_name(launcher->bus_regular, &unique_name);
        if (r < 0)
                return error_origin(r);

        r = asprintf(&unit, "dbus-%s-%s@%"PRIu64".service", unique_name, service->name, service->instance++);
        if (r < 0)
                return error_origin(-errno);

        r = sd_bus_message_new_method_call(launcher->bus_regular, &method_call,
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

        r = sd_bus_call_async(launcher->bus_regular, &service->slot, method_call, service_start_unit_handler, service, -1);
        if (r < 0)
                return error_origin(r);

        return 0;
}

int service_activate(Service *service) {
        int r;

        if (!strcmp(service->name, "org.freedesktop.systemd1")) {
                /*
                 * systemd activation requests are silently ignored.
                 * In the future this special-case can be dropped
                 * once systemd ships a service file without an
                 * Exec directive.
                 */
                return 0;
        }

        c_assert(service->running);

        if (service->unit) {
                r = service_start_unit(service);
                if (r)
                        return error_trace(r);
        } else if (service->argc > 0) {
                r = service_start_transient_unit(service);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

int service_add(Service *service) {
        Launcher *launcher = service->launcher;
        _c_cleanup_(c_freep) char *object_path = NULL;
        int r;

        if (service->running)
                return 0;

        r = asprintf(&object_path, "/org/bus1/DBus/Name/%s", service->id);
        if (r < 0)
                return error_origin(-ENOMEM);

        r = sd_bus_call_method(launcher->bus_controller,
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

        service->running = true;
        return 0;
}

int service_remove(Service *service) {
        Launcher *launcher = service->launcher;
        _c_cleanup_(c_freep) char *object_path = NULL;
        int r;

        if (!service->running)
                return 0;

        r = asprintf(&object_path, "/org/bus1/DBus/Name/%s", service->id);
        if (r < 0)
                return error_origin(-ENOMEM);

        r = sd_bus_call_method(launcher->bus_controller,
                               NULL,
                               object_path,
                               "org.bus1.DBus.Name",
                               "Release",
                               NULL,
                               NULL,
                               "");
        if (r < 0)
                return error_origin(r);

        service->running = false;
        return 0;
}
