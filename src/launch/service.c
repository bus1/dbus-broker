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
#include "broker/controller.h"
#include "catalog/catalog-ids.h"
#include "launch/service.h"
#include "util/error.h"
#include "util/log.h"
#include "util/systemd.h"

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
        log_append_service_name(log, service->name);

        if (service->active_data) {
                log_append_service_path(log, service->active_data->path);
                log_append_service_unit(log, service->active_data->unit);
                log_append_service_user(log, service->active_data->user);
                log_appendf(
                        log,
                        "DBUS_BROKER_LAUNCH_SERVICE_UID=%"PRIu32"\n",
                        service->active_data->uid
                );
                for (size_t i = 0; i < service->active_data->argc; ++i)
                        log_appendf(
                                log,
                                "DBUS_BROKER_LAUNCH_ARG%zu=%s\n",
                                i,
                                service->active_data->argv[i]
                        );
        } else {
                log_append_service_path(log, service->data->path);
                log_append_service_unit(log, service->data->unit);
                log_append_service_user(log, service->data->user);
                log_appendf(
                        log,
                        "DBUS_BROKER_LAUNCH_SERVICE_UID=%"PRIu32"\n",
                        service->data->uid
                );
                for (size_t i = 0; i < service->data->argc; ++i)
                        log_appendf(
                                log,
                                "DBUS_BROKER_LAUNCH_ARG%zu=%s\n",
                                i,
                                service->data->argv[i]
                        );
        }

        log_appendf(
                log,
                "DBUS_BROKER_LAUNCH_SERVICE_INSTANCE=%"PRIu64"\n",
                service->instance
        );
        log_appendf(
                log,
                "DBUS_BROKER_LAUNCH_SERVICE_ID=%s\n",
                service->id
        );
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

        r = service_data_new(&service->data, path, unit, user, uid, argc, argv);
        if (r)
                return error_fold(r);

        slot = c_rbtree_find_slot(&launcher->services, service_compare, service->id, &parent);
        c_assert(slot);
        c_rbtree_add(&launcher->services, parent, slot, &service->rb);
        c_rbtree_add(&launcher->services_by_name, parent_by_name, slot_by_name, &service->rb_by_name);

        *servicep = service;
        service = NULL;
        return 0;
}

Service *service_free(Service *service) {
        if (!service)
                return NULL;

        c_rbnode_unlink(&service->rb_by_name);
        c_rbnode_unlink(&service->rb);

        service_data_free(service->data);
        free(service->name);

        free(service->job);
        free(service->active_unit);
        service_data_free(service->active_data);

        service->slot_start_unit = sd_bus_slot_unref(service->slot_start_unit);
        service->slot_watch_unit = sd_bus_slot_unref(service->slot_watch_unit);
        service->slot_watch_jobs = sd_bus_slot_unref(service->slot_watch_jobs);
        free(service);

        return NULL;
}

int service_update(Service *service, const char *path, const char *unit, size_t argc, char **argv, const char *user, uid_t uid) {
        ServiceData *data;
        int r;

        r = service_data_new(&data, path, unit, user, uid, argc, argv);
        if (r)
                return error_fold(r);

        service_data_free(service->data);
        service->data = data;
        return 0;
}

int service_compare(CRBTree *t, void *k, CRBNode *n) {
        Service *service = c_container_of(n, Service, rb);

        return strcmp(k, service->id);
}

int service_compare_by_name(CRBTree *t, void *k, CRBNode *n) {
        Service *service = c_container_of(n, Service, rb_by_name);

        return strcmp(k, service->name);
}

static void service_discard_activation(Service *service) {
        service->job = c_free(service->job);
        service->active_unit = c_free(service->active_unit);
        service->active_data = service_data_free(service->active_data);
        service->is_transient = false;
        service->slot_start_unit = sd_bus_slot_unref(service->slot_start_unit);
        service->slot_watch_unit = sd_bus_slot_unref(service->slot_watch_unit);
        service->slot_watch_jobs = sd_bus_slot_unref(service->slot_watch_jobs);
}

static int service_reset_activation(Service *service, unsigned int name_error) {
        _c_cleanup_(c_freep) char *object_path = NULL;
        int r;

        service_discard_activation(service);

        r = asprintf(&object_path, "/org/bus1/DBus/Name/%s", service->id);
        if (r < 0)
                return error_origin(-errno);

        r = sd_bus_call_method(service->launcher->bus_controller,
                               NULL,
                               object_path,
                               "org.bus1.DBus.Name",
                               "Reset",
                               NULL,
                               NULL,
                               "ts",
                               service->last_serial,
                               controller_name_error_to_string(name_error));
        if (r < 0)
                return error_origin(r);

        return 0;
}

static int service_watch_jobs_handler(sd_bus_message *message, void *userdata, sd_bus_error *errorp) {
        Service *service = userdata;
        const char *path = NULL, *unit = NULL, *result = NULL;
        uint32_t id;
        int r;

        /*
         * Whenever we have an activation job queued, we want to know when it
         * is done. We get a `JobRemoved` signal from systemd, which includes
         * the reason why the job is done.
         * We get those signals for all jobs, since we cannot know a job-id to
         * match for before we create job. This is quite unfortunate, but
         * little we can do about it now.
         *
         * We require this signal merely to know when systemd finished handling
         * a job. For properly configured services, this should already tell us
         * whether the startup was successful or failed. But for basic services
         * that use no notify or dbus systemd-startup handling, we have to
         * continue tracking their `ActiveState` to see whether they failed.
         */

        r = sd_bus_message_read(message, "uoss", &id, &path, &unit, &result);
        if (r < 0)
                return error_origin(r);

        if (!service->job || strcmp(path, service->job))
                return 0;

        if (!strcmp(result, "done") || !strcmp(result, "skipped")) {
                /*
                 * Our job completed successfully. Make sure to stop watching
                 * it so the `ActiveState` handling will take effect.
                 */
                service->job = c_free(service->job);
                service->slot_watch_jobs = sd_bus_slot_unref(service->slot_watch_jobs);
        } else {
                /*
                 * Our job failed. Forward this information to the broker so it
                 * can fail pending activations.
                 */
                r = service_reset_activation(
                        service,
                        !strcmp(result, "skipped")
                                ? CONTROLLER_NAME_ERROR_STARTUP_SKIPPED
                                : CONTROLLER_NAME_ERROR_STARTUP_FAILURE
                );
                if (r)
                        return error_trace(r);
        }

        return 0;
}

static int service_watch_jobs(Service *service) {
        int r;

        assert(!service->slot_watch_jobs);
        assert(!service->job);

        r = sd_bus_match_signal_async(
                service->launcher->bus_regular,
                &service->slot_watch_jobs,
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "JobRemoved",
                service_watch_jobs_handler,
                NULL,
                service
        );
        if (r < 0)
                return error_origin(r);

        return 0;
}

static int service_start_unit_handler(sd_bus_message *message, void *userdata, sd_bus_error *errorp) {
        Service *service = userdata;
        Launcher *launcher = service->launcher;
        unsigned int name_error;
        const sd_bus_error *error;
        const char *job;
        int r;

        service->slot_start_unit = sd_bus_slot_unref(service->slot_start_unit);

        error = sd_bus_message_get_error(message);
        if (!error) {
                /*
                 * We successfully queued the job. Now remember the job path,
                 * so we can properly track when it finishes (via the
                 * JobRemoved signal).
                 */

                assert(!service->job);

                r = sd_bus_message_read(message, "o", &job);
                if (r < 0)
                        return error_origin(r);

                service->job = strdup(job);
                if (!service->job)
                        return error_origin(-ENOMEM);

                return 1;
        }

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
                 *  * `UnitMasked` from systemd tells us that the administrator
                 *    masked the unit we want to activate. This is again a
                 *    valid way to disable a service locally. Similar to
                 *    `NoSuchUnit` we warn once and then stay silent.
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
                                                service->active_unit);
                                if (r)
                                        return error_fold(r);
                        }

                        name_error = CONTROLLER_NAME_ERROR_UNKNOWN_UNIT;
                } else if (strcmp(error->name, "org.freedesktop.systemd1.UnitMasked") == 0) {
                        if (!service->n_masked_unit++) {
                                log_append_here(&launcher->log, LOG_NOTICE, 0, DBUS_BROKER_CATALOG_ACTIVATE_MASKED_UNIT);
                                log_append_bus_error(&launcher->log, error);
                                log_append_service(&launcher->log, service);

                                r = log_commitf(&launcher->log,
                                                "Activation request for '%s' failed: The systemd unit '%s' is masked.\n",
                                                service->name,
                                                service->active_unit);
                                if (r)
                                        return error_fold(r);
                        }

                        name_error = CONTROLLER_NAME_ERROR_MASKED_UNIT;
                } else {
                        log_append_here(&launcher->log, LOG_ERR, 0, NULL);
                        log_append_bus_error(&launcher->log, error);
                        log_append_service(&launcher->log, service);

                        r = log_commitf(&launcher->log,
                                        "Activation request for '%s' failed.\n",
                                        service->name);
                        if (r)
                                return error_fold(r);

                        name_error = CONTROLLER_NAME_ERROR_INVALID_UNIT;
                }
        } else {
                name_error = CONTROLLER_NAME_ERROR_DESTRUCTIVE_TRANSACTION;
        }

        r = service_reset_activation(service, name_error);
        if (r)
                return error_trace(r);

        return 1;
}

static int service_start_unit(Service *service) {
        Launcher *launcher = service->launcher;
        _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *method_call = NULL;
        int r;

        r = sd_bus_message_new_method_call(launcher->bus_regular, &method_call,
                                           "org.freedesktop.systemd1",
                                           "/org/freedesktop/systemd1",
                                           "org.freedesktop.systemd1.Manager",
                                           "StartUnit");
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_append(method_call, "ss", service->active_unit, "replace");
        if (r < 0)
                return error_origin(r);

        r = sd_bus_call_async(launcher->bus_regular, &service->slot_start_unit, method_call, service_start_unit_handler, service, -1);
        if (r < 0)
                return error_origin(r);

        return 0;
}

static int service_start_transient_unit(Service *service) {
        Launcher *launcher = service->launcher;
        _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *method_call = NULL;
        int r;

        r = sd_bus_message_new_method_call(launcher->bus_regular, &method_call,
                                           "org.freedesktop.systemd1",
                                           "/org/freedesktop/systemd1",
                                           "org.freedesktop.systemd1.Manager",
                                           "StartTransientUnit");
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_append(method_call, "ss", service->active_unit, "replace");
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
                                                r = sd_bus_message_append(method_call, "s", service->active_data->argv[0]);
                                                if (r < 0)
                                                        return error_origin(r);

                                                r = sd_bus_message_open_container(method_call, 'a', "s");
                                                if (r < 0)
                                                        return error_origin(r);

                                                {
                                                        for (size_t i = 0; i < service->active_data->argc; ++i) {
                                                                r = sd_bus_message_append(method_call, "s", service->active_data->argv[i]);
                                                                if (r < 0)
                                                                        return error_origin(r);
                                                        }
                                                }

                                                r = sd_bus_message_close_container(method_call);
                                                if (r < 0)
                                                        return error_origin(r);

                                                r = sd_bus_message_append(method_call, "b", false);
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

                r = sd_bus_message_open_container(method_call, 'r', "sv");
                if (r < 0)
                        return error_origin(r);

                {
                        r = sd_bus_message_append(method_call, "s", "CollectMode");
                        if (r < 0)
                                return error_origin(r);

                        r = sd_bus_message_open_container(method_call, 'v', "s");
                        if (r < 0)
                                return error_origin(r);

                        {
                                r = sd_bus_message_append(method_call, "s", "inactive-or-failed");
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

                if (service->active_data->user) {
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
                                        r = asprintf(&uid, "%"PRIu32, service->active_data->uid);
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

        r = sd_bus_call_async(launcher->bus_regular, &service->slot_start_unit, method_call, service_start_unit_handler, service, -1);
        if (r < 0)
                return error_origin(r);

        return 0;
}

static int service_watch_unit_handler(sd_bus_message *message, void *userdata, sd_bus_error *errorp) {
        Service *service = userdata;
        const char *interface = NULL, *property = NULL, *value = NULL;
        int r, condition_result = 1;

        /*
         * If we still watch the job-signals it means systemd has not yet fully
         * finished our job. In this case, any errors will be caught by the
         * `JobRemoved` handler and we do not have to track the unit, yet.
         * Moreover, we must not track the unit, since it might still return
         * failures before our job was actually handled by systemd.
         *
         * Hence, simply ignore any PropertiesChanged signals until we got
         * confirmation by systemd that our job finished. Bus ordering will
         * guarantee that we catch unit-failures both before and after the job
         * completion.
         */
        if (service->slot_watch_jobs)
                return 0;

        /*
         * The properties of the bus unit changed. We are only interested in
         * the "ActiveState" and "ConditionResult" properties. We check whether
         * it is included in the payload. If not, we ignore the signal.
         *
         * Note that we rely on systemd including it with value in the signal.
         * We will not query it, if it was merely invalidated. This is a
         * systemd API guarantee, and we rely on it.
         */

        /* Parse: "s" */
        {
                r = sd_bus_message_read(message, "s", &interface);
                if (r < 0)
                        return error_origin(r);
        }

        /* We are not interested in properties other than the Unit-Interface */
        if (strcmp(interface, "org.freedesktop.systemd1.Unit") != 0)
                return 0;

        /* Parse: "a{sv}" */
        {
                r = sd_bus_message_enter_container(message, 'a', "{sv}");
                if (r < 0)
                        return error_origin(r);

                while (!sd_bus_message_at_end(message, false)) {
                        r = sd_bus_message_enter_container(message, 'e', "sv");
                        if (r < 0)
                                return error_origin(r);

                        r = sd_bus_message_read(message, "s", &property);
                        if (r < 0)
                                return error_origin(r);

                        if (!strcmp(property, "ActiveState")) {
                                r = sd_bus_message_enter_container(message, 'v', "s");
                                if (r < 0)
                                        return error_origin(r);

                                r = sd_bus_message_read(message, "s", &value);
                                if (r < 0)
                                        return error_origin(r);

                                r = sd_bus_message_exit_container(message);
                                if (r < 0)
                                        return error_origin(r);
                        } else if (!strcmp(property, "ConditionResult")) {
                                r = sd_bus_message_enter_container(message, 'v', "b");
                                if (r < 0)
                                        return error_origin(r);

                                r = sd_bus_message_read(message, "b", &condition_result);
                                if (r < 0)
                                        return error_origin(r);

                                r = sd_bus_message_exit_container(message);
                                if (r < 0)
                                        return error_origin(r);
                        } else {
                                r = sd_bus_message_skip(message, "v");
                                if (r < 0)
                                        return error_origin(r);
                        }

                        r = sd_bus_message_exit_container(message);
                        if (r < 0)
                                return error_origin(r);
                }

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return error_origin(r);
        }

        /*
         * The possible values of "ActiveState" are:
         *
         *   active, reloading, inactive, failed, activating, deactivating
         *
         * We are never interested in positive results, because the broker
         * already gets those by tracking the name to be acquired. Therefore,
         * we only ever track negative results. This means we only ever react
         * to "failed".
         * We could also react to units entering "inactive", but we cannot know
         * upfront whether the unit is just a oneshot unit and thus is expected
         * to enter "inactive" when it finished. Hence, we simply require
         * anything to explicitly fail if they want to reset the activation.
         *
         * Additionally, we also check for "ConditionResult". If false, systemd
         * did not start the unit due to unsatisfied conditions, however, it
         * still considers the job a success. We need to consider it a failure,
         * though, as the job will never end up claiming its name.
         */
        if ((value && !strcmp(value, "failed")) || !condition_result) {
                r = service_reset_activation(service, CONTROLLER_NAME_ERROR_UNIT_FAILURE);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

static int service_watch_unit_load_handler(sd_bus_message *message, void *userdata, sd_bus_error *errorp) {
        Service *service = userdata;
        const char *object_path;
        int r;

        service->slot_watch_unit = sd_bus_slot_unref(service->slot_watch_unit);

        if (sd_bus_message_get_error(message)) {
                service_reset_activation(service, CONTROLLER_NAME_ERROR_UNIT_FAILURE);
                return 1;
        }

        r = sd_bus_message_read(message, "o", &object_path);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_match_signal_async(
                service->launcher->bus_regular,
                &service->slot_watch_unit,
                "org.freedesktop.systemd1",
                object_path,
                "org.freedesktop.DBus.Properties",
                "PropertiesChanged",
                service_watch_unit_handler,
                NULL,
                service
        );
        if (r < 0)
                return error_origin(r);

        /*
         * With the correct `PropertiesChanged` match installed, we can start
         * the service. For classic activation, we use transient units. For
         * systemd activation, we just spawn the specified unit.
         */

        if (service->is_transient)
                r = service_start_transient_unit(service);
        else
                r = service_start_unit(service);
        if (r)
                return error_fold(r);

        return 1;
}

static int service_watch_unit(Service *service, const char *unit) {
        int r;

        assert(!service->slot_watch_unit);

        /*
         * We first fetch the object-path for the unit in question, then we
         * install a watch-handler for its properties. We re-use the
         * `slot_watch_unit` slot for both operations.
         * By fetching the object-path first, we resolve possible aliases and
         * avoid hard-coding the object-path translation of systemd.
         *
         * XXX: Changes to the unit that cause changes to the object-path while
         *      we use it will likely cause us to watch the wrong signals. We
         *      accept this for now as it can be argued to be a
         *      misconfiguration. But a proper fix would be nice in the future.
         */

        r = sd_bus_call_method_async(
                service->launcher->bus_regular,
                &service->slot_watch_unit,
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "LoadUnit",
                service_watch_unit_load_handler,
                service,
                "s",
                unit
        );
        if (r < 0)
                return error_origin(r);

        return 0;
}

/**
 * service_activate() - trigger a service activation
 * @service:            service to activate
 * @serial:             activation serial number
 *
 * This activates the specified service. Any previous activation is discarded
 * silently. The new activation replaces a possible old one.
 *
 * An activation starts the systemd unit that the dbus-service-file configured.
 * In case no unit was specified, a transient unit is created, which spawns the
 * executable specified in the dbus-service-file.
 *
 * The launcher never tracks successfull activations. It is up to the broker to
 * consider an activation successful, once the corresponding bus-name is
 * claimed. Furthermore, the broker is free to consider an activation failed at
 * any point in time, without notifying the launcher. There is no need to
 * cancel the activation in the launcher.
 *
 * The role of the launcher is merely to start the right units on request, and
 * track whenever those fail. If they fail, the activation is discarded and the
 * failure is forwarded to the broker. However, it is not the job of the
 * launcher to tell whether an activation succeeded.
 *
 * Long story short, this function triggers an activation and tracks the status
 * of the activation until it fails. If it fails, the information is forwarded
 * to the broker and the activation is discarded. If it does not fail, it
 * continues tracking the activation until the entire service object is removed
 * (see service_remove()).
 *
 * In all cases this does not mean that there is a matching activation object
 * in the broker. The broker activation can have a completely different
 * lifetime than this activation in the launcher.
 *
 * Returns: 0 on success, negative error code on failure.
 */
int service_activate(Service *service, uint64_t serial) {
        _c_cleanup_(c_freep) char *escaped_name = NULL;
        Launcher *launcher = service->launcher;
        const char *unique_name;
        int r;

        service_discard_activation(service);
        service->last_serial = serial;

        r = service_data_duplicate(service->data, &service->active_data);
        if (r)
                return error_fold(r);

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
        c_assert(!service->active_unit);

        if (service->active_data->unit) {
                service->active_unit = strdup(service->active_data->unit);
                if (!service->active_unit)
                        return error_origin(-ENOMEM);
        } else if (service->active_data->argc > 0) {
                r = sd_bus_get_unique_name(launcher->bus_regular, &unique_name);
                if (r < 0)
                        return error_origin(r);

                r = systemd_escape_unit(&escaped_name, service->name);
                if (r)
                        return error_fold(r);

                r = asprintf(
                        &service->active_unit,
                        "dbus-%s-%s@%"PRIu64".service",
                        unique_name,
                        escaped_name,
                        service->instance++
                );
                if (r < 0)
                        return error_origin(-errno);

                service->is_transient = true;
        } else {
                /*
                 * If no unit-file, nor any command-line is specified, we
                 * expect the service to self-activate. This is an extension
                 * over the reference-implementation, which refuses to load
                 * such service files.
                 * However, this is very handy for services like PID1, or other
                 * auto-start services, which we know will appear on the bus at
                 * some point, but don't need to be triggered. They can now
                 * provide service-files and be available on the bus right from
                 * the beginning, without requiring activation from us.
                 * Technically, you could achieve the same with `/bin/true` as
                 * command, but being explicit is always preferred.
                 */
        }

        if (service->active_unit) {
                r = service_watch_jobs(service);
                if (r)
                        return error_fold(r);

                r = service_watch_unit(service, service->active_unit);
                if (r)
                        return error_fold(r);

                /*
                 * Actual start of the service unit is delayed until all the
                 * correct D-Bus matches are configured.
                 */
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
                               service->data->uid);
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

        service_discard_activation(service);

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

int service_data_new(
        ServiceData **datap,
        const char *path,
        const char *unit,
        const char *user,
        uid_t uid,
        size_t argc,
        char **argv
) {
        _c_cleanup_(service_data_freep) ServiceData *data = NULL;
        size_t i;

        data = calloc(1, sizeof(*data) + argc * sizeof(*argv));
        if (!data)
                return error_origin(-ENOMEM);

        if (path) {
                data->path = strdup(path);
                if (!data->path)
                        return error_origin(-ENOMEM);
        }

        if (unit) {
                data->unit = strdup(unit);
                if (!data->unit)
                        return error_origin(-ENOMEM);
        }

        if (user) {
                data->user = strdup(user);
                if (!data->user)
                        return error_origin(-ENOMEM);
        }

        data->uid = uid;
        data->argc = argc;

        for (i = 0; i < argc; ++i) {
                data->argv[i] = strdup(argv[i]);
                if (!data->argv[i])
                        return error_origin(-ENOMEM);
        }

        *datap = data;
        data = NULL;
        return 0;
}

ServiceData *service_data_free(ServiceData *data) {
        size_t i;

        if (!data)
                return NULL;

        for (i = 0; i < data->argc; ++i)
                c_free(data->argv[i]);

        c_free(data->user);
        c_free(data->unit);
        c_free(data->path);
        c_free(data);

        return NULL;
}

int service_data_duplicate(ServiceData *data, ServiceData **dupp) {
        return service_data_new(
                dupp,
                data->path,
                data->unit,
                data->user,
                data->uid,
                data->argc,
                data->argv
        );
}
