#pragma once

/*
 * Broker Controller
 */

#include <c-rbtree.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/types.h>
#include "bus/activation.h"
#include "bus/listener.h"
#include "bus/metrics.h"
#include "bus/policy.h"
#include "dbus/connection.h"
#include "util/string.h"
#include "util/user.h"

typedef struct Broker Broker;
typedef struct Bus Bus;
typedef struct Controller Controller;
typedef struct ControllerName ControllerName;
typedef struct ControllerListener ControllerListener;
typedef struct ControllerMetrics ControllerMetrics;
typedef struct ControllerReload ControllerReload;
typedef struct Message Message;

enum {
        _CONTROLLER_E_SUCCESS,

        CONTROLLER_E_EOF,

        CONTROLLER_E_SERIAL_EXHAUSTED,
        CONTROLLER_E_QUOTA,

        CONTROLLER_E_PROTOCOL_VIOLATION,

        CONTROLLER_E_INVALID_MESSAGE,

        CONTROLLER_E_UNEXPECTED_MESSAGE_TYPE,
        CONTROLLER_E_UNEXPECTED_PATH,
        CONTROLLER_E_UNEXPECTED_INTERFACE,
        CONTROLLER_E_UNEXPECTED_METHOD,
        CONTROLLER_E_UNEXPECTED_SIGNATURE,
        CONTROLLER_E_UNEXPECTED_REPLY,
        CONTROLLER_E_UNEXPECTED_ERROR,

        CONTROLLER_E_LISTENER_EXISTS,
        CONTROLLER_E_LISTENER_INVALID_FD,
        CONTROLLER_E_LISTENER_INVALID_POLICY,
        CONTROLLER_E_NAME_EXISTS,
        CONTROLLER_E_NAME_IS_ACTIVATABLE,
        CONTROLLER_E_NAME_INVALID,
        CONTROLLER_E_METRICS_EXISTS,
        CONTROLLER_E_METRICS_INVALID_FD,

        CONTROLLER_E_LISTENER_NOT_FOUND,
        CONTROLLER_E_NAME_NOT_FOUND,
        CONTROLLER_E_METRICS_NOT_FOUND,
};

enum {
        _CONTROLLER_NAME_ERROR_INVALID                  = 0,
        CONTROLLER_NAME_ERROR_DESTRUCTIVE_TRANSACTION   = 1,
        CONTROLLER_NAME_ERROR_UNKNOWN_UNIT              = 2,
        CONTROLLER_NAME_ERROR_MASKED_UNIT               = 3,
        CONTROLLER_NAME_ERROR_INVALID_UNIT              = 4,
        CONTROLLER_NAME_ERROR_UNIT_FAILURE              = 5,
        CONTROLLER_NAME_ERROR_STARTUP_FAILURE           = 6,
        CONTROLLER_NAME_ERROR_STARTUP_SKIPPED           = 7,
        CONTROLLER_NAME_ERROR_NAME_RELEASED             = 8,
        _CONTROLLER_NAME_ERROR_N,
};

struct ControllerName {
        Controller *controller;
        CRBNode controller_node;
        Activation activation;
        char path[];
};

struct ControllerListener {
        Controller *controller;
        CRBNode controller_node;
        Listener listener;
        char path[];
};

struct ControllerMetrics {
        Controller *controller;
        CRBNode controller_node;
        Metrics metrics;
        char path[];
};

struct ControllerReload {
        Controller *controller;
        UserCharge charge;
        CRBNode controller_node;
        uint64_t sender_id;
        uint32_t sender_serial;
        uint32_t serial;
};

#define CONTROLLER_RELOAD_NULL(_x) {                                                    \
                .charge = USER_CHARGE_INIT,                                             \
                .controller_node = (CRBNode)C_RBNODE_INIT((_x).controller_node),        \
                .sender_id = ADDRESS_ID_INVALID,                                        \
        }

struct Controller {
        Broker *broker;
        Connection connection;
        CRBTree name_tree;
        CRBTree listener_tree;
        CRBTree metrics_tree;
        CRBTree reload_tree;
        uint32_t serial;
};

#define CONTROLLER_NULL(_x) {                                                   \
                .connection = CONNECTION_NULL((_x).connection),                 \
                .name_tree = C_RBTREE_INIT,                                     \
                .listener_tree = C_RBTREE_INIT,                                 \
                .metrics_tree = C_RBTREE_INIT,                                  \
                .reload_tree = C_RBTREE_INIT,                                   \
        }

/* names */

ControllerName *controller_name_free(ControllerName *name);
int controller_name_reset(ControllerName *name, uint64_t serial, unsigned int name_error);
int controller_name_activate(ControllerName *name, uint64_t serial);

C_DEFINE_CLEANUP(ControllerName *, controller_name_free);

/* listeners */

ControllerListener *controller_listener_free(ControllerListener *listener);
int controller_listener_set_policy(ControllerListener *listener, PolicyRegistry *policy);

C_DEFINE_CLEANUP(ControllerListener *, controller_listener_free);

/* metrics */

ControllerMetrics *controller_metrics_free(ControllerMetrics *metrics);

C_DEFINE_CLEANUP(ControllerMetrics *, controller_metrics_free);

/* reload */

ControllerReload *controller_reload_free(ControllerReload *reload);
int controller_reload_completed(ControllerReload *reload);
int controller_reload_invalid(ControllerReload *reload);

C_DEFINE_CLEANUP(ControllerReload *, controller_reload_free);

/* controller */

int controller_init(Controller *controller, Broker *broker, int controller_fd);
void controller_deinit(Controller *controller);

int controller_add_name(Controller *controller,
                        ControllerName **namep,
                        const char *path,
                        const char *name_str,
                        uid_t uid);
int controller_add_listener(Controller *controller,
                            ControllerListener **listenerp,
                            const char *path,
                            int listener_fd,
                            PolicyRegistry *policy);
int controller_add_metrics(Controller *controller,
                           ControllerMetrics **metricsp,
                           const char *path,
                           int metrics_fd);
int controller_request_reload(Controller *controller,
                              User *user,
                              uint64_t sender_id,
                              uint32_t sender_serial);
ControllerName *controller_find_name(Controller *controller, const char *path);
ControllerListener *controller_find_listener(Controller *controller, const char *path);
ControllerMetrics *controller_find_metrics(Controller *controller, const char *path);
ControllerReload *controller_find_reload(Controller *controller, uint32_t serial);

int controller_dbus_dispatch(Controller *controller, Message *message);
int controller_dbus_send_activation(Controller *controller, const char *path, uint64_t serial);
int controller_dbus_send_reload(Controller *controller, User *user, uint32_t serial);
int controller_dbus_send_environment(Controller *controller, const char * const *env, size_t n_env);

C_DEFINE_CLEANUP(Controller *, controller_deinit);

/* inline helpers */

static inline ControllerName *CONTROLLER_NAME(Activation *activation) {
        /*
         * This function up-casts an Activation to its parent class
         * ControllerName. In our code base we pretend an Activation is an
         * abstract class with several virtual methods. However, we only do
         * this to clearly separate our code-bases. We never intended this to
         * be modular. Hence, instead of providing real vtables with userdata
         * pointers, we instead allow explicit up-casts to the parent type.
         *
         * This function performs the up-cast, relying on the fact that all our
         * Activation objects are always owned by a ControllerName object.
         */
        return c_container_of(activation, ControllerName, activation);
}

static const char *const controller_name_error_table[_CONTROLLER_NAME_ERROR_N] = {
        [CONTROLLER_NAME_ERROR_DESTRUCTIVE_TRANSACTION] = "org.bus1.DBus.Name.Error.DestructiveTransaction",
        [CONTROLLER_NAME_ERROR_UNKNOWN_UNIT]            = "org.bus1.DBus.Name.Error.UnknownUnit",
        [CONTROLLER_NAME_ERROR_MASKED_UNIT]             = "org.bus1.DBus.Name.Error.MaskedUnit",
        [CONTROLLER_NAME_ERROR_INVALID_UNIT]            = "org.bus1.DBus.Name.Error.InvalidUnit",
        [CONTROLLER_NAME_ERROR_UNIT_FAILURE]            = "org.bus1.DBus.Name.Error.UnitFailure",
        [CONTROLLER_NAME_ERROR_STARTUP_FAILURE]         = "org.bus1.DBus.Name.Error.StartupFailure",
        [CONTROLLER_NAME_ERROR_STARTUP_SKIPPED]         = "org.bus1.DBus.Name.Error.StartupSkipped",
        [CONTROLLER_NAME_ERROR_NAME_RELEASED]           = "org.bus1.DBus.Name.Error.NameReleased",
};

static const char *const controller_name_error_table_human_readable[_CONTROLLER_NAME_ERROR_N] = {
        [CONTROLLER_NAME_ERROR_DESTRUCTIVE_TRANSACTION] = "activation request failed: a concurrent deactivation request is already in progress",
        [CONTROLLER_NAME_ERROR_UNKNOWN_UNIT]            = "activation request failed: unknown unit",
        [CONTROLLER_NAME_ERROR_MASKED_UNIT]             = "activation request failed: unit is masked",
        [CONTROLLER_NAME_ERROR_INVALID_UNIT]            = "activation request failed: unit is invalid",
        [CONTROLLER_NAME_ERROR_UNIT_FAILURE]            = "unit failed",
        [CONTROLLER_NAME_ERROR_STARTUP_FAILURE]         = "startup job failed",
        [CONTROLLER_NAME_ERROR_STARTUP_SKIPPED]         = "startup job skipped",
        [CONTROLLER_NAME_ERROR_NAME_RELEASED]           = "activation request cancelled: bus name was released",
};

static inline const char *controller_name_error_to_string(unsigned int error) {
        c_assert(error > 0 && error < _CONTROLLER_NAME_ERROR_N);
        c_assert(controller_name_error_table[error]);

        return controller_name_error_table[error];
}

static inline const char *controller_name_error_to_human_readable(unsigned int error) {
        c_assert(error > 0 && error < _CONTROLLER_NAME_ERROR_N);
        c_assert(controller_name_error_table_human_readable[error]);

        return controller_name_error_table_human_readable[error];
}

static inline unsigned int controller_name_error_from_string(const char *error) {
        for (size_t i = 0; i < _CONTROLLER_NAME_ERROR_N; ++i)
                if (string_equal(error, controller_name_error_table[i]))
                        return i;

        return 0;
}
