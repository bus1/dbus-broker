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
#include "bus/policy.h"
#include "dbus/connection.h"
#include "util/user.h"

typedef struct Broker Broker;
typedef struct Bus Bus;
typedef struct Controller Controller;
typedef struct ControllerName ControllerName;
typedef struct ControllerListener ControllerListener;
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

        CONTROLLER_E_LISTENER_NOT_FOUND,
        CONTROLLER_E_NAME_NOT_FOUND,
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
        CRBTree reload_tree;
        uint32_t serial;
};

#define CONTROLLER_NULL(_x) {                                                   \
                .connection = CONNECTION_NULL((_x).connection),                 \
                .name_tree = C_RBTREE_INIT,                                     \
                .listener_tree = C_RBTREE_INIT,                                 \
                .reload_tree = C_RBTREE_INIT,                                   \
        }

/* names */

ControllerName *controller_name_free(ControllerName *name);
int controller_name_reset(ControllerName *name, uint64_t serial);
int controller_name_activate(ControllerName *name, uint64_t serial);

C_DEFINE_CLEANUP(ControllerName *, controller_name_free);

/* listeners */

ControllerListener *controller_listener_free(ControllerListener *listener);
int controller_listener_set_policy(ControllerListener *listener, PolicyRegistry *policy);

C_DEFINE_CLEANUP(ControllerListener *, controller_listener_free);

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
int controller_request_reload(Controller *controller,
                              User *user,
                              uint64_t sender_id,
                              uint32_t sender_serial);
ControllerName *controller_find_name(Controller *controller, const char *path);
ControllerListener *controller_find_listener(Controller *controller, const char *path);
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
