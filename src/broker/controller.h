#pragma once

/*
 * Broker Controller
 */

#include <c-macro.h>
#include <c-rbtree.h>
#include <stdlib.h>
#include <sys/types.h>
#include "activation.h"
#include "dbus/connection.h"
#include "listener.h"

typedef struct Bus Bus;
typedef struct Controller Controller;
typedef struct ControllerName ControllerName;
typedef struct ControllerListener ControllerListener;
typedef struct Manager Manager;
typedef struct Message Message;

enum {
        _CONTROLLER_E_SUCCESS,

        CONTROLLER_E_DISCONNECT,

        CONTROLLER_E_INVALID_MESSAGE,

        CONTROLLER_E_UNEXPECTED_MESSAGE_TYPE,
        CONTROLLER_E_UNEXPECTED_PATH,
        CONTROLLER_E_UNEXPECTED_INTERFACE,
        CONTROLLER_E_UNEXPECTED_METHOD,
        CONTROLLER_E_UNEXPECTED_SIGNATURE,
        CONTROLLER_E_UNEXPECTED_REPLY,

        CONTROLLER_E_LISTENER_EXISTS,
        CONTROLLER_E_LISTENER_INVALID,
        CONTROLLER_E_NAME_EXISTS,
        CONTROLLER_E_NAME_IS_ACTIVATABLE,
        CONTROLLER_E_NAME_INVALID,

        CONTROLLER_E_LISTENER_NOT_FOUND,
        CONTROLLER_E_ACTIVATION_NOT_FOUND,
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

struct Controller {
        Manager *manager;
        Connection connection;
        CRBTree name_tree;
        CRBTree listener_tree;
};

#define CONTROLLER_NULL(_x) {                                                   \
                .connection = CONNECTION_NULL((_x).connection),                 \
                .name_tree = C_RBTREE_INIT,                                     \
                .listener_tree = C_RBTREE_INIT,                                 \
        }

/* names */

ControllerName *controller_name_free(ControllerName *name);
void controller_name_reset(ControllerName *name);
int controller_name_activate(ControllerName *name);

C_DEFINE_CLEANUP(ControllerName *, controller_name_free);

/* listeners */

ControllerListener *controller_listener_free(ControllerListener *listener);

C_DEFINE_CLEANUP(ControllerListener *, controller_listener_free);

/* controller */

int controller_init(Controller *controller, Manager *manager, int controller_fd);
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
                            const char *policy_path);
ControllerName *controller_find_name(Controller *controller, const char *path);
ControllerListener *controller_find_listener(Controller *controller, const char *path);

int controller_dbus_dispatch(Controller *controller, Message *message);
int controller_dbus_send_activation(Controller *controller, const char *path);

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
