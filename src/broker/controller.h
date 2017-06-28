#pragma once

/*
 * Broker Controller
 */

#include <c-macro.h>
#include <c-rbtree.h>
#include <stdlib.h>
#include "listener.h"

typedef struct Activation Activation;
typedef struct Bus Bus;
typedef struct Connection Connection;
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
        CONTROLLER_E_ACTIVATION_EXISTS,
        CONTROLLER_E_NAME_IS_ACTIVATABLE,
        CONTROLLER_E_NAME_INVALID,

        CONTROLLER_E_LISTENER_NOT_FOUND,
        CONTROLLER_E_ACTIVATION_NOT_FOUND,
};

struct ControllerName {
        Controller *controller;
        CRBNode controller_node;
        Activation *activation;
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
        CRBTree name_tree;
        CRBTree listener_tree;
};

#define CONTROLLER_INIT(_manager) {             \
                .manager = (_manager),          \
                .name_tree = C_RBTREE_INIT,     \
                .listener_tree = C_RBTREE_INIT, \
        }

/* names */

ControllerName *controller_name_free(ControllerName *name);
void controller_name_reset(ControllerName *name);

C_DEFINE_CLEANUP(ControllerName *, controller_name_free);

/* listeners */

ControllerListener *controller_listener_free(ControllerListener *listener);

C_DEFINE_CLEANUP(ControllerListener *, controller_listener_free);

/* controller */

void controller_init(Controller *controller, Manager *manager);
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

int controller_dispatch(Controller *controller, Message *message);
