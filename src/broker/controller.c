/*
 * Broker Controller
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/types.h>
#include "activation.h"
#include "broker/controller.h"
#include "broker/manager.h"
#include "bus.h"
#include "dbus/connection.h"
#include "dbus/message.h"
#include "util/error.h"

static int controller_name_compare(CRBTree *t, void *k, CRBNode *rb) {
        ControllerName *name = c_container_of(rb, ControllerName, controller_node);

        return strcmp(k, name->path);
}

/**
 * controller_name_free() - XXX
 */
ControllerName *controller_name_free(ControllerName *name) {
        if (!name)
                return NULL;

        activation_deinit(&name->activation);
        c_rbtree_remove_init(&name->controller->name_tree, &name->controller_node);
        free(name);

        return NULL;
}

static int controller_name_new(ControllerName **namep, Controller *controller, const char *path) {
        CRBNode **slot, *parent;
        ControllerName *name;
        size_t n_path;

        slot = c_rbtree_find_slot(&controller->name_tree, controller_name_compare, path, &parent);
        if (!slot)
                return CONTROLLER_E_NAME_EXISTS;

        n_path = strlen(path);
        name = calloc(1, sizeof(*name) + n_path + 1);
        if (!name)
                return error_origin(-ENOMEM);

        name->controller = controller;
        name->controller_node = (CRBNode)C_RBNODE_INIT(name->controller_node);
        memcpy(name->path, path, n_path + 1);

        c_rbtree_add(&controller->name_tree, parent, slot, &name->controller_node);
        *namep = name;
        return 0;
}

/**
 * controller_name_reset() - XXX
 */
void controller_name_reset(ControllerName *name) {
        activation_flush(&name->activation);
}

/**
 * controller_name_activate() - XXX
 */
int controller_name_activate(ControllerName *name) {
        return controller_dbus_send_activation(name->controller, name->path);
}

static int controller_listener_compare(CRBTree *t, void *k, CRBNode *rb) {
        ControllerListener *listener = c_container_of(rb, ControllerListener, controller_node);

        return strcmp(k, listener->path);
}

/**
 * controller_listener_free() - XXX
 */
ControllerListener *controller_listener_free(ControllerListener *listener) {
        if (!listener)
                return NULL;

        listener_deinit(&listener->listener);
        c_rbtree_remove_init(&listener->controller->listener_tree, &listener->controller_node);
        free(listener);

        return NULL;
}

static int controller_listener_new(ControllerListener **listenerp, Controller *controller, const char *path) {
        CRBNode **slot, *parent;
        ControllerListener *listener;
        size_t n_path;

        slot = c_rbtree_find_slot(&controller->listener_tree, controller_listener_compare, path, &parent);
        if (!slot)
                return CONTROLLER_E_LISTENER_EXISTS;

        n_path = strlen(path);
        listener = calloc(1, sizeof(*listener) + n_path + 1);
        if (!listener)
                return error_origin(-ENOMEM);

        listener->controller = controller;
        listener->controller_node = (CRBNode)C_RBNODE_INIT(listener->controller_node);
        memcpy(listener->path, path, n_path + 1);

        c_rbtree_add(&controller->listener_tree, parent, slot, &listener->controller_node);
        *listenerp = listener;
        return 0;
}

static int controller_dispatch_connection(DispatchFile *file, uint32_t events) {
        Controller *controller = c_container_of(file, Controller, connection.socket_file);
        int r;

        r = connection_dispatch(&controller->connection, events);
        if (r)
                return error_fold(r);

        do {
                _c_cleanup_(message_unrefp) Message *m = NULL;

                r = connection_dequeue(&controller->connection, &m);
                if (!r) {
                        if (!m)
                                break;

                        r = controller_dbus_dispatch(controller, m);
                }
        } while (!r);

        if (r == CONNECTION_E_EOF) {
                connection_shutdown(&controller->connection);
                return connection_is_running(&controller->connection) ? 0 : DISPATCH_E_EXIT;
        }

        return error_fold(r);
}

/**
 * controller_init() - XXX
 */
int controller_init(Controller *c, Manager *manager, int controller_fd) {
        _c_cleanup_(controller_deinitp) Controller *controller = c;
        int r;

        *controller = (Controller)CONTROLLER_NULL(*controller);
        controller->manager = manager;

        r = connection_init_server(&controller->connection,
                                   &manager->dispatcher,
                                   controller_dispatch_connection,
                                   manager->bus.user,
                                   "0123456789abcdef",
                                   controller_fd);
        if (r)
                return error_fold(r);

        controller = NULL;
        return 0;
}

/**
 * controller_deinit() - XXX
 */
void controller_deinit(Controller *controller) {
        ControllerListener *listener, *listener_safe;
        ControllerName *name, *name_safe;

        c_rbtree_for_each_entry_unlink(name, name_safe, &controller->name_tree, controller_node)
                controller_name_free(name);

        c_rbtree_for_each_entry_unlink(listener, listener_safe, &controller->listener_tree, controller_node)
                controller_listener_free(listener);

        connection_deinit(&controller->connection);
        controller->manager = NULL;
}

/**
 * controller_add_name() - XXX
 */
int controller_add_name(Controller *controller,
                        ControllerName **namep,
                        const char *path,
                        const char *name_str,
                        uid_t uid) {
        _c_cleanup_(controller_name_freep) ControllerName *name = NULL;
        _c_cleanup_(name_unrefp) Name *name_entry = NULL;
        _c_cleanup_(user_unrefp) User *user_entry = NULL;
        int r;

        r = name_registry_ref_name(&controller->manager->bus.names, &name_entry, name_str);
        if (r)
                return error_fold(r);

        r = user_registry_ref_user(&controller->manager->bus.users, &user_entry, uid);
        if (r)
                return error_fold(r);

        r = controller_name_new(&name, controller, path);
        if (r)
                return error_trace(r);

        r = activation_init(&name->activation, name_entry, user_entry);
        if (r)
                return (r == ACTIVATION_E_ALREADY_ACTIVATABLE) ? CONTROLLER_E_NAME_IS_ACTIVATABLE : error_fold(r);

        *namep = name;
        name = NULL;
        return 0;
}

/**
 * controller_add_listener() - XXX
 */
int controller_add_listener(Controller *controller,
                            ControllerListener **listenerp,
                            const char *path,
                            int listener_fd,
                            const char *policy_path) {
        _c_cleanup_(controller_listener_freep) ControllerListener *listener = NULL;
        int r;

        r = controller_listener_new(&listener, controller, path);
        if (r)
                return error_trace(r);

        r = listener_init_with_fd(&listener->listener,
                                  &controller->manager->bus,
                                  &controller->manager->dispatcher,
                                  listener_fd,
                                  policy_path);
        if (r)
                return error_fold(r);

        *listenerp = listener;
        listener = NULL;
        return 0;
}

/**
 * controller_find_name() - XXX
 */
ControllerName *controller_find_name(Controller *controller, const char *path) {
        return c_container_of(c_rbtree_find_node(&controller->name_tree,
                                                 controller_name_compare,
                                                 path),
                              ControllerName,
                              controller_node);
}

/**
 * controller_find_listener() - XXX
 */
ControllerListener *controller_find_listener(Controller *controller, const char *path) {
        return c_container_of(c_rbtree_find_node(&controller->listener_tree,
                                                 controller_listener_compare,
                                                 path),
                              ControllerListener,
                              controller_node);
}
