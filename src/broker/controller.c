/*
 * Broker Controller
 */

#include <c-rbtree.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/types.h>
#include "broker/broker.h"
#include "broker/controller.h"
#include "bus/activation.h"
#include "bus/bus.h"
#include "bus/driver.h"
#include "bus/listener.h"
#include "bus/metrics.h"
#include "bus/policy.h"
#include "dbus/connection.h"
#include "dbus/message.h"
#include "util/error.h"
#include "util/sockopt.h"
#include "util/user.h"

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
        c_rbnode_unlink(&name->controller_node);
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
        name->activation = (Activation)ACTIVATION_NULL(name->activation);
        c_memcpy(name->path, path, n_path + 1);

        c_rbtree_add(&controller->name_tree, parent, slot, &name->controller_node);
        *namep = name;
        return 0;
}

/**
 * controller_name_reset() - XXX
 */
int controller_name_reset(ControllerName *name, uint64_t serial, unsigned int error) {
        int r;

        r = driver_name_activation_failed(&name->controller->broker->bus, &name->activation, serial, error);
        if (r)
                return error_fold(r);

        return 0;
}

/**
 * controller_name_activate() - XXX
 */
int controller_name_activate(ControllerName *name, uint64_t serial) {
        return controller_dbus_send_activation(name->controller, name->path, serial);
}

static int controller_reload_compare(CRBTree *t, void *k, CRBNode *rb) {
        ControllerReload *reload = c_container_of(rb, ControllerReload, controller_node);
        uint32_t serial = *(uint32_t *)k;

        if (serial < reload->serial)
                return -1;
        if (serial > reload->serial)
                return 1;

        return 0;
}

ControllerReload *controller_reload_free(ControllerReload *reload) {
        if (!reload)
                return NULL;

        user_charge_deinit(&reload->charge);
        c_rbnode_unlink(&reload->controller_node);
        free(reload);

        return NULL;
}

static int controller_reload_new(ControllerReload **reloadp, User *user, Controller *controller) {
        CRBNode **slot, *parent;
        ControllerReload *reload;
        uint32_t serial;
        int r;

        for (uint32_t i = 0; i < UINT32_MAX; i++) {
                serial = ++controller->serial;

                if (!serial)
                        continue;

                slot = c_rbtree_find_slot(&controller->reload_tree, controller_reload_compare, &serial, &parent);
                if (slot)
                        break;
        }
        if (!slot)
                return CONTROLLER_E_SERIAL_EXHAUSTED;

        reload = calloc(1, sizeof(*reload));
        if (!reload)
                return error_origin(-ENOMEM);

        *reload = (ControllerReload)CONTROLLER_RELOAD_NULL(*reload);
        reload->controller = controller;
        reload->serial = serial;

        r = user_charge(controller->broker->bus.user, &reload->charge, user, USER_SLOT_BYTES, sizeof(ControllerReload));
        if (r)
                return (r == USER_E_QUOTA) ? CONTROLLER_E_QUOTA : error_fold(r);

        c_rbtree_add(&controller->reload_tree, parent, slot, &reload->controller_node);
        *reloadp = reload;
        return 0;
}

/**
 * controller_reload_completed() - XXX
 */
int controller_reload_completed(ControllerReload *reload) {
        return error_fold(driver_reload_config_completed(&reload->controller->broker->bus, reload->sender_id, reload->sender_serial));
}

/**
 * controller_reload_invalid() - XXX
 */
int controller_reload_invalid(ControllerReload *reload) {
        return error_fold(driver_reload_config_invalid(&reload->controller->broker->bus, reload->sender_id, reload->sender_serial));
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
        c_rbnode_unlink(&listener->controller_node);
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
        listener->listener = (Listener)LISTENER_NULL(listener->listener);
        c_memcpy(listener->path, path, n_path + 1);

        c_rbtree_add(&controller->listener_tree, parent, slot, &listener->controller_node);
        *listenerp = listener;
        return 0;
}

/**
 * controller_listener_set_policy() - XXX
 */
int controller_listener_set_policy(ControllerListener *listener, PolicyRegistry *policy) {
        return error_fold(listener_set_policy(&listener->listener, policy));
}

static int controller_metrics_compare(CRBTree *t, void *k, CRBNode *rb) {
        ControllerMetrics *metrics = c_container_of(rb, ControllerMetrics, controller_node);

        return strcmp(k, metrics->path);
}

/**
 * controller_metrics_free() - XXX
 */
ControllerMetrics *controller_metrics_free(ControllerMetrics *metrics) {
        if (!metrics)
                return NULL;

        metrics_deinit(&metrics->metrics);
        c_rbnode_unlink(&metrics->controller_node);
        free(metrics);

        return NULL;
}

static int controller_metrics_new(ControllerMetrics **metricsp, Controller *controller, const char *path) {
        CRBNode **slot, *parent;
        ControllerMetrics *metrics;
        size_t n_path;

        slot = c_rbtree_find_slot(&controller->metrics_tree, controller_metrics_compare, path, &parent);
        if (!slot)
                return CONTROLLER_E_METRICS_EXISTS;

        n_path = strlen(path);
        metrics = calloc(1, sizeof(*metrics) + n_path + 1);
        if (!metrics)
                return error_origin(-ENOMEM);

        metrics->controller = controller;
        metrics->controller_node = (CRBNode)C_RBNODE_INIT(metrics->controller_node);
        metrics->metrics = (Metrics)METRICS_NULL(metrics->metrics);
        c_memcpy(metrics->path, path, n_path + 1);

        c_rbtree_add(&controller->metrics_tree, parent, slot, &metrics->controller_node);
        *metricsp = metrics;
        return 0;
}

static int controller_dispatch_connection(DispatchFile *file) {
        Controller *controller = c_container_of(file, Controller, connection.socket_file);
        int r;

        r = connection_dispatch(&controller->connection, dispatch_file_events(file));
        if (r)
                return error_fold(r);

        do {
                _c_cleanup_(message_unrefp) Message *m = NULL;

                r = connection_dequeue(&controller->connection, &m);
                if (r) {
                        if (r == CONNECTION_E_EOF)
                                r = CONTROLLER_E_EOF;
                        else
                                return error_fold(r);
                } else {
                        if (!m)
                                break;

                        r = controller_dbus_dispatch(controller, m);
                }
        } while (!r);

        if (r == CONTROLLER_E_EOF) {
                connection_shutdown(&controller->connection);
                return connection_is_running(&controller->connection) ? 0 : DISPATCH_E_EXIT;
        } else if (r == CONTROLLER_E_PROTOCOL_VIOLATION) {
                connection_close(&controller->connection);
                return connection_is_running(&controller->connection) ? 0 : DISPATCH_E_EXIT;
        }

        return error_fold(r);
}

/**
 * controller_init() - XXX
 */
int controller_init(Controller *c, Broker *broker, int controller_fd) {
        _c_cleanup_(controller_deinitp) Controller *controller = c;
        int r;

        *controller = (Controller)CONTROLLER_NULL(*controller);
        controller->broker = broker;

        r = connection_init_server(&controller->connection,
                                   &broker->dispatcher,
                                   controller_dispatch_connection,
                                   broker->bus.user,
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
        ControllerMetrics *metrics, *metrics_safe;
        ControllerName *name, *name_safe;
        ControllerReload *reload, *reload_safe;

        c_rbtree_for_each_entry_safe_postorder_unlink(reload, reload_safe, &controller->reload_tree, controller_node)
                controller_reload_free(reload);

        c_rbtree_for_each_entry_safe_postorder_unlink(metrics, metrics_safe, &controller->metrics_tree, controller_node)
                controller_metrics_free(metrics);

        c_rbtree_for_each_entry_safe_postorder_unlink(name, name_safe, &controller->name_tree, controller_node)
                controller_name_free(name);

        c_rbtree_for_each_entry_safe_postorder_unlink(listener, listener_safe, &controller->listener_tree, controller_node)
                controller_listener_free(listener);

        connection_deinit(&controller->connection);
        controller->broker = NULL;
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

        r = name_registry_ref_name(&controller->broker->bus.names, &name_entry, name_str);
        if (r)
                return error_fold(r);

        r = user_registry_ref_user(&controller->broker->bus.users, &user_entry, uid);
        if (r)
                return error_fold(r);

        r = controller_name_new(&name, controller, path);
        if (r)
                return error_trace(r);

        r = activation_init(&name->activation, &controller->broker->bus, name_entry, user_entry);
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
                            PolicyRegistry *policy) {
        _c_cleanup_(controller_listener_freep) ControllerListener *listener = NULL;
        int r;

        r = controller_listener_new(&listener, controller, path);
        if (r)
                return error_trace(r);

        r = listener_init_with_fd(&listener->listener,
                                  &controller->broker->bus,
                                  &controller->broker->dispatcher,
                                  listener_fd,
                                  policy);
        if (r)
                return error_fold(r);

        *listenerp = listener;
        listener = NULL;
        return 0;
}

/**
 * controller_add_metrics() - XXX
 */
int controller_add_metrics(Controller *controller,
                           ControllerMetrics **metricsp,
                           const char *path,
                           int metrics_fd) {
        _c_cleanup_(controller_metrics_freep) ControllerMetrics *metrics = NULL;
        int r;

        r = controller_metrics_new(&metrics, controller, path);
        if (r)
                return error_trace(r);

        r = metrics_init_with_fd(&metrics->metrics,
                                 &controller->broker->bus,
                                 &controller->broker->dispatcher,
                                 metrics_fd);
        if (r)
                return error_fold(r);

        *metricsp = metrics;
        metrics = NULL;
        return 0;
}

/**
 * controller_request_reload() - XXX
 */
int controller_request_reload(Controller *controller,
                              User *sender_user,
                              uint64_t sender_id,
                              uint32_t sender_serial) {
        _c_cleanup_(controller_reload_freep) ControllerReload *reload = NULL;
        int r;

        r = controller_reload_new(&reload, sender_user, controller);
        if (r)
                return error_trace(r);

        reload->sender_id = sender_id;
        reload->sender_serial = sender_serial;

        r = controller_dbus_send_reload(controller, sender_user, reload->serial);
        if (r)
                return error_trace(r);

        reload = NULL;
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

/**
 * controller_find_metrics() - XXX
 */
ControllerMetrics *controller_find_metrics(Controller *controller, const char *path) {
        return c_container_of(c_rbtree_find_node(&controller->metrics_tree,
                                                 controller_metrics_compare,
                                                 path),
                              ControllerMetrics,
                              controller_node);
}

/**
 * controller_find_reload() - XXX
 */
ControllerReload *controller_find_reload(Controller *controller, uint32_t serial) {
        return c_container_of(c_rbtree_find_node(&controller->reload_tree,
                                                 controller_reload_compare,
                                                 &serial),
                              ControllerReload,
                              controller_node);
}
