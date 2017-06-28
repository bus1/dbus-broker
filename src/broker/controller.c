/*
 * Broker Controller
 */

#include <c-dvar.h>
#include <c-dvar-type.h>
#include <c-macro.h>
#include <c-string.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "broker/controller.h"
#include "broker/manager.h"
#include "activation.h"
#include "bus.h"
#include "dbus/connection.h"
#include "dbus/message.h"
#include "dbus/protocol.h"
#include "dbus/socket.h"
#include "util/error.h"
#include "util/fdlist.h"

typedef struct DispatchContext DispatchContext;
typedef struct ControllerMethod ControllerMethod;
typedef int (*ControllerMethodFn) (Controller *controller, const char *path, CDVar *var_in, FDList *fds_in, CDVar *var_out);

struct ControllerMethod {
        const char *name;
        ControllerMethodFn fn;
        const CDVarType *in;
        const CDVarType *out;
};

/*
 * This macro defines a c-dvar type for DBus Messages. It evaluates to:
 *
 *         ((yyyyuua(yv))X)
 *
 * ..where 'X' is provided via @_body. That is, it evaluates to the combination
 * of DBus Header and DBus Body for a given body-type.
 */
#define CONTROLLER_T_MESSAGE(_body) \
        C_DVAR_T_TUPLE2(                                \
                C_DVAR_T_TUPLE7(                        \
                        C_DVAR_T_y,                     \
                        C_DVAR_T_y,                     \
                        C_DVAR_T_y,                     \
                        C_DVAR_T_y,                     \
                        C_DVAR_T_u,                     \
                        C_DVAR_T_u,                     \
                        C_DVAR_T_ARRAY(                 \
                                C_DVAR_T_TUPLE2(        \
                                        C_DVAR_T_y,     \
                                        C_DVAR_T_v      \
                                )                       \
                        )                               \
                ),                                      \
                _body                                   \
        )

static const CDVarType controller_type_in_ohs[] = {
        C_DVAR_T_INIT(
                C_DVAR_T_TUPLE3(
                        C_DVAR_T_o,
                        C_DVAR_T_h,
                        C_DVAR_T_s
                )
        )
};
static const CDVarType controller_type_in_osu[] = {
        C_DVAR_T_INIT(
                C_DVAR_T_TUPLE3(
                        C_DVAR_T_o,
                        C_DVAR_T_s,
                        C_DVAR_T_u
                )
        )
};
static const CDVarType controller_type_out_unit[] = {
        C_DVAR_T_INIT(
                CONTROLLER_T_MESSAGE(
                        C_DVAR_T_TUPLE0
                )
        )
};

static void controller_dvar_write_signature_out(CDVar *var, const CDVarType *type) {
        char signature[C_DVAR_TYPE_LENGTH_MAX + 1];

        assert(type->length < sizeof(signature) + strlen("((yyyyuua(yv))())"));
        assert(type[0].element == '(');
        assert(type[1].element == '(');
        assert(type[2].element == 'y');
        assert(type[3].element == 'y');
        assert(type[4].element == 'y');
        assert(type[5].element == 'y');
        assert(type[6].element == 'u');
        assert(type[7].element == 'u');
        assert(type[8].element == 'a');
        assert(type[9].element == '(');
        assert(type[10].element == 'y');
        assert(type[11].element == 'v');
        assert(type[12].element == ')');
        assert(type[13].element == ')');
        assert(type[14].element == '(');
        assert(type[type->length - 2].element == ')');
        assert(type[type->length - 1].element == ')');

        for (unsigned int i = strlen("((yyyyuua(yv))("), j = 0; i < type->length - strlen("))"); i++, j++)
                signature[j] = type[i].element;

        signature[type->length - strlen("((yyyyuua(yv))())")] = '\0';

        c_dvar_write(var, "g", signature);
}

static int controller_dvar_verify_signature_in(const CDVarType *type, const char *signature) {
        if (type->length != strlen(signature) + 2)
                return CONTROLLER_E_UNEXPECTED_SIGNATURE;

        assert(type[0].element == '(');
        assert(type[type->length - 1].element == ')');

        for (unsigned int i = 1; i + 1 < type->length; i++)
                if (signature[i - 1] != type[i].element)
                        return CONTROLLER_E_UNEXPECTED_SIGNATURE;

        return 0;
}

static void controller_write_reply_header(CDVar *var, uint32_t serial, const CDVarType *type) {
        c_dvar_write(var, "(yyyyuu[(y<u>)(y<",
                     c_dvar_is_big_endian(var) ? 'B' : 'l', DBUS_MESSAGE_TYPE_METHOD_RETURN, DBUS_HEADER_FLAG_NO_REPLY_EXPECTED, 1, 0, (uint32_t)-1,
                     DBUS_MESSAGE_FIELD_REPLY_SERIAL, c_dvar_type_u, serial,
                     DBUS_MESSAGE_FIELD_SIGNATURE, c_dvar_type_g);
        controller_dvar_write_signature_out(var, type);
        c_dvar_write(var, ">)])");
}

static int controller_send_error(Connection *connection, uint32_t serial, const char *error) {
        static const CDVarType type[] = {
                C_DVAR_T_INIT(
                        CONTROLLER_T_MESSAGE(
                                C_DVAR_T_TUPLE0
                        )
                )
        };
        _c_cleanup_(c_dvar_deinitp) CDVar var = C_DVAR_INIT;
        _c_cleanup_(message_unrefp) Message *message = NULL;
        void *data;
        size_t n_data;
        int r;

        c_dvar_begin_write(&var, type, 1);
        c_dvar_write(&var, "((yyyyuu[(y<u>)(y<s>)])())",
                     c_dvar_is_big_endian(&var) ? 'B' : 'l', DBUS_MESSAGE_TYPE_ERROR, DBUS_HEADER_FLAG_NO_REPLY_EXPECTED, 1, 0, (uint32_t)-1,
                     DBUS_MESSAGE_FIELD_REPLY_SERIAL, c_dvar_type_u, serial,
                     DBUS_MESSAGE_FIELD_ERROR_NAME, c_dvar_type_s, error);

        r = c_dvar_end_write(&var, &data, &n_data);
        if (r)
                return error_origin(r);

        r = message_new_outgoing(&message, data, n_data);
        if (r)
                return error_fold(r);

        r = connection_queue(connection, NULL, 0, message);
        if (r) {
                if (r == CONNECTION_E_QUOTA)
                        connection_close(connection);
                else
                        return error_fold(r);
        }

        return 0;
}

static int controller_end_read(CDVar *var) {
        int r;

        r = c_dvar_end_read(var);
        switch (r) {
        case C_DVAR_E_CORRUPT_DATA:
        case C_DVAR_E_OUT_OF_BOUNDS:
        case C_DVAR_E_TYPE_MISMATCH:
                return CONTROLLER_E_INVALID_MESSAGE;
        default:
                return error_origin(r);
        }
}

static int controller_method_add_name(Controller *controller, const char *_path, CDVar *in_v, FDList *fds, CDVar *out_v) {
        const char *path, *name_str;
        ControllerName *name;
        uid_t uid;
        int r;

        c_dvar_read(in_v, "(osu)", &path, &name_str, &uid);

        r = controller_end_read(in_v);
        if (r)
                return error_trace(r);

        if (strncmp(path, "/org/bus1/DBus/Name/", strlen("/org/bus1/DBus/Name/")) != 0)
                return CONTROLLER_E_UNEXPECTED_PATH;
        if (!dbus_validate_name(name_str, strlen(name_str)))
                return CONTROLLER_E_NAME_INVALID;

        r = controller_add_name(controller, &name, path, name_str, uid);
        if (r)
                return error_trace(r);

        c_dvar_write(out_v, "()");

        return 0;
}

static int controller_method_add_listener(Controller *controller, const char *_path, CDVar *in_v, FDList *fds, CDVar *out_v) {
        const char *path, *policy_path;
        ControllerListener *listener;
        int r, listener_fd, v1, v2;
        uint32_t fd_index;
        socklen_t n;

        c_dvar_read(in_v, "(ohs)", &path, &fd_index, &policy_path);

        r = controller_end_read(in_v);
        if (r)
                return error_trace(r);

        if (strncmp(path, "/org/bus1/DBus/Listener/", strlen("/org/bus1/DBus/Listener/")) != 0)
                return CONTROLLER_E_UNEXPECTED_PATH;

        listener_fd = fdlist_get(fds, fd_index);
        if (listener_fd < 0)
                return CONTROLLER_E_LISTENER_INVALID;

        n = sizeof(v1);
        r = getsockopt(listener_fd, SOL_SOCKET, SO_DOMAIN, &v1, &n);
        n = sizeof(v2);
        r = r ?: getsockopt(listener_fd, SOL_SOCKET, SO_TYPE, &v2, &n);

        if (r < 0)
                return (errno == EBADF || errno == ENOTSOCK) ? CONTROLLER_E_LISTENER_INVALID : error_origin(-errno);
        if (v1 != AF_UNIX || v2 != SOCK_STREAM)
                return CONTROLLER_E_LISTENER_INVALID;

        r = controller_add_listener(controller, &listener, path, listener_fd, policy_path);
        if (r)
                return error_trace(r);

        fdlist_steal(fds, fd_index);

        c_dvar_write(out_v, "()");

        return 0;
}

static int controller_method_listener_release(Controller *controller, const char *path, CDVar *in_v, FDList *fds, CDVar *out_v) {
        ControllerListener *listener;
        int r;

        c_dvar_read(in_v, "()");

        r = controller_end_read(in_v);
        if (r)
                return error_trace(r);

        listener = controller_find_listener(controller, path);
        if (!listener)
                return CONTROLLER_E_LISTENER_NOT_FOUND;

        controller_listener_free(listener);

        c_dvar_write(out_v, "()");

        return 0;
}

static int controller_method_name_release(Controller *controller, const char *path, CDVar *in_v, FDList *fds, CDVar *out_v) {
        ControllerName *name;
        int r;

        c_dvar_read(in_v, "()");

        r = controller_end_read(in_v);
        if (r)
                return error_trace(r);

        name = controller_find_name(controller, path);
        if (!name)
                return CONTROLLER_E_ACTIVATION_NOT_FOUND;

        controller_name_free(name);

        c_dvar_write(out_v, "()");

        return 0;
}

static int controller_method_name_reset(Controller *controller, const char *path, CDVar *in_v, FDList *fds, CDVar *out_v) {
        ControllerName *name;
        int r;

        c_dvar_read(in_v, "()");

        r = controller_end_read(in_v);
        if (r)
                return error_trace(r);

        name = controller_find_name(controller, path);
        if (!name)
                return CONTROLLER_E_ACTIVATION_NOT_FOUND;

        controller_name_reset(name);

        c_dvar_write(out_v, "()");

        return 0;
}

static int controller_handle_method(const ControllerMethod *method, Controller *controller, const char *path, uint32_t serial, const char *signature_in, Message *message_in) {
        _c_cleanup_(c_dvar_deinitp) CDVar var_in = C_DVAR_INIT, var_out = C_DVAR_INIT;
        _c_cleanup_(message_unrefp) Message *message_out = NULL;
        void *data;
        size_t n_data;
        int r;

        /*
         * Verify the input signature and prepare the input & output variants
         * for input parsing and output marshaling.
         */

        r = controller_dvar_verify_signature_in(method->in, signature_in);
        if (r)
                return error_trace(r);

        c_dvar_begin_read(&var_in, message_in->big_endian, method->in, 1, message_in->body, message_in->n_body);
        c_dvar_begin_write(&var_out, method->out, 1);

        /*
         * Write the generic reply-header and then call into the method-handler
         * of the specific controller method. Note that the controller-methods are
         * responsible to call controller_end_read(var_in), to verify all read data
         * was correct.
         */

        c_dvar_write(&var_out, "(");
        controller_write_reply_header(&var_out, serial, method->out);

        r = method->fn(controller, path, &var_in, message_in->fds, &var_out);
        if (r)
                return error_trace(r);

        c_dvar_write(&var_out, ")");

        /*
         * The message was correctly handled and the reply is serialized in
         * @var_out. Lets finish it up and queue the reply on the destination.
         * Note that any failure in doing so must be a fatal error, so there is
         * no point in reverting the operation on failure.
         */

        r = c_dvar_end_write(&var_out, &data, &n_data);
        if (r)
                return error_origin(r);

        r = message_new_outgoing(&message_out, data, n_data);
        if (r)
                return error_fold(r);

        r = connection_queue(&controller->manager->controller, NULL, 0, message_out);
        if (r) {
                if (r == CONNECTION_E_QUOTA)
                        connection_close(&controller->manager->controller);
                else
                        return error_fold(r);
        }

        return 0;
}

static int controller_dispatch_controller(Controller *controller, uint32_t serial, const char *method, const char *path, const char *signature, Message *message) {
        static const ControllerMethod methods[] = {
                { "AddName",            controller_method_add_name,     controller_type_in_osu, controller_type_out_unit },
                { "AddListener",        controller_method_add_listener, controller_type_in_ohs,  controller_type_out_unit },
        };

        for (size_t i = 0; i < C_ARRAY_SIZE(methods); i++) {
                if (strcmp(methods[i].name, method) != 0)
                        continue;

                return controller_handle_method(&methods[i], controller, path, serial, signature, message);
        }

        return CONTROLLER_E_UNEXPECTED_METHOD;
}

static int controller_dispatch_name(Controller *controller, uint32_t serial, const char *method, const char *path, const char *signature, Message *message) {
        static const ControllerMethod methods[] = {
                { "Reset",      controller_method_name_reset,   c_dvar_type_unit,       controller_type_out_unit },
                { "Release",    controller_method_name_release, c_dvar_type_unit,       controller_type_out_unit },
        };

        for (size_t i = 0; i < C_ARRAY_SIZE(methods); i++) {
                if (strcmp(methods[i].name, method) != 0)
                        continue;

                return controller_handle_method(&methods[i], controller, path, serial, signature, message);
        }

        return CONTROLLER_E_UNEXPECTED_METHOD;
}

static int controller_dispatch_listener(Controller *controller, uint32_t serial, const char *method, const char *path, const char *signature, Message *message) {
        static const ControllerMethod methods[] = {
                { "Release",    controller_method_listener_release,     c_dvar_type_unit,       controller_type_out_unit },
                /* XXX: SetPolicy */
        };

        for (size_t i = 0; i < C_ARRAY_SIZE(methods); i++) {
                if (strcmp(methods[i].name, method) != 0)
                        continue;

                return controller_handle_method(&methods[i], controller, path, serial, signature, message);
        }

        return CONTROLLER_E_UNEXPECTED_METHOD;
}

static int controller_dispatch_object(Controller *controller, uint32_t serial, const char *interface, const char *member, const char *path, const char *signature, Message *message) {
        if (strcmp(path, "/org/bus1/DBus/Broker") == 0) {
                if (interface && _c_unlikely_(strcmp(interface, "org.bus1.DBus.Broker") != 0))
                        return CONTROLLER_E_UNEXPECTED_INTERFACE;

                return controller_dispatch_controller(controller, serial, member, path, signature, message);
        } else if (strncmp(path, "/org/bus1/DBus/Name/", strlen("/org/bus1/DBus/Name/")) == 0) {
                if (interface && _c_unlikely_(strcmp(interface, "org.bus1.DBus.Name") != 0))
                        return CONTROLLER_E_UNEXPECTED_INTERFACE;

                return controller_dispatch_name(controller, serial, member, path, signature, message);
        } else if (strncmp(path, "/org/bus1/DBus/Listener/", strlen("/org/bus1/DBus/Listener/")) == 0) {
                if (interface && _c_unlikely_(strcmp(interface, "org.bus1.DBus.Listener") != 0))
                        return CONTROLLER_E_UNEXPECTED_INTERFACE;

                return controller_dispatch_listener(controller, serial, member, path, signature, message);
        }

        return CONTROLLER_E_UNEXPECTED_PATH;
}

int controller_dispatch(Controller *controller, Message *message) {
        Bus *bus = &controller->manager->bus;
        int r;

        if (message->header->type != DBUS_MESSAGE_TYPE_METHOD_CALL)
                return CONTROLLER_E_DISCONNECT;

        r = message_parse_metadata(message);
        if (r > 0)
                return CONTROLLER_E_DISCONNECT;
        else if (r < 0)
                return error_fold(r);

        r = controller_dispatch_object(controller,
                                       message->metadata.header.serial,
                                       message->metadata.fields.interface,
                                       message->metadata.fields.member,
                                       message->metadata.fields.path,
                                       message->metadata.fields.signature,
                                       message);
        switch (r) {
        case CONTROLLER_E_INVALID_MESSAGE:
                return CONTROLLER_E_DISCONNECT;
        case CONTROLLER_E_UNEXPECTED_PATH:
        case CONTROLLER_E_UNEXPECTED_MESSAGE_TYPE:
                r = controller_send_error(bus->controller, message->metadata.header.serial, "org.freedesktop.DBus.Error.AccessDenied");
                break;
        case CONTROLLER_E_UNEXPECTED_INTERFACE:
                r = controller_send_error(bus->controller, message->metadata.header.serial, "org.freedesktop.DBus.Error.UnknownInterface");
                break;
        case CONTROLLER_E_UNEXPECTED_METHOD:
                r = controller_send_error(bus->controller, message->metadata.header.serial, "org.freedesktop.DBus.Error.UnknownMethod");
                break;
        case CONTROLLER_E_UNEXPECTED_SIGNATURE:
                r = controller_send_error(bus->controller, message->metadata.header.serial, "org.freedesktop.DBus.Error.InvalidArgs");
                break;
        default:
                break;
        }

        return error_trace(r);
}

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

        activation_free(name->activation);
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
                return CONTROLLER_E_ACTIVATION_EXISTS;

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

void controller_name_reset(ControllerName *name) {
        assert(!name->activation);

        activation_flush(name->activation);
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

        listener_free(listener->listener);
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

/**
 * controller_init() - XXX
 */
void controller_init(Controller *controller, Manager *manager) {
        *controller = (Controller)CONTROLLER_INIT(manager);
}

/**
 * controller_deinit() - XXX
 */
void controller_deinit(Controller *controller) {
        assert(c_rbtree_is_empty(&controller->name_tree));
        assert(c_rbtree_is_empty(&controller->listener_tree));
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

        r = activation_new(&name->activation, &controller->manager->bus.activations, path, name_entry, user_entry);
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

        r = listener_new_with_fd(&listener->listener,
                                 &controller->manager->bus,
                                 path,
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
