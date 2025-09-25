/*
 * D-Bus Interface of Broker Controller
 */

#include <c-dvar.h>
#include <c-dvar-type.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "broker/broker.h"
#include "broker/controller.h"
#include "bus/policy.h"
#include "dbus/connection.h"
#include "dbus/message.h"
#include "dbus/protocol.h"
#include "util/error.h"
#include "util/fdlist.h"

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

static const CDVarType controller_type_in_t[] = {
        C_DVAR_T_INIT(
                C_DVAR_T_TUPLE2(
                        C_DVAR_T_t,
                        C_DVAR_T_s
                )
        )
};
static const CDVarType controller_type_in_v[] = {
        C_DVAR_T_INIT(
                C_DVAR_T_TUPLE1(
                        C_DVAR_T_v
                )
        )
};
static const CDVarType controller_type_in_oh[] = {
        C_DVAR_T_INIT(
                C_DVAR_T_TUPLE2(
                        C_DVAR_T_o,
                        C_DVAR_T_h
                )
        )
};
static const CDVarType controller_type_in_ohv[] = {
        C_DVAR_T_INIT(
                C_DVAR_T_TUPLE3(
                        C_DVAR_T_o,
                        C_DVAR_T_h,
                        C_DVAR_T_v
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

        c_assert(type->length < sizeof(signature) + strlen("((yyyyuua(yv))())"));
        c_assert(type[0].element == '(');
        c_assert(type[1].element == '(');
        c_assert(type[2].element == 'y');
        c_assert(type[3].element == 'y');
        c_assert(type[4].element == 'y');
        c_assert(type[5].element == 'y');
        c_assert(type[6].element == 'u');
        c_assert(type[7].element == 'u');
        c_assert(type[8].element == 'a');
        c_assert(type[9].element == '(');
        c_assert(type[10].element == 'y');
        c_assert(type[11].element == 'v');
        c_assert(type[12].element == ')');
        c_assert(type[13].element == ')');
        c_assert(type[14].element == '(');
        c_assert(type[type->length - 2].element == ')');
        c_assert(type[type->length - 1].element == ')');

        for (unsigned int i = strlen("((yyyyuua(yv))("), j = 0; i < type->length - strlen("))"); i++, j++)
                signature[j] = type[i].element;

        signature[type->length - strlen("((yyyyuua(yv))())")] = '\0';

        c_dvar_write(var, "g", signature);
}

static int controller_dvar_verify_signature_in(const CDVarType *type, const char *signature) {
        if (type->length != strlen(signature) + 2)
                return CONTROLLER_E_UNEXPECTED_SIGNATURE;

        c_assert(type[0].element == '(');
        c_assert(type[type->length - 1].element == ')');

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
        _c_cleanup_(c_dvar_deinit) CDVar var = C_DVAR_INIT;
        _c_cleanup_(message_unrefp) Message *message = NULL;
        _c_cleanup_(c_freep) void *data = NULL;
        size_t n_data;
        int r;

        if (!serial)
                return 0;

        c_dvar_begin_write(&var, (__BYTE_ORDER == __BIG_ENDIAN), controller_type_out_unit, 1);
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
        data = NULL;

        r = connection_queue(connection, NULL, message);
        if (r) {
                if (r == CONNECTION_E_QUOTA || r == CONNECTION_E_UNEXPECTED_FDS)
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
        case C_DVAR_E_DEPTH_OVERFLOW:
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
        if (!dbus_validate_name(name_str, strlen(name_str)) || name_str[0] == ':')
                return CONTROLLER_E_NAME_INVALID;

        r = controller_add_name(controller, &name, path, name_str, uid);
        if (r)
                return error_trace(r);

        c_dvar_write(out_v, "()");

        return 0;
}

static int controller_method_add_listener(Controller *controller, const char *_path, CDVar *in_v, FDList *fds, CDVar *out_v) {
        _c_cleanup_(policy_registry_freep) PolicyRegistry *policy = NULL;
        const char *path;
        ControllerListener *listener;
        int r, listener_fd, v1, v2;
        uint32_t fd_index;
        socklen_t n;

        r = policy_registry_new(&policy, controller->broker->bus.seclabel);
        if (r)
                return error_fold(r);

        c_dvar_read(in_v, "(oh", &path, &fd_index);

        r = policy_registry_import(policy, in_v);
        if (r)
                return (r == POLICY_E_INVALID) ? CONTROLLER_E_LISTENER_INVALID_POLICY : error_fold(r);

        c_dvar_read(in_v, ")");

        r = controller_end_read(in_v);
        if (r)
                return error_trace(r);

        if (strncmp(path, "/org/bus1/DBus/Listener/", strlen("/org/bus1/DBus/Listener/")) != 0)
                return CONTROLLER_E_UNEXPECTED_PATH;

        listener_fd = fdlist_get(fds, fd_index);
        if (listener_fd < 0)
                return CONTROLLER_E_LISTENER_INVALID_FD;

        n = sizeof(v1);
        r = getsockopt(listener_fd, SOL_SOCKET, SO_DOMAIN, &v1, &n);
        n = sizeof(v2);
        r = r ?: getsockopt(listener_fd, SOL_SOCKET, SO_TYPE, &v2, &n);

        if (r < 0)
                return (errno == EBADF || errno == ENOTSOCK) ? CONTROLLER_E_LISTENER_INVALID_FD : error_origin(-errno);
        if (v1 != AF_UNIX || v2 != SOCK_STREAM)
                return CONTROLLER_E_LISTENER_INVALID_FD;

        r = controller_add_listener(controller, &listener, path, listener_fd, policy);
        if (r)
                return error_trace(r);

        policy = NULL;
        fdlist_steal(fds, fd_index);

        c_dvar_write(out_v, "()");

        return 0;
}

static int controller_method_add_metrics(Controller *controller, const char *_path, CDVar *in_v, FDList *fds, CDVar *out_v) {
        const char *path;
        ControllerMetrics *metrics;
        int r, metrics_fd, v1, v2;
        uint32_t fd_index;
        socklen_t n;

        c_dvar_read(in_v, "(oh)", &path, &fd_index);

        r = controller_end_read(in_v);
        if (r)
                return error_trace(r);

        if (strncmp(path, "/org/bus1/DBus/Metrics/", strlen("/org/bus1/DBus/Metrics/")) != 0)
                return CONTROLLER_E_UNEXPECTED_PATH;

        metrics_fd = fdlist_get(fds, fd_index);
        if (metrics_fd < 0)
                return CONTROLLER_E_METRICS_INVALID_FD;

        n = sizeof(v1);
        r = getsockopt(metrics_fd, SOL_SOCKET, SO_DOMAIN, &v1, &n);
        n = sizeof(v2);
        r = r ?: getsockopt(metrics_fd, SOL_SOCKET, SO_TYPE, &v2, &n);

        if (r < 0)
                return (errno == EBADF || errno == ENOTSOCK) ? CONTROLLER_E_METRICS_INVALID_FD : error_origin(-errno);
        if (v1 != AF_UNIX || v2 != SOCK_STREAM)
                return CONTROLLER_E_METRICS_INVALID_FD;

        r = controller_add_metrics(controller, &metrics, path, metrics_fd);
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
                return CONTROLLER_E_NAME_NOT_FOUND;

        r = controller_name_reset(name, name->activation.pending, CONTROLLER_NAME_ERROR_NAME_RELEASED);
        if (r)
                return error_trace(r);

        controller_name_free(name);

        c_dvar_write(out_v, "()");

        return 0;
}

static int controller_method_metrics_release(Controller *controller, const char *path, CDVar *in_v, FDList *fds, CDVar *out_v) {
        ControllerMetrics *metrics;
        int r;

        c_dvar_read(in_v, "()");

        r = controller_end_read(in_v);
        if (r)
                return error_trace(r);

        metrics = controller_find_metrics(controller, path);
        if (!metrics)
                return CONTROLLER_E_METRICS_NOT_FOUND;

        controller_metrics_free(metrics);

        c_dvar_write(out_v, "()");

        return 0;
}

static int controller_method_listener_set_policy(Controller *controller, const char *path, CDVar *in_v, FDList *fds, CDVar *out_v) {
        _c_cleanup_(policy_registry_freep) PolicyRegistry *policy = NULL;
        ControllerListener *listener;
        int r;

        r = policy_registry_new(&policy, controller->broker->bus.seclabel);
        if (r)
                return error_fold(r);

        c_dvar_read(in_v, "(");

        r = policy_registry_import(policy, in_v);
        if (r)
                return (r == POLICY_E_INVALID) ? CONTROLLER_E_LISTENER_INVALID_POLICY : error_fold(r);

        c_dvar_read(in_v, ")");

        r = controller_end_read(in_v);
        if (r)
                return error_trace(r);

        listener = controller_find_listener(controller, path);
        if (!listener)
                return CONTROLLER_E_LISTENER_NOT_FOUND;

        r = controller_listener_set_policy(listener, policy);
        if (r)
                return error_trace(r);
        policy = NULL;

        c_dvar_write(out_v, "()");

        return 0;
}

static int controller_method_name_reset(Controller *controller, const char *path, CDVar *in_v, FDList *fds, CDVar *out_v) {
        ControllerName *name;
        unsigned int error;
        const char *reason;
        uint64_t serial;
        int r;

        c_dvar_read(in_v, "(ts)", &serial, &reason);

        r = controller_end_read(in_v);
        if (r)
                return error_trace(r);

        name = controller_find_name(controller, path);
        if (!name)
                return CONTROLLER_E_NAME_NOT_FOUND;

        error = controller_name_error_from_string(reason);
        if (!error)
                return CONTROLLER_E_INVALID_MESSAGE;

        r = controller_name_reset(name, serial, error);
        if (r)
                return error_trace(r);

        c_dvar_write(out_v, "()");

        return 0;
}

static int controller_handle_method(const ControllerMethod *method, Controller *controller, const char *path, uint32_t serial, const char *signature_in, Message *message_in) {
        _c_cleanup_(c_dvar_deinit) CDVar var_in = C_DVAR_INIT, var_out = C_DVAR_INIT;
        _c_cleanup_(message_unrefp) Message *message_out = NULL;
        _c_cleanup_(c_freep) void *data = NULL;
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
        c_dvar_begin_write(&var_out, (__BYTE_ORDER == __BIG_ENDIAN), method->out, 1);

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

        /* No reply expected. */
        if (!serial)
                return 0;

        r = message_new_outgoing(&message_out, data, n_data);
        if (r)
                return error_fold(r);
        data = NULL;

        r = connection_queue(&controller->connection, NULL, message_out);
        if (r) {
                if (r == CONNECTION_E_QUOTA || r == CONNECTION_E_UNEXPECTED_FDS)
                        connection_close(&controller->connection);
                else
                        return error_fold(r);
        }

        return 0;
}

static int controller_dispatch_controller(Controller *controller, uint32_t serial, const char *method, const char *path, const char *signature, Message *message) {
        static const ControllerMethod methods[] = {
                { "AddName",            controller_method_add_name,     controller_type_in_osu, controller_type_out_unit },
                { "AddListener",        controller_method_add_listener, controller_type_in_ohv, controller_type_out_unit },
                { "AddMetrics",         controller_method_add_metrics,  controller_type_in_oh,  controller_type_out_unit },
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
                { "Reset",      controller_method_name_reset,   controller_type_in_t,   controller_type_out_unit },
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
                { "SetPolicy",  controller_method_listener_set_policy,  controller_type_in_v,   controller_type_out_unit },
        };

        for (size_t i = 0; i < C_ARRAY_SIZE(methods); i++) {
                if (strcmp(methods[i].name, method) != 0)
                        continue;

                return controller_handle_method(&methods[i], controller, path, serial, signature, message);
        }

        return CONTROLLER_E_UNEXPECTED_METHOD;
}

static int controller_dispatch_metrics(Controller *controller, uint32_t serial, const char *method, const char *path, const char *signature, Message *message) {
        static const ControllerMethod methods[] = {
                { "Release",    controller_method_metrics_release,      c_dvar_type_unit,       controller_type_out_unit },
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
        } else if (strncmp(path, "/org/bus1/DBus/Metrics/", strlen("/org/bus1/DBus/Metrics/")) == 0) {
                if (interface && _c_unlikely_(strcmp(interface, "org.bus1.DBus.Metrics") != 0))
                        return CONTROLLER_E_UNEXPECTED_INTERFACE;

                return controller_dispatch_metrics(controller, serial, member, path, signature, message);
        }

        return CONTROLLER_E_UNEXPECTED_PATH;
}

static int controller_dispatch_reply(Controller *controller, uint32_t serial, const char *signature, Message *message) {
        ControllerReload *reload;
        int r;

        reload = controller_find_reload(controller, serial);
        if (!reload)
                return CONTROLLER_E_UNEXPECTED_REPLY;

        if (strcmp(signature, ""))
                return CONTROLLER_E_UNEXPECTED_SIGNATURE;

        r = controller_reload_completed(reload);
        if (r)
                return error_trace(r);

        controller_reload_free(reload);

        return 0;
}

static int controller_dispatch_error(Controller *controller, uint32_t serial, const char *error_name, Message *message) {
        ControllerReload *reload;
        int r;

        reload = controller_find_reload(controller, serial);
        if (!reload)
                return CONTROLLER_E_UNEXPECTED_REPLY;

        if (strcmp(error_name, "org.bus1.DBus.Controller.Error.InvalidConfig"))
                return CONTROLLER_E_UNEXPECTED_ERROR;

        r = controller_reload_invalid(reload);
        if (r)
                return error_trace(r);

        controller_reload_free(reload);

        return 0;
}

int controller_dbus_dispatch(Controller *controller, Message *message) {
        Connection *connection = &controller->connection;
        int r;

        r = message_parse_metadata(message);
        if (r > 0)
                return CONTROLLER_E_PROTOCOL_VIOLATION;
        else if (r < 0)
                return error_fold(r);

        switch (message->header->type) {
        case DBUS_MESSAGE_TYPE_METHOD_CALL:
                r = controller_dispatch_object(controller,
                                               message_read_serial(message),
                                               message->metadata.fields.interface,
                                               message->metadata.fields.member,
                                               message->metadata.fields.path,
                                               message->metadata.fields.signature,
                                               message);
                break;
        case DBUS_MESSAGE_TYPE_METHOD_RETURN:
                r = controller_dispatch_reply(controller,
                                              message->metadata.fields.reply_serial,
                                              message->metadata.fields.signature,
                                              message);
                break;
        case DBUS_MESSAGE_TYPE_ERROR:
                r = controller_dispatch_error(controller,
                                              message->metadata.fields.reply_serial,
                                              message->metadata.fields.error_name,
                                              message);
                break;
        default:
                return CONTROLLER_E_PROTOCOL_VIOLATION;
        }

        switch (r) {
        case CONTROLLER_E_INVALID_MESSAGE:
        case CONTROLLER_E_UNEXPECTED_REPLY:
        case CONTROLLER_E_UNEXPECTED_ERROR:
                return CONTROLLER_E_PROTOCOL_VIOLATION;
        case CONTROLLER_E_UNEXPECTED_MESSAGE_TYPE:
        case CONTROLLER_E_UNEXPECTED_PATH:
                r = controller_send_error(connection, message_read_serial(message), "org.freedesktop.DBus.Error.AccessDenied");
                break;
        case CONTROLLER_E_UNEXPECTED_INTERFACE:
                r = controller_send_error(connection, message_read_serial(message), "org.freedesktop.DBus.Error.UnknownInterface");
                break;
        case CONTROLLER_E_UNEXPECTED_METHOD:
                r = controller_send_error(connection, message_read_serial(message), "org.freedesktop.DBus.Error.UnknownMethod");
                break;
        case CONTROLLER_E_UNEXPECTED_SIGNATURE:
                r = controller_send_error(connection, message_read_serial(message), "org.freedesktop.DBus.Error.InvalidArgs");
                break;
        case CONTROLLER_E_LISTENER_EXISTS:
                r = controller_send_error(connection, message_read_serial(message), "org.bus1.DBus.Listener.Exists");
                break;
        case CONTROLLER_E_LISTENER_INVALID_FD:
                r = controller_send_error(connection, message_read_serial(message), "org.bus1.DBus.Listener.InvalidFD");
                break;
        case CONTROLLER_E_LISTENER_INVALID_POLICY:
                r = controller_send_error(connection, message_read_serial(message), "org.bus1.DBus.Listener.InvalidPolicy");
                break;
        case CONTROLLER_E_NAME_EXISTS:
                r = controller_send_error(connection, message_read_serial(message), "org.bus1.DBus.Name.Exists");
                break;
        case CONTROLLER_E_NAME_IS_ACTIVATABLE:
                r = controller_send_error(connection, message_read_serial(message), "org.bus1.DBus.Name.IsActivatable");
                break;
        case CONTROLLER_E_NAME_INVALID:
                r = controller_send_error(connection, message_read_serial(message), "org.bus1.DBus.Name.Invalid");
                break;
        case CONTROLLER_E_METRICS_EXISTS:
                r = controller_send_error(connection, message_read_serial(message), "org.bus1.DBus.Metrics.Exists");
                break;
        case CONTROLLER_E_METRICS_INVALID_FD:
                r = controller_send_error(connection, message_read_serial(message), "org.bus1.DBus.Metrics.InvalidFD");
                break;
        case CONTROLLER_E_LISTENER_NOT_FOUND:
                r = controller_send_error(connection, message_read_serial(message), "org.bus1.DBus.Listener.NotFound");
                break;
        case CONTROLLER_E_NAME_NOT_FOUND:
                r = controller_send_error(connection, message_read_serial(message), "org.bus1.DBus.Name.NotFound");
                break;
        case CONTROLLER_E_METRICS_NOT_FOUND:
                r = controller_send_error(connection, message_read_serial(message), "org.bus1.DBus.Metrics.NotFound");
                break;
        default:
                break;
        }

        return error_trace(r);
}

/**
 * controller_dbus_send_activation() - XXX
 */
int controller_dbus_send_activation(Controller *controller, const char *path, uint64_t serial) {
        static const CDVarType type[] = {
                C_DVAR_T_INIT(
                        CONTROLLER_T_MESSAGE(
                                C_DVAR_T_TUPLE1(
                                        C_DVAR_T_t
                                )
                        )
                )
        };
        _c_cleanup_(c_dvar_deinit) CDVar var = C_DVAR_INIT;
        _c_cleanup_(message_unrefp) Message *message = NULL;
        _c_cleanup_(c_freep) void *data = NULL;
        size_t n_data;
        int r;

        c_dvar_begin_write(&var, (__BYTE_ORDER == __BIG_ENDIAN), type, 1);
        c_dvar_write(&var, "((yyyyuu[(y<o>)(y<s>)(y<s>)(y<g>)])(t))",
                     c_dvar_is_big_endian(&var) ? 'B' : 'l', DBUS_MESSAGE_TYPE_SIGNAL, DBUS_HEADER_FLAG_NO_REPLY_EXPECTED, 1, 0, (uint32_t)-1,
                     DBUS_MESSAGE_FIELD_PATH, c_dvar_type_o, path,
                     DBUS_MESSAGE_FIELD_INTERFACE, c_dvar_type_s, "org.bus1.DBus.Name",
                     DBUS_MESSAGE_FIELD_MEMBER, c_dvar_type_s, "Activate",
                     DBUS_MESSAGE_FIELD_SIGNATURE, c_dvar_type_g, "t",
                     serial);

        r = c_dvar_end_write(&var, &data, &n_data);
        if (r)
                return error_origin(r);

        r = message_new_outgoing(&message, data, n_data);
        if (r)
                return error_fold(r);
        data = NULL;

        r = connection_queue(&controller->connection, NULL, message);
        if (r)
                return error_fold(r);

        return 0;
}

/**
 * controller_dbus_send_environment() - XXX
 */
int controller_dbus_send_environment(Controller *controller, const char * const *env, size_t n_env) {
        static const CDVarType type[] = {
                C_DVAR_T_INIT(
                        CONTROLLER_T_MESSAGE(
                                C_DVAR_T_TUPLE1(
                                        C_DVAR_T_ARRAY(
                                                C_DVAR_T_PAIR(
                                                        C_DVAR_T_s,
                                                        C_DVAR_T_s
                                                )
                                        )
                                )
                        )
                )
        };
        _c_cleanup_(c_dvar_deinit) CDVar var = C_DVAR_INIT;
        _c_cleanup_(message_unrefp) Message *message = NULL;
        _c_cleanup_(c_freep) void *data = NULL;
        size_t i, n_data;
        int r;

        c_dvar_begin_write(&var, (__BYTE_ORDER == __BIG_ENDIAN), type, 1);
        c_dvar_write(&var, "((yyyyuu[(y<o>)(y<s>)(y<s>)(y<g>)])([",
                     c_dvar_is_big_endian(&var) ? 'B' : 'l', DBUS_MESSAGE_TYPE_SIGNAL, DBUS_HEADER_FLAG_NO_REPLY_EXPECTED, 1, 0, (uint32_t)-1,
                     DBUS_MESSAGE_FIELD_PATH, c_dvar_type_o, "/org/bus1/DBus/Broker",
                     DBUS_MESSAGE_FIELD_INTERFACE, c_dvar_type_s, "org.bus1.DBus.Broker",
                     DBUS_MESSAGE_FIELD_MEMBER, c_dvar_type_s, "SetActivationEnvironment",
                     DBUS_MESSAGE_FIELD_SIGNATURE, c_dvar_type_g, "a{ss}");

        for (i = 0; i < n_env; ++i)
                c_dvar_write(&var, "{ss}", env[i * 2], env[i * 2 + 1]);

        c_dvar_write(&var, "]))");

        r = c_dvar_end_write(&var, &data, &n_data);
        if (r)
                return error_origin(r);

        r = message_new_outgoing(&message, data, n_data);
        if (r)
                return error_fold(r);
        data = NULL;

        r = connection_queue(&controller->connection, NULL, message);
        if (r)
                return error_fold(r);

        return 0;
}

/**
 * controller_dbus_send_reload() - XXX
 */
int controller_dbus_send_reload(Controller *controller, User *user, uint32_t serial) {
        static const CDVarType type[] = {
                C_DVAR_T_INIT(
                        CONTROLLER_T_MESSAGE(
                                C_DVAR_T_TUPLE0
                        )
                )
        };
        _c_cleanup_(c_dvar_deinit) CDVar var = C_DVAR_INIT;
        _c_cleanup_(message_unrefp) Message *message = NULL;
        _c_cleanup_(c_freep) void *data = NULL;
        size_t n_data;
        int r;

        c_dvar_begin_write(&var, (__BYTE_ORDER == __BIG_ENDIAN), type, 1);
        c_dvar_write(&var, "((yyyyuu[(y<o>)(y<s>)(y<s>)])())",
                     c_dvar_is_big_endian(&var) ? 'B' : 'l', DBUS_MESSAGE_TYPE_METHOD_CALL, 0, 1, 0, serial,
                     DBUS_MESSAGE_FIELD_PATH, c_dvar_type_o, "/org/bus1/DBus/Controller",
                     DBUS_MESSAGE_FIELD_INTERFACE, c_dvar_type_s, "org.bus1.DBus.Controller",
                     DBUS_MESSAGE_FIELD_MEMBER, c_dvar_type_s, "ReloadConfig");

        r = c_dvar_end_write(&var, &data, &n_data);
        if (r)
                return error_origin(r);

        r = message_new_outgoing(&message, data, n_data);
        if (r)
                return error_fold(r);
        data = NULL;

        r = connection_queue(&controller->connection, user, message);
        if (r) {
                if (r == CONNECTION_E_QUOTA)
                        return CONTROLLER_E_QUOTA;

                return error_fold(r);
        }

        return 0;
}
