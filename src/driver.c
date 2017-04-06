/*
 * DBus Driver
 */

#include <c-dvar.h>
#include <c-dvar-type.h>
#include <c-macro.h>
#include <c-string.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include "bus.h"
#include "driver.h"
#include "message.h"
#include "peer.h"
#include "socket.h"

/* XXX: move to where it belongs */
#define DBUS_MESSAGE_TYPE_INVALID       (0)
#define DBUS_MESSAGE_TYPE_METHOD_CALL   (1)
#define DBUS_MESSAGE_TYPE_METHOD_REPLY  (2)
#define DBUS_MESSAGE_TYPE_ERROR         (3)
#define DBUS_MESSAGE_TYPE_SIGNAL        (4)

#define DBUS_MESSAGE_FIELD_INVALID      (0)
#define DBUS_MESSAGE_FIELD_PATH         (1)
#define DBUS_MESSAGE_FIELD_INTERFACE    (2)
#define DBUS_MESSAGE_FIELD_MEMBER       (3)
#define DBUS_MESSAGE_FIELD_ERROR_NAME   (4)
#define DBUS_MESSAGE_FIELD_REPLY_SERIAL (5)
#define DBUS_MESSAGE_FIELD_DESTINATION  (6)
#define DBUS_MESSAGE_FIELD_SENDER       (7)
#define DBUS_MESSAGE_FIELD_SIGNATURE    (8)
#define DBUS_MESSAGE_FIELD_UNIX_FDS     (9)

#define DBUS_HEADER_FLAG_NO_REPLY_EXPECTED                      (1UL << 0)
#define DBUS_HEADER_FLAG_NO_AUTO_START                          (1UL << 1)
#define DBUS_HEADER_FLAG_ALLOW_INTERACTIVE_AUTHORIZATION        (1UL << 2)

#define DRIVER_T_OUT_INIT(type)         C_DVAR_T_INIT(                                          \
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
                                                        type                                    \
                                                )                                               \
                                        )
static const CDVarType * const driver_type_in_unit = (const CDVarType[]){
                                                C_DVAR_T_INIT(
                                                        C_DVAR_T_TUPLE0
                                                ) };
static const CDVarType * const driver_type_in_s = (const CDVarType[]){
                                                C_DVAR_T_INIT(
                                                        C_DVAR_T_TUPLE1(
                                                                C_DVAR_T_s
                                                        )
                                                ) };
static const CDVarType * const driver_type_in_apss = (const CDVarType[]){
                                                C_DVAR_T_INIT(
                                                        C_DVAR_T_TUPLE1(
                                                                C_DVAR_T_ARRAY(
                                                                        C_DVAR_T_PAIR(
                                                                                C_DVAR_T_s,
                                                                                C_DVAR_T_s
                                                                        )
                                                                )
                                                        )
                                                ) };
static const CDVarType * const driver_type_in_asu = (const CDVarType[]){
                                                C_DVAR_T_INIT(
                                                        C_DVAR_T_TUPLE2(
                                                                C_DVAR_T_ARRAY(
                                                                        C_DVAR_T_s
                                                                ),
                                                                C_DVAR_T_u
                                                        )
                                                ) };

static const CDVarType * const driver_type_out_unit = (const CDVarType[]){
                                                DRIVER_T_OUT_INIT(
                                                        C_DVAR_T_TUPLE0
                                                ) };
static const CDVarType * const driver_type_out_s = (const CDVarType[]){
                                                DRIVER_T_OUT_INIT(
                                                        C_DVAR_T_TUPLE1(
                                                                C_DVAR_T_s
                                                        )
                                                ) };
static const CDVarType * const driver_type_out_b = (const CDVarType[]){
                                                DRIVER_T_OUT_INIT(
                                                        C_DVAR_T_TUPLE1(
                                                                C_DVAR_T_b
                                                        )
                                                ) };
static const CDVarType * const driver_type_out_u = (const CDVarType[]){
                                                DRIVER_T_OUT_INIT(
                                                        C_DVAR_T_TUPLE1(
                                                                C_DVAR_T_u
                                                        )
                                                ) };
static const CDVarType * const driver_type_out_as = (const CDVarType[]){
                                                DRIVER_T_OUT_INIT(
                                                        C_DVAR_T_TUPLE1(
                                                                C_DVAR_T_ARRAY(
                                                                        C_DVAR_T_s
                                                                )
                                                        )
                                                ) };
static const CDVarType * const driver_type_out_ab = (const CDVarType[]){
                                                DRIVER_T_OUT_INIT(
                                                        C_DVAR_T_TUPLE1(
                                                                C_DVAR_T_ARRAY(
                                                                        C_DVAR_T_b
                                                                )
                                                        )
                                                ) };
static const CDVarType * const driver_type_out_apsv = (const CDVarType[]){
                                                DRIVER_T_OUT_INIT(
                                                        C_DVAR_T_TUPLE1(
                                                                C_DVAR_T_ARRAY(
                                                                        C_DVAR_T_PAIR(
                                                                                C_DVAR_T_s,
                                                                                C_DVAR_T_v
                                                                        )
                                                                )
                                                        )
                                                ) };

typedef struct DriverMethod DriverMethod;
typedef int (*DriverMethodFn) (Peer *peer, CDVar *var_in, CDVar *var_out);

struct DriverMethod {
        const char *name;
        DriverMethodFn fn;
        const CDVarType * const *in;
        const CDVarType * const *out;
};

static void driver_dvar_write_unique_name(CDVar *var, Peer *peer) {
        char unique_name[strlen(":1.") + C_DECIMAL_MAX(uint64_t) + 1];
        int r;

        r = snprintf(unique_name, sizeof(unique_name), ":1.%"PRIu64, peer->id);
        assert(r >= 0 && r < sizeof(unique_name));

        c_dvar_write(var, "s", unique_name);
}

static void driver_dvar_write_signature_out(CDVar *var, const CDVarType *type) {
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

static int driver_dvar_verify_signature_in(const CDVarType *type, const char *signature) {
        if (type->length - 2 != strlen(signature))
                return -EBADMSG;

        assert(type[0].element == '(');
        assert(type[type->length - 1].element == ')');

        for (unsigned int i = 1; i < type->length - 1; i++)
                if (signature[i - 1] != type[i].element)
                        return -EBADMSG;

        return 0;
}

static void driver_write_reply_header(CDVar *var,
                                      Peer *peer,
                                      uint32_t serial,
                                      const CDVarType *type) {
        c_dvar_write(var, "(yyyyuu[(y<u>)(y<s>)(y<",
                     c_dvar_is_big_endian(var) ? 'B' : 'l', DBUS_MESSAGE_TYPE_METHOD_REPLY, DBUS_HEADER_FLAG_NO_REPLY_EXPECTED, 1, 0, 1,
                     DBUS_MESSAGE_FIELD_REPLY_SERIAL, c_dvar_type_u, serial,
                     DBUS_MESSAGE_FIELD_SENDER, c_dvar_type_s, "org.freedesktop.DBus",
                     DBUS_MESSAGE_FIELD_DESTINATION, c_dvar_type_s);
        driver_dvar_write_unique_name(var, peer);
        c_dvar_write(var, ">)(y<",
                     DBUS_MESSAGE_FIELD_SIGNATURE, c_dvar_type_g);
        driver_dvar_write_signature_out(var, type);
        c_dvar_write(var, ">)])");
}

static int driver_method_hello(Peer *peer, CDVar *in_v, CDVar *out_v) {
        int r;

        if (_c_unlikely_(peer_is_registered(peer)))
                return -EBADMSG;

        /* verify the input argument */
        c_dvar_read(in_v, "()");

        r = c_dvar_end_read(in_v);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        /* write the output message */
        c_dvar_write(out_v, "(");
        driver_dvar_write_unique_name(out_v, peer);
        c_dvar_write(out_v, ")");

        /* register on the bus */
        bus_register_peer(peer->bus, peer);

        return 0;
}

static int driver_method_list_names(Peer *peer, CDVar *in_v, CDVar *out_v) {
        return 0;
}

static int driver_method_list_activatable_names(Peer *peer, CDVar *in_v, CDVar *out_v) {
        return 0;
}

static int driver_method_name_has_owner(Peer *peer, CDVar *in_v, CDVar *out_v) {
        return 0;
}

static int driver_method_start_service_by_name(Peer *peer, CDVar *in_v, CDVar *out_v) {
        return 0;
}

static int driver_method_update_activation_environment(Peer *peer, CDVar *in_v, CDVar *out_v) {
        return 0;
}

static int driver_method_get_name_owner(Peer *peer, CDVar *in_v, CDVar *out_v) {
        return 0;
}

static int driver_method_get_connection_unix_user(Peer *peer, CDVar *in_v, CDVar *out_v) {
        return 0;
}

static int driver_method_get_connection_unix_process_id(Peer *peer, CDVar *in_v, CDVar *out_v) {
        return 0;
}

static int driver_method_get_connection_credentials(Peer *peer, CDVar *in_v, CDVar *out_v) {
        return 0;
}

static int driver_method_get_adt_audit_session_data(Peer *peer, CDVar *in_v, CDVar *out_v) {
        return 0;
}

static int driver_method_get_connection_selinux_security_context(Peer *peer, CDVar *in_v, CDVar *out_v) {
        return 0;
}

static int driver_method_add_match(Peer *peer, CDVar *in_v, CDVar *out_v) {
        return 0;
}

static int driver_method_remove_match(Peer *peer, CDVar *in_v, CDVar *out_v) {
        return 0;
}

static int driver_method_get_id(Peer *peer, CDVar *in_v, CDVar *out_v) {
        char buffer[sizeof(peer->bus->guid) * 2];
        int r;

        /* verify the input argument */
        c_dvar_read(in_v, "()");

        r = c_dvar_end_read(in_v);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        /* write the output message */
        c_string_to_hex(peer->bus->guid, sizeof(peer->bus->guid), buffer);
        c_dvar_write(out_v, "(s)", buffer);

        return 0;
}

static int driver_method_become_monitor(Peer *peer, CDVar *in_v, CDVar *out_v) {
        return 0;
}

static int driver_handle_method(const DriverMethod *method, Peer *peer, uint32_t serial, const char *signature_in, Message *message_in) {
        _c_cleanup_(c_dvar_freep) CDVar *var_in = NULL, *var_out = NULL;
        _c_cleanup_(message_unrefp) Message *message_out = NULL;
        void *data;
        size_t n_data;
        int r;

        /* prepare the input variant */
        r = driver_dvar_verify_signature_in(*method->in, signature_in);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        r = c_dvar_new(&var_in);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        c_dvar_begin_read(var_in, message_in->big_endian, *method->in, message_in->body, message_in->n_body);

        /* prepare the output variant */
        r = c_dvar_new(&var_out);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        /* call the handler and write the output */
        c_dvar_begin_write(var_out, *method->out);

        c_dvar_write(var_out, "(");

        driver_write_reply_header(var_out, peer, serial, *method->out);

        r = method->fn(peer, var_in, var_out);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        c_dvar_write(var_out, ")");

        r = c_dvar_end_write(var_out, &data, &n_data);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        r = message_new_outgoing(&message_out, data, n_data);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        r = socket_queue_message(peer->socket, message_out);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        dispatch_file_select(&peer->dispatch_file, EPOLLOUT);

        return 0;
}

static int driver_dispatch_method(Peer *peer, uint32_t serial, const char *method, const char *signature, Message *message) {
        static const DriverMethod methods[] = {
                { "Hello", driver_method_hello, &driver_type_in_unit, &driver_type_out_s },
                { "ListNames", driver_method_list_names, &driver_type_in_unit, &driver_type_out_as },
                { "ListActivatableNames", driver_method_list_activatable_names, &driver_type_in_unit, &driver_type_out_as },
                { "NameHasOwner", driver_method_name_has_owner, &driver_type_in_s, &driver_type_out_b },
                { "StartServiceByName", driver_method_start_service_by_name, &driver_type_in_s, &driver_type_out_u },
                { "UpdateActivationEnvironment", driver_method_update_activation_environment, &driver_type_in_apss, &driver_type_out_unit },
                { "GetNameOwner", driver_method_get_name_owner, &driver_type_in_s, &driver_type_out_s },
                { "GetConnectionUnixUser", driver_method_get_connection_unix_user, &driver_type_in_s, &driver_type_out_u },
                { "GetConnectionUnixProcessID", driver_method_get_connection_unix_process_id, &driver_type_in_s, &driver_type_out_u },
                { "GetConnecitonCredentials", driver_method_get_connection_credentials, &driver_type_in_s, &driver_type_out_apsv },
                { "GetAdtAuditSessionData", driver_method_get_adt_audit_session_data, &driver_type_in_s, &driver_type_out_ab },
                { "GetConnectionSELinuxSecurityContext", driver_method_get_connection_selinux_security_context, &driver_type_in_s, &driver_type_out_ab },
                { "AddMatch", driver_method_add_match, &driver_type_in_s, &driver_type_out_unit },
                { "RemoveMatch", driver_method_remove_match, &driver_type_in_s, &driver_type_out_unit },
                { "GetId", driver_method_get_id, &driver_type_in_unit, &driver_type_out_s },
                { "BecomeMonitor", driver_method_become_monitor, &driver_type_in_asu, &driver_type_out_unit },
        };
        int r;

        if (_c_unlikely_(!peer_is_registered(peer)) && strcmp(method, "Hello") != 0)
                return -EBADMSG;

        for (size_t i = 0; i < C_ARRAY_SIZE(methods); i++) {
                if (strcmp(methods[i].name, method) != 0)
                        continue;

                r = driver_handle_method(&methods[i], peer, serial, signature, message);
                if (r < 0)
                        return r;
        }

        return -ENOENT;
}

static int driver_dispatch_interface(Peer *peer,
                                     uint32_t serial,
                                     const char *interface,
                                     const char *member,
                                     const char *path,
                                     const char *signature,
                                     Message *message) {
        if (message->header->type != DBUS_MESSAGE_TYPE_METHOD_CALL)
                return -EBADMSG;

        if (interface && _c_unlikely_(strcmp(interface, "org.freedesktop.DBus") != 0))
                return -EBADMSG;

        /* XXX: path ? */

        return driver_dispatch_method(peer, serial, member, signature, message);
}

static Peer *driver_find_peer_by_name(Bus *bus, const char *destination) {
        if (*destination != ':') {
                return name_registry_resolve_name(&bus->names, destination);
        } else {
                char *end;
                uint64_t id;

                if (strlen(destination) < strlen(":1."))
                        return NULL;

                destination += strlen(":1.");

                errno = 0;
                id = strtoull(destination, &end, 10);
                if (errno != 0)
                        return NULL;
                if (*end || destination == end)
                        return NULL;

                return bus_find_peer(bus, id);
        }
}

static int driver_forward_unicast(Peer *sender, const char *destination, const char *signature, Message *message) {
        Peer *receiver;
        int r;

        receiver = driver_find_peer_by_name(sender->bus, destination);
        if (!receiver)
                return -EBADMSG;

        /* XXX: verify message contents, append sender */

        r = socket_queue_message(receiver->socket, message);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        dispatch_file_select(&receiver->dispatch_file, EPOLLOUT);

        return 0;
}

static int driver_forward_broadcast(Peer *peer, const char *signature, Message *message) {
        return 0;
}

int driver_handle_message(Peer *peer, Message *message) {
        static const CDVarType type[] = {
                C_DVAR_T_INIT(
                        C_DVAR_T_TUPLE7(
                                C_DVAR_T_y,
                                C_DVAR_T_y,
                                C_DVAR_T_y,
                                C_DVAR_T_y,
                                C_DVAR_T_u,
                                C_DVAR_T_u,
                                C_DVAR_T_ARRAY(
                                        C_DVAR_T_TUPLE2(
                                                C_DVAR_T_y,
                                                C_DVAR_T_v
                                        )
                                )
                        )
                ), /* (yyyyuua(yv)) */
        };
        _c_cleanup_(c_dvar_freep) CDVar *v = NULL;
        const char *path = NULL,
                   *interface = NULL,
                   *member = NULL,
                   *error_name = NULL,
                   *destination = NULL,
                   *sender = NULL,
                   *signature = "";
        uint32_t serial = 0, reply_serial = 0, n_fds = 0;
        uint8_t field;
        int r;

        /*
         * XXX: Rather than allocating @v, we should use its static versions on the stack,
         *      once provided by c-dvar.
         */

        r = c_dvar_new(&v);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        c_dvar_begin_read(v, message->big_endian, type, message->header, message->n_header);

        c_dvar_read(v, "(yyyyuu[", NULL, NULL, NULL, NULL, NULL, &serial);

        while (c_dvar_more(v)) {
                /*
                 * XXX: What should we do on duplicates?
                 */

                c_dvar_read(v, "(y", &field);

                switch (field) {
                case DBUS_MESSAGE_FIELD_INVALID:
                        return -EBADMSG;
                case DBUS_MESSAGE_FIELD_PATH:
                        c_dvar_read(v, "<o>)", c_dvar_type_o, &path);
                        break;
                case DBUS_MESSAGE_FIELD_INTERFACE:
                        c_dvar_read(v, "<s>)", c_dvar_type_s, &interface);
                        break;
                case DBUS_MESSAGE_FIELD_MEMBER:
                        c_dvar_read(v, "<s>)", c_dvar_type_s, &member);
                        break;
                case DBUS_MESSAGE_FIELD_ERROR_NAME:
                        c_dvar_read(v, "<s>)", c_dvar_type_s, &error_name);
                        break;
                case DBUS_MESSAGE_FIELD_REPLY_SERIAL:
                        c_dvar_read(v, "<u>)", c_dvar_type_u, &reply_serial);
                        break;
                case DBUS_MESSAGE_FIELD_DESTINATION:
                        c_dvar_read(v, "<s>)", c_dvar_type_s, &destination);
                        break;
                case DBUS_MESSAGE_FIELD_SENDER:
                        /* XXX: check with dbus-daemon(1) on what to do */
                        c_dvar_read(v, "<s>)", c_dvar_type_s, &sender);
                        break;
                case DBUS_MESSAGE_FIELD_SIGNATURE:
                        c_dvar_read(v, "<g>)", c_dvar_type_g, &signature);
                        break;
                case DBUS_MESSAGE_FIELD_UNIX_FDS:
                        c_dvar_read(v, "<u>)", c_dvar_type_u, &n_fds);
                        break;
                default:
                        c_dvar_skip(v, "v)");
                        break;
                }
        }

        c_dvar_read(v, "])");

        r = c_dvar_end_read(v);
        if (r)
                return (r > 0) ? -EBADMSG : r;

        if (_c_unlikely_(n_fds > message->n_fds))
                return -EBADMSG;
        while (_c_unlikely_(n_fds < message->n_fds))
                close(message->fds[-- message->n_fds]);

        if (destination) {
                if (_c_unlikely_(c_string_equal(destination, "org.freedesktop.DBus")))
                        return driver_dispatch_interface(peer, serial, interface, member, path, signature, message);
                else
                        return driver_forward_unicast(peer, destination, signature, message);
        } else {
                return driver_forward_broadcast(peer, signature, message);
        }

        return 0;
}

void driver_notify_name_owner_change(const char *name, Peer *old_peer, Peer *new_peer) {
        assert(old_peer || new_peer);
        assert(!old_peer || c_rbnode_is_linked(&old_peer->rb));
        assert(!new_peer || c_rbnode_is_linked(&new_peer->rb));
        assert(name || !old_peer || !new_peer);
}
