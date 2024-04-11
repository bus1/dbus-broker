/*
 * DBus Driver
 */

#include <c-dvar.h>
#include <c-dvar-type.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include "broker/broker.h"
#include "broker/controller.h"
#include "bus/activation.h"
#include "bus/bus.h"
#include "bus/driver.h"
#include "bus/match.h"
#include "bus/peer.h"
#include "catalog/catalog-ids.h"
#include "dbus/address.h"
#include "dbus/message.h"
#include "dbus/protocol.h"
#include "dbus/socket.h"
#include "util/apparmor.h"
#include "util/error.h"
#include "util/selinux.h"
#include "util/string.h"

typedef struct DriverCredentials DriverCredentials;
typedef struct DriverInterface DriverInterface;
typedef struct DriverMethod DriverMethod;
typedef int (*DriverMethodFn) (Peer *peer, const char *path, CDVar *var_in, uint32_t serial, CDVar *var_out);

struct DriverCredentials {
        pid_t pid;
        int pid_fd;
        uid_t uid;
        gid_t *gids;
        size_t n_gids;
        const char *seclabel;
        size_t n_seclabel;
};

#define DRIVER_CREDENTIALS_NULL {       \
                .pid_fd = -1,           \
                .uid = -1,              \
        }

struct DriverMethod {
        const char *name;
        bool needs_registration;
        const char *path;
        DriverMethodFn fn;
        const CDVarType *in;
        const CDVarType *out;
        bool writes_own_header;
};

struct DriverInterface {
        const char *name;
        const DriverMethod *methods;
};

/*
 * This macro defines a c-dvar type for DBus Messages. It evaluates to:
 *
 *         ((yyyyuua(yv))X)
 *
 * ..where 'X' is provided via @_body. That is, it evaluates to the combination
 * of DBus Header and DBus Body for a given body-type.
 */
#define DRIVER_T_MESSAGE(_body) \
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

static const CDVarType driver_type_in_s[] = {
        C_DVAR_T_INIT(
                C_DVAR_T_TUPLE1(
                        C_DVAR_T_s
                )
        )
};
static const CDVarType driver_type_in_su[] = {
        C_DVAR_T_INIT(
                C_DVAR_T_TUPLE2(
                        C_DVAR_T_s,
                        C_DVAR_T_u
                )
        )
};
static const CDVarType driver_type_in_ss[] = {
        C_DVAR_T_INIT(
                C_DVAR_T_TUPLE2(
                        C_DVAR_T_s,
                        C_DVAR_T_s
                )
        )
};
static const CDVarType driver_type_in_ssv[] = {
        C_DVAR_T_INIT(
                C_DVAR_T_TUPLE3(
                        C_DVAR_T_s,
                        C_DVAR_T_s,
                        C_DVAR_T_v
                )
        )
};
static const CDVarType driver_type_in_apss[] = {
        C_DVAR_T_INIT(
                C_DVAR_T_TUPLE1(
                        C_DVAR_T_ARRAY(
                                C_DVAR_T_PAIR(
                                        C_DVAR_T_s,
                                        C_DVAR_T_s
                                )
                        )
                )
        )
};
static const CDVarType driver_type_in_asu[] = {
        C_DVAR_T_INIT(
                C_DVAR_T_TUPLE2(
                        C_DVAR_T_ARRAY(
                                C_DVAR_T_s
                        ),
                        C_DVAR_T_u
                )
        )
};
static const CDVarType driver_type_out_unit[] = {
        C_DVAR_T_INIT(
                DRIVER_T_MESSAGE(
                        C_DVAR_T_TUPLE0
                )
        )
};
static const CDVarType driver_type_out_s[] = {
        C_DVAR_T_INIT(
                DRIVER_T_MESSAGE(
                        C_DVAR_T_TUPLE1(
                                C_DVAR_T_s
                        )
                )
        )
};
static const CDVarType driver_type_out_b[] = {
        C_DVAR_T_INIT(
                DRIVER_T_MESSAGE(
                        C_DVAR_T_TUPLE1(
                                C_DVAR_T_b
                        )
                )
        )
};
static const CDVarType driver_type_out_u[] = {
        C_DVAR_T_INIT(
                DRIVER_T_MESSAGE(
                        C_DVAR_T_TUPLE1(
                                C_DVAR_T_u
                        )
                )
        )
};
static const CDVarType driver_type_out_v[] = {
        C_DVAR_T_INIT(
                DRIVER_T_MESSAGE(
                        C_DVAR_T_TUPLE1(
                                C_DVAR_T_v
                        )
                )
        )
};
static const CDVarType driver_type_out_as[] = {
        C_DVAR_T_INIT(
                DRIVER_T_MESSAGE(
                        C_DVAR_T_TUPLE1(
                                C_DVAR_T_ARRAY(
                                        C_DVAR_T_s
                                )
                        )
                )
        )
};
static const CDVarType driver_type_out_ay[] = {
        C_DVAR_T_INIT(
                DRIVER_T_MESSAGE(
                        C_DVAR_T_TUPLE1(
                                C_DVAR_T_ARRAY(
                                        C_DVAR_T_y
                                )
                        )
                )
        )
};
static const CDVarType driver_type_out_apsv[] = {
        C_DVAR_T_INIT(
                DRIVER_T_MESSAGE(
                        C_DVAR_T_TUPLE1(
                                C_DVAR_T_ARRAY(
                                        C_DVAR_T_PAIR(
                                                C_DVAR_T_s,
                                                C_DVAR_T_v
                                        )
                                )
                        )
                )
        )
};
static const CDVarType driver_type_out_apsas[] = {
        C_DVAR_T_INIT(
                DRIVER_T_MESSAGE(
                        C_DVAR_T_TUPLE1(
                                C_DVAR_T_ARRAY(
                                        C_DVAR_T_PAIR(
                                                C_DVAR_T_s,
                                                C_DVAR_T_ARRAY(
                                                        C_DVAR_T_s
                                                )
                                        )
                                )
                        )
                )
        )
};

static void driver_write_bytes(CDVar *var, const char *bytes, size_t n_bytes) {
        c_dvar_write(var, "[");
        for (size_t i = 0; i < n_bytes; ++i)
                c_dvar_write(var, "y", bytes[i]);
        c_dvar_write(var, "]");
}

static void driver_dvar_write_unique_name(CDVar *var, Peer *peer) {
        c_dvar_write(var, "s", address_to_string(&(Address)ADDRESS_INIT_ID(peer->id)));
}

static void driver_dvar_write_signature_out(CDVar *var, const CDVarType *type) {
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

static int driver_dvar_verify_signature_in(const CDVarType *type, const char *signature) {
        if (type->length != strlen(signature) + 2)
                return DRIVER_E_UNEXPECTED_SIGNATURE;

        c_assert(type[0].element == '(');
        c_assert(type[type->length - 1].element == ')');

        for (unsigned int i = 1; i + 1 < type->length; i++)
                if (signature[i - 1] != type[i].element)
                        return DRIVER_E_UNEXPECTED_SIGNATURE;

        return 0;
}

static void driver_write_reply_header(CDVar *var, Peer *peer, uint32_t serial, const CDVarType *type, size_t n_fds) {
        c_dvar_write(var, "(yyyyuu[(y<u>)(y<s>)(y<",
                     c_dvar_is_big_endian(var) ? 'B' : 'l', DBUS_MESSAGE_TYPE_METHOD_RETURN, DBUS_HEADER_FLAG_NO_REPLY_EXPECTED, 1, 0, (uint32_t)-1,
                     DBUS_MESSAGE_FIELD_REPLY_SERIAL, c_dvar_type_u, serial,
                     DBUS_MESSAGE_FIELD_SENDER, c_dvar_type_s, "org.freedesktop.DBus",
                     DBUS_MESSAGE_FIELD_DESTINATION, c_dvar_type_s);
        driver_dvar_write_unique_name(var, peer);
        c_dvar_write(var, ">)(y<",
                     DBUS_MESSAGE_FIELD_SIGNATURE, c_dvar_type_g);
        driver_dvar_write_signature_out(var, type);
        c_dvar_write(var, ">)");
        if (n_fds > 0)
                c_dvar_write(var, "(y<u>)", DBUS_MESSAGE_FIELD_UNIX_FDS, c_dvar_type_u, n_fds);
        c_dvar_write(var, "])");
}

static void driver_write_signal_header(CDVar *var, Peer *peer, const char *member, const char *signature) {
        c_dvar_write(var, "(yyyyuu[(y<s>)",
                     c_dvar_is_big_endian(var) ? 'B' : 'l', DBUS_MESSAGE_TYPE_SIGNAL, DBUS_HEADER_FLAG_NO_REPLY_EXPECTED, 1, 0, (uint32_t)-1,
                     DBUS_MESSAGE_FIELD_SENDER, c_dvar_type_s, "org.freedesktop.DBus");

        if (peer) {
                c_dvar_write(var, "(y<", DBUS_MESSAGE_FIELD_DESTINATION, c_dvar_type_s);
                driver_dvar_write_unique_name(var, peer);
                c_dvar_write(var, ">)");
        }

        c_dvar_write(var, "(y<o>)(y<s>)(y<s>)(y<g>)])",
                     DBUS_MESSAGE_FIELD_PATH, c_dvar_type_o, "/org/freedesktop/DBus",
                     DBUS_MESSAGE_FIELD_INTERFACE, c_dvar_type_s, "org.freedesktop.DBus",
                     DBUS_MESSAGE_FIELD_MEMBER, c_dvar_type_s, member,
                     DBUS_MESSAGE_FIELD_SIGNATURE, c_dvar_type_g, signature);
}

static const char *driver_error_to_string(int r) {
        static const char *error_strings[_DRIVER_E_MAX] = {
                [DRIVER_E_UNIMPLEMENTED]                        = "Unimplemented functionality",
                [DRIVER_E_PEER_ALREADY_REGISTERED]              = "Hello() already called",
                [DRIVER_E_PEER_NOT_YET_REGISTERED]              = "Hello() was not yet called",
                [DRIVER_E_PEER_NOT_REGISTERED]                  = "Message forwarding attempted without calling Hello()",
                [DRIVER_E_PEER_NOT_PRIVILEGED]                  = "The caller does not have the necessary privileged to call this method",
                [DRIVER_E_MONITOR_READ_ONLY]                    = "Monitor attempted to send message",
                [DRIVER_E_UNEXPECTED_FDS]                       = "Peer does not support file descriptor passing.",
                [DRIVER_E_UNEXPECTED_MESSAGE_TYPE]              = "Unexpected message type",
                [DRIVER_E_UNEXPECTED_PATH]                      = "Invalid object path",
                [DRIVER_E_UNEXPECTED_INTERFACE]                 = "Invalid interface",
                [DRIVER_E_UNEXPECTED_METHOD]                    = "Invalid method call",
                [DRIVER_E_UNEXPECTED_PROPERTY]                  = "Invalid property",
                [DRIVER_E_READONLY_PROPERTY]                    = "Cannot set read-only property",
                [DRIVER_E_UNEXPECTED_SIGNATURE]                 = "Invalid signature for method",
                [DRIVER_E_UNEXPECTED_REPLY]                     = "No pending reply with that serial",
                [DRIVER_E_FORWARD_FAILED]                       = "Request could not be forwarded to the parent process",
                [DRIVER_E_QUOTA]                                = "Sending user's quota exceeded",
                [DRIVER_E_UNEXPECTED_FLAGS]                     = "Invalid flags",
                [DRIVER_E_UNEXPECTED_ENVIRONMENT_UPDATE]        = "User is not authorized to update environment variables",
                [DRIVER_E_SEND_DENIED]                          = "Sender is not authorized to send message",
                [DRIVER_E_RECEIVE_DENIED]                       = "Receiver is not authorized to receive message",
                [DRIVER_E_EXPECTED_REPLY_EXISTS]                = "Pending reply with that serial already exists",
                [DRIVER_E_NAME_RESERVED]                        = "org.freedesktop.DBus is a reserved name",
                [DRIVER_E_NAME_UNIQUE]                          = "The name is a unique name",
                [DRIVER_E_NAME_INVALID]                         = "The name is not a valid well-known name",
                [DRIVER_E_NAME_REFUSED]                         = "Request to own name refused by policy",
                [DRIVER_E_NAME_NOT_FOUND]                       = "The name does not exist",
                [DRIVER_E_NAME_NOT_ACTIVATABLE]                 = "The name is not activatable",
                [DRIVER_E_NAME_OWNER_NOT_FOUND]                 = "The name does not have an owner",
                [DRIVER_E_PEER_NOT_FOUND]                       = "The connection does not exist",
                [DRIVER_E_DESTINATION_NOT_FOUND]                = "Destination does not exist",
                [DRIVER_E_MATCH_INVALID]                        = "Invalid match rule",
                [DRIVER_E_MATCH_NOT_FOUND]                      = "The match does not exist",
                [DRIVER_E_ADT_NOT_SUPPORTED]                    = "Solaris ADT is not supported",
                [DRIVER_E_SELINUX_NOT_SUPPORTED]                = "SELinux is not supported",
        };
        c_assert(r >= 0 && r < _DRIVER_E_MAX && error_strings[r]);

        return error_strings[r];
}

static int driver_monitor(Bus *bus, Peer *sender, Message *message) {
        _c_cleanup_(c_list_flush) CList destinations = C_LIST_INIT(destinations);
        MatchOwner *match_owner;
        int r;

        if (!bus->n_monitors)
                return 0;

        r = message_parse_metadata(message);
        if (r)
                return error_fold(r);

        bus_get_monitor_destinations(bus, &destinations, sender, &message->metadata);

        while ((match_owner = c_list_first_entry(&destinations, MatchOwner, destinations_link))) {
                Peer *receiver = c_container_of(match_owner, Peer, owned_matches);

                c_list_unlink(&match_owner->destinations_link);

                r = connection_queue(&receiver->connection, NULL, message);
                if (r) {
                        if (r == CONNECTION_E_QUOTA || r == CONNECTION_E_UNEXPECTED_FDS) {
                                NameSet sender_names = NAME_SET_INIT_FROM_OWNER(sender ? &sender->owned_names : NULL);

                                connection_shutdown(&receiver->connection);

                                log_append_here(bus->log, LOG_WARNING, 0, DBUS_BROKER_CATALOG_RECEIVE_FAILED);
                                bus_log_append_transaction(bus, sender ? sender->id : ADDRESS_ID_INVALID, receiver->id,
                                                           &sender_names, NULL,
                                                           sender ? sender->policy->seclabel : bus->seclabel, receiver->policy->seclabel,
                                                           message);
                                if (r == CONNECTION_E_QUOTA)
                                        r = log_commitf(bus->log, "Monitor :1.%llu is being disconnected as it does not have the resources to receive a message it subscribed to.", receiver->id);
                                else
                                        r = log_commitf(bus->log, "Monitor :1.%llu is being disconnected as it does not support receiving file descriptors it subscribed to.", receiver->id);
                                if (r)
                                        return error_fold(r);
                        } else {
                                return error_fold(r);
                        }
                }
        }

        return 0;
}

static int driver_send_unicast(Peer *receiver, Message *message) {
        int r;

        r = driver_monitor(receiver->bus, NULL, message);
        if (r)
                return error_fold(r);

        r = connection_queue(&receiver->connection, NULL, message);
        if (r) {
                if (r == CONNECTION_E_QUOTA || r == CONNECTION_E_UNEXPECTED_FDS) {
                        NameSet receiver_names = NAME_SET_INIT_FROM_OWNER(&receiver->owned_names);

                        connection_shutdown(&receiver->connection);

                        log_append_here(receiver->bus->log, LOG_WARNING, 0, DBUS_BROKER_CATALOG_RECEIVE_FAILED);
                        bus_log_append_transaction(receiver->bus, ADDRESS_ID_INVALID, receiver->id, NULL, &receiver_names,
                                                   receiver->bus->seclabel, receiver->policy->seclabel,
                                                   message);
                        if (r == CONNECTION_E_QUOTA)
                                r = log_commitf(receiver->bus->log, "Peer :1.%llu is being disconnected as it does not have the resources to receive a reply or unicast signal it expects.", receiver->id);
                        else
                                r = log_commitf(receiver->bus->log, "Peer :1.%llu is being disconnected as it does not support receiving file descriptors it expects.", receiver->id);
                        if (r)
                                return error_fold(r);
                } else {
                        return error_fold(r);
                }
        }

        return 0;
}

static int driver_send_error(Peer *receiver, uint32_t serial, const char *error, const char *error_message) {
        static const CDVarType type[] = {
                C_DVAR_T_INIT(
                        DRIVER_T_MESSAGE(
                                C_DVAR_T_TUPLE1(
                                        C_DVAR_T_s
                                )
                        )
                )
        };
        _c_cleanup_(c_dvar_deinit) CDVar var = C_DVAR_INIT;
        _c_cleanup_(message_unrefp) Message *message = NULL;
        _c_cleanup_(c_freep) void *data = NULL;
        size_t n_data;
        int r;

        /* If no reply was expected, never send an error. */
        if (!serial)
                return 0;

        c_dvar_begin_write(&var, (__BYTE_ORDER == __BIG_ENDIAN), type, 1);
        c_dvar_write(&var, "((yyyyuu[(y<u>)(y<s>)(y<s>)(y<g>)(y<",
                     c_dvar_is_big_endian(&var) ? 'B' : 'l', DBUS_MESSAGE_TYPE_ERROR, DBUS_HEADER_FLAG_NO_REPLY_EXPECTED, 1, 0, (uint32_t)-1,
                     DBUS_MESSAGE_FIELD_REPLY_SERIAL, c_dvar_type_u, serial,
                     DBUS_MESSAGE_FIELD_SENDER, c_dvar_type_s, "org.freedesktop.DBus",
                     DBUS_MESSAGE_FIELD_ERROR_NAME, c_dvar_type_s, error,
                     DBUS_MESSAGE_FIELD_SIGNATURE, c_dvar_type_g, "s",
                     DBUS_MESSAGE_FIELD_DESTINATION, c_dvar_type_s);
        driver_dvar_write_unique_name(&var, receiver);
        c_dvar_write(&var, ">)])(s))", error_message);

        r = c_dvar_end_write(&var, &data, &n_data);
        if (r)
                return error_origin(r);

        r = message_new_outgoing(&message, data, n_data);
        if (r)
                return error_fold(r);
        data = NULL;

        r = driver_send_unicast(receiver, message);
        if (r)
                return error_trace(r);

        return 0;
}

static int driver_send_reply_with_fds(Peer *peer, CDVar *var, uint32_t serial, int *fds, size_t n_fds) {
        _c_cleanup_(message_unrefp) Message *message = NULL;
        _c_cleanup_(c_freep) void *data = NULL;
        size_t n_data;
        int r;

        c_assert(fds || n_fds == 0);

        /*
         * The message was correctly handled and the reply is serialized in
         * @var. Lets finish it up and queue the reply on the destination.
         * Note that any failure in doing so must be a fatal error, so there is
         * no point in reverting the operation on failure.
         */

        c_dvar_write(var, ")");

        r = c_dvar_end_write(var, &data, &n_data);
        if (r)
                return error_origin(r);

        /* If no reply was expected, simply discard the message. */
        if (!serial)
                return 0;

        r = message_new_outgoing(&message, data, n_data);
        if (r)
                return error_fold(r);
        data = NULL;

        if (n_fds > 0) {
                r = fdlist_new_dup_fds(&message->fds, fds, n_fds);
                if (r)
                        return error_fold(r);
        }

        r = driver_send_unicast(peer, message);
        if (r)
                return error_trace(r);

        return 0;
}

static int driver_send_reply(Peer *peer, CDVar *var, uint32_t serial) {
        return driver_send_reply_with_fds(peer, var, serial, NULL, 0);
}

static int driver_notify_name_acquired(Peer *peer, const char *name) {
        static const CDVarType type[] = {
                C_DVAR_T_INIT(
                        DRIVER_T_MESSAGE(
                                C_DVAR_T_TUPLE1(
                                        C_DVAR_T_s
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
        c_dvar_write(&var, "(");
        driver_write_signal_header(&var, peer, "NameAcquired", "s");
        c_dvar_write(&var, "(s)", name);
        c_dvar_write(&var, ")");
        r = c_dvar_end_write(&var, &data, &n_data);
        if (r)
                return error_origin(r);

        r = message_new_outgoing(&message, data, n_data);
        if (r)
                return error_fold(r);
        data = NULL;

        r = driver_send_unicast(peer, message);
        if (r)
                return error_trace(r);

        return 0;
}

static int driver_notify_name_lost(Peer *peer, const char *name) {
        static const CDVarType type[] = {
                C_DVAR_T_INIT(
                        DRIVER_T_MESSAGE(
                                C_DVAR_T_TUPLE1(
                                        C_DVAR_T_s
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
        c_dvar_write(&var, "(");
        driver_write_signal_header(&var, peer, "NameLost", "s");
        c_dvar_write(&var, "(s)", name);
        c_dvar_write(&var, ")");
        r = c_dvar_end_write(&var, &data, &n_data);
        if (r)
                return error_origin(r);

        r = message_new_outgoing(&message, data, n_data);
        if (r)
                return error_fold(r);
        data = NULL;

        r = driver_send_unicast(peer, message);
        if (r)
                return error_trace(r);

        return 0;
}

static int driver_notify_name_owner_changed(Bus *bus, MatchRegistry *matches, const char *name, const char *old_owner, const char *new_owner) {
        _c_cleanup_(c_list_flush) CList destinations = C_LIST_INIT(destinations);
        MessageMetadata metadata = {
                .header = {
                        .type = DBUS_MESSAGE_TYPE_SIGNAL,
                },
                .sender_id = ADDRESS_ID_INVALID,
                .fields = {
                        .path = "/org/freedesktop/DBus",
                        .interface = "org.freedesktop.DBus",
                        .member = "NameOwnerChanged",
                },
                .args = {
                        {
                                .value = name,
                                .element = 's',
                        },
                        {
                                .value = old_owner,
                                .element = 's',
                        },
                        {
                                .value = new_owner,
                                .element = 's',
                        },
                },
                .n_args = 3,
        };
        int r;

        bus_get_monitor_destinations(bus, &destinations, NULL, &metadata);
        bus_get_broadcast_destinations(bus, &destinations, matches, NULL, &metadata);

        if (!c_list_is_empty(&destinations)) {
                static const CDVarType type[] = {
                        C_DVAR_T_INIT(
                                DRIVER_T_MESSAGE(
                                        C_DVAR_T_TUPLE3(
                                                C_DVAR_T_s,
                                                C_DVAR_T_s,
                                                C_DVAR_T_s
                                        )
                                )
                        )
                };
                _c_cleanup_(c_dvar_deinit) CDVar var = C_DVAR_INIT;
                _c_cleanup_(message_unrefp) Message *message = NULL;
                _c_cleanup_(c_freep) void *data = NULL;
                MatchOwner *match_owner;
                size_t n_data;

                c_dvar_begin_write(&var, (__BYTE_ORDER == __BIG_ENDIAN), type, 1);
                c_dvar_write(&var, "(");
                driver_write_signal_header(&var, NULL, "NameOwnerChanged", "sss");
                c_dvar_write(&var, "(sss)", name, old_owner, new_owner);
                c_dvar_write(&var, ")");
                r = c_dvar_end_write(&var, &data, &n_data);
                if (r)
                        return error_origin(r);

                r = message_new_outgoing(&message, data, n_data);
                if (r)
                        return error_fold(r);
                data = NULL;

                while ((match_owner = c_list_first_entry(&destinations, MatchOwner, destinations_link))) {
                        Peer *receiver = c_container_of(match_owner, Peer, owned_matches);

                        c_list_unlink(&match_owner->destinations_link);

                        r = policy_snapshot_check_receive(receiver->policy,
                                                          NULL,
                                                          NULL,
                                                          0,
                                                          metadata.fields.interface,
                                                          metadata.fields.member,
                                                          metadata.fields.path,
                                                          metadata.header.type,
                                                          true,
                                                          0);
                        if (r) {
                                if (r == POLICY_E_ACCESS_DENIED ||
                                    r == POLICY_E_SELINUX_ACCESS_DENIED ||
                                    r == POLICY_E_APPARMOR_ACCESS_DENIED)
                                        continue;

                                return error_fold(r);
                        }

                        r = connection_queue(&receiver->connection, NULL, message);
                        if (r) {
                                if (r == CONNECTION_E_QUOTA || r == CONNECTION_E_UNEXPECTED_FDS) {
                                        NameSet receiver_names = NAME_SET_INIT_FROM_OWNER(&receiver->owned_names);

                                        connection_shutdown(&receiver->connection);

                                        log_append_here(bus->log, LOG_WARNING, 0, DBUS_BROKER_CATALOG_RECEIVE_FAILED);
                                        bus_log_append_transaction(bus, ADDRESS_ID_INVALID, receiver->id, NULL, &receiver_names,
                                                                   receiver->bus->seclabel, receiver->policy->seclabel,
                                                                   message);
                                        if (r == CONNECTION_E_QUOTA)
                                                r = log_commitf(bus->log, "Peer :1.%llu is being disconnected as it does not have the resources to receive a signal it subscribed to.", receiver->id);
                                        else
                                                r = log_commitf(bus->log, "Peer :1.%llu is being disconnected as it does not support receiving the file descriptors it subscribed to.", receiver->id);
                                        if (r)
                                                return error_fold(r);
                                } else {
                                        return error_fold(r);
                                }
                        }
                }
        }

        return 0;
}

static int driver_name_owner_changed(Bus *bus, MatchRegistry *matches, const char *name, Peer *old_owner, Peer *new_owner) {
        const char *old_owner_str, *new_owner_str;
        int r;

        c_assert(old_owner || new_owner);
        c_assert(name || !old_owner || !new_owner);

        old_owner_str = old_owner ? address_to_string(&(Address)ADDRESS_INIT_ID(old_owner->id)) : "";
        new_owner_str = new_owner ? address_to_string(&(Address)ADDRESS_INIT_ID(new_owner->id)) : "";
        name = name ?: (old_owner ? old_owner_str : new_owner_str);

        if (old_owner) {
                r = driver_notify_name_lost(old_owner, name);
                if (r)
                        return error_trace(r);
        }

        r = driver_notify_name_owner_changed(bus, matches, name, old_owner_str, new_owner_str);
        if (r)
                return error_trace(r);

        if (new_owner) {
                r = driver_notify_name_acquired(new_owner, name);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

int driver_name_activation_failed(Bus *bus, Activation *activation, uint64_t serial, unsigned int name_error) {
        ActivationRequest *request, *request_safe;
        ActivationMessage *message, *message_safe;
        _c_cleanup_(c_freep) char *error = NULL;
        int r;

        /*
         * If there is no pending activation, or if it is an event for an old
         * activation, we ignore it silently.
         */
        if (!activation->pending || serial != activation->pending)
                return 0;

        r = asprintf(
                &error,
                "Could not activate remote peer '%s': %s",
                activation->name->name,
                controller_name_error_to_human_readable(name_error)
        );
        if (r < 0)
                return error_origin(-errno);

        activation->pending = 0;

        c_list_for_each_entry_safe(request, request_safe, &activation->activation_requests, link) {
                Peer *sender;

                sender = peer_registry_find_peer(&bus->peers, request->sender_id);
                if (sender) {
                        r = driver_send_error(sender, request->serial, "org.freedesktop.DBus.Error.ServiceUnknown", error);
                        if (r)
                                return error_trace(r);
                }

                activation_request_free(request);
        }

        c_list_for_each_entry_safe(message, message_safe, &activation->activation_messages, link) {
                Peer *sender;

                sender = peer_registry_find_peer(&bus->peers, message->message->metadata.sender_id);
                if (sender) {
                        r = driver_send_error(sender, message_read_serial(message->message), "org.freedesktop.DBus.Error.NameHasNoOwner", error);
                        if (r)
                                return error_trace(r);
                }

                activation_message_free(message);
        }

        return 0;
}

static int driver_name_activated(Activation *activation, Peer *receiver) {
        ActivationRequest *request, *request_safe;
        ActivationMessage *message, *message_safe;
        int r;

        if (!activation)
                return 0;

        /* in case the name is dropped again in the future, we should request it again */
        activation->pending = 0;

        c_list_for_each_entry_safe(request, request_safe, &activation->activation_requests, link) {
                Peer *sender;

                sender = peer_registry_find_peer(&receiver->bus->peers, request->sender_id);
                if (sender) {
                        _c_cleanup_(c_dvar_deinit) CDVar var = C_DVAR_INIT;

                        c_dvar_begin_write(&var, (__BYTE_ORDER == __BIG_ENDIAN), driver_type_out_u, 1);
                        c_dvar_write(&var, "(");
                        driver_write_reply_header(&var, sender, request->serial, driver_type_out_u, /* n_fds= */ 0);
                        c_dvar_write(&var, "(u)", DBUS_START_REPLY_SUCCESS);

                        r = driver_send_reply(sender, &var, request->serial);
                        if (r)
                                return error_trace(r);
                }

                activation_request_free(request);
        }

        c_list_for_each_entry_safe(message, message_safe, &activation->activation_messages, link) {
                NameSet sender_names = NAME_SET_INIT_FROM_SNAPSHOT(message->senders_names);
                Peer *sender;

                sender = peer_registry_find_peer(&receiver->bus->peers, message->message->metadata.sender_id);

                r = peer_queue_unicast(message->senders_policy, &sender_names, sender ? &sender->owned_replies : NULL, message->user, message->message->metadata.sender_id, receiver, message->message);
                if (r) {
                        switch (r) {
                        case PEER_E_QUOTA:
                                if (sender)
                                        r = driver_send_error(sender, message_read_serial(message->message),
                                                              "org.freedesktop.DBus.Error.LimitsExceeded",
                                                              driver_error_to_string(DRIVER_E_QUOTA));
                                else
                                        r = 0;

                                break;
                        case PEER_E_EXPECTED_REPLY_EXISTS:
                                if (sender)
                                        r = driver_send_error(sender, message_read_serial(message->message),
                                                              "org.freedesktop.DBus.Error.AccessDenied",
                                                              driver_error_to_string(DRIVER_E_EXPECTED_REPLY_EXISTS));
                                else
                                        r = 0;

                                break;
                        case PEER_E_RECEIVE_DENIED:
                                if (sender)
                                        r = driver_send_error(sender, message_read_serial(message->message),
                                                              "org.freedesktop.DBus.Error.AccessDenied",
                                                              driver_error_to_string(DRIVER_E_RECEIVE_DENIED));
                                else
                                        r = 0;

                                break;
                        case PEER_E_SEND_DENIED:
                                if (sender)
                                        r = driver_send_error(sender, message_read_serial(message->message),
                                                              "org.freedesktop.DBus.Error.AccessDenied",
                                                              driver_error_to_string(DRIVER_E_SEND_DENIED));
                                else
                                        r = 0;

                                break;
                        case PEER_E_UNEXPECTED_FDS:
                                if (sender)
                                        r = driver_send_error(sender, message_read_serial(message->message),
                                                              "org.freedesktop.DBus.Error.Failed",
                                                              driver_error_to_string(DRIVER_E_UNEXPECTED_FDS));
                                else
                                        r = 0;

                                break;
                        }

                        if (r)
                                return error_fold(r);
                }

                activation_message_free(message);
        }

        return 0;
}

static int driver_end_read(CDVar *var) {
        int r;

        /*
         * Messages passed to the driver have already been verified,
         * so we simply fold away any errors here as they would be
         * caused by our own programming errors.
         */
        r = c_dvar_end_read(var);
        if (r)
                return error_fold(r);

        return 0;
}

static int driver_method_hello(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        const char *unique_name;
        int r;

        if (_c_unlikely_(peer_is_registered(peer)))
                return DRIVER_E_PEER_ALREADY_REGISTERED;

        c_dvar_read(in_v, "()");

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        peer_register(peer);
        unique_name = address_to_string(&(Address)ADDRESS_INIT_ID(peer->id));

        c_dvar_write(out_v, "(s)", unique_name);

        r = driver_send_reply(peer, out_v, serial);
        if (r)
                return error_trace(r);

        r = driver_name_owner_changed(peer->bus, &peer->name_owner_changed_matches, NULL, NULL, peer);
        if (r)
                return error_trace(r);

        return 0;
}

static int driver_method_request_name(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        NameChange change = NAME_CHANGE_INIT;
        const char *name;
        uint32_t flags, reply;
        int r;

        c_dvar_read(in_v, "(su)", &name, &flags);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        if (!dbus_validate_name(name, strlen(name)))
                return DRIVER_E_NAME_INVALID;

        r = peer_request_name(peer, name, flags, &change);
        if (!r)
                reply = DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER;
        else if (r == PEER_E_NAME_ALREADY_OWNER)
                reply = DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER;
        else if (r == PEER_E_NAME_IN_QUEUE)
                reply = DBUS_REQUEST_NAME_REPLY_IN_QUEUE;
        else if (r == PEER_E_NAME_EXISTS)
                reply = DBUS_REQUEST_NAME_REPLY_EXISTS;
        else if (r == PEER_E_QUOTA)
                return DRIVER_E_QUOTA;
        else if (r == PEER_E_NAME_RESERVED)
                return DRIVER_E_NAME_RESERVED;
        else if (r == PEER_E_NAME_UNIQUE)
                return DRIVER_E_NAME_UNIQUE;
        else if (r == PEER_E_NAME_REFUSED)
                return DRIVER_E_NAME_REFUSED;
        else
                return error_fold(r);

        c_dvar_write(out_v, "(u)", reply);

        if (change.name) {
                r = driver_name_owner_changed(peer->bus,
                                              &change.name->name_owner_changed_matches,
                                              change.name->name,
                                              c_container_of(change.old_owner, Peer, owned_names),
                                              c_container_of(change.new_owner, Peer, owned_names));
                if (r)
                        return error_trace(r);

                r = driver_name_activated(change.name->activation,
                                          c_container_of(change.new_owner, Peer, owned_names));
                if (r)
                        return error_trace(r);
        }

        name_change_deinit(&change);

        r = driver_send_reply(peer, out_v, serial);
        if (r)
                return error_trace(r);

        return 0;
}

static int driver_method_release_name(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        NameChange change = NAME_CHANGE_INIT;
        const char *name;
        uint32_t reply;
        int r;

        c_dvar_read(in_v, "(s)", &name);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        if (!dbus_validate_name(name, strlen(name)))
                return DRIVER_E_NAME_INVALID;

        r = peer_release_name(peer, name, &change);
        if (!r)
                reply = DBUS_RELEASE_NAME_REPLY_RELEASED;
        else if (r == PEER_E_NAME_NOT_FOUND)
                reply = DBUS_RELEASE_NAME_REPLY_NON_EXISTENT;
        else if (r == PEER_E_NAME_NOT_OWNER)
                reply = DBUS_RELEASE_NAME_REPLY_NOT_OWNER;
        else if (r == PEER_E_NAME_RESERVED)
                return DRIVER_E_NAME_RESERVED;
        else if (r == PEER_E_NAME_UNIQUE)
                return DRIVER_E_NAME_UNIQUE;
        else
                return error_fold(r);

        c_dvar_write(out_v, "(u)", reply);

        if (change.name) {
                r = driver_name_owner_changed(peer->bus,
                                              &change.name->name_owner_changed_matches,
                                              change.name->name,
                                              c_container_of(change.old_owner, Peer, owned_names),
                                              c_container_of(change.new_owner, Peer, owned_names));
                if (r)
                        return error_trace(r);
        }

        name_change_deinit(&change);

        r = driver_send_reply(peer, out_v, serial);
        if (r)
                return error_trace(r);

        return 0;
}

static int driver_method_list_queued_owners(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        NameOwnership *ownership;
        const char *name_str;
        Peer *owner;
        Name *name;
        int r;

        c_dvar_read(in_v, "(s)", &name_str);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        c_dvar_write(out_v, "([");
        if (!strcmp(name_str, "org.freedesktop.DBus")) {
                c_dvar_write(out_v, "s", "org.freedesktop.DBus");
        } else {
                owner = bus_find_peer_by_name(peer->bus, &name, name_str);
                if (!owner)
                        return DRIVER_E_NAME_NOT_FOUND;

                if (name) {
                        c_list_for_each_entry(ownership, &name->ownership_list, name_link)
                                driver_dvar_write_unique_name(out_v, c_container_of(ownership->owner, Peer, owned_names));
                } else {
                        driver_dvar_write_unique_name(out_v, owner);
                }
        }
        c_dvar_write(out_v, "])");

        r = driver_send_reply(peer, out_v, serial);
        if (r)
                return error_trace(r);

        return 0;
}

static int driver_method_list_names(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        Peer *p;
        Name *name;
        int r;

        c_dvar_read(in_v, "()");

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        c_dvar_write(out_v, "([");
        c_dvar_write(out_v, "s", "org.freedesktop.DBus");
        c_rbtree_for_each_entry(p, &peer->bus->peers.peer_tree, registry_node) {
                if (!peer_is_registered(p))
                        continue;

                driver_dvar_write_unique_name(out_v, p);
        }
        c_rbtree_for_each_entry(name, &peer->bus->names.name_tree, registry_node) {
                if (!name_primary(name))
                        continue;

                c_dvar_write(out_v, "s", name->name);
        }
        c_dvar_write(out_v, "])");

        r = driver_send_reply(peer, out_v, serial);
        if (r)
                return error_trace(r);

        return 0;
}

static int driver_method_list_activatable_names(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        Name *name;
        int r;

        c_dvar_read(in_v, "()");

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        c_dvar_write(out_v, "([");
        c_dvar_write(out_v, "s", "org.freedesktop.DBus");
        c_rbtree_for_each_entry(name, &peer->bus->names.name_tree, registry_node) {
                if (!name->activation)
                        continue;

                c_dvar_write(out_v, "s", name->name);
        }
        c_dvar_write(out_v, "])");

        r = driver_send_reply(peer, out_v, serial);
        if (r)
                return error_trace(r);

        return 0;
}

static int driver_method_name_has_owner(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        Peer *connection;
        const char *name;
        int r;

        c_dvar_read(in_v, "(s)", &name);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        if (strcmp(name, "org.freedesktop.DBus") == 0) {
                c_dvar_write(out_v, "(b)", true);
        } else {
                connection = bus_find_peer_by_name(peer->bus, NULL, name);

                c_dvar_write(out_v, "(b)", !!connection);
        }

        r = driver_send_reply(peer, out_v, serial);
        if (r)
                return error_trace(r);

        return 0;
}

static int driver_method_start_service_by_name(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        const char *service;
        Name *name;
        NameOwnership *ownership;
        uint32_t flags;
        int r;

        /* flags are silently ignored */
        c_dvar_read(in_v, "(su)", &service, &flags);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        name = name_registry_find_name(&peer->bus->names, service);
        if (!name || !name->activation)
                return DRIVER_E_NAME_NOT_ACTIVATABLE;

        ownership = name_primary(name);
        if (ownership) {
                c_dvar_write(out_v, "(u)", DBUS_START_REPLY_ALREADY_RUNNING);

                r = driver_send_reply(peer, out_v, serial);
                if (r)
                        return error_trace(r);
        } else {
                r = activation_queue_request(name->activation, peer->user, peer->id, serial);
                if (r) {
                        if (r == ACTIVATION_E_QUOTA)
                                return DRIVER_E_QUOTA;

                        return error_fold(r);
                }
        }

        return 0;
}

static int driver_method_update_activation_environment(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        _c_cleanup_(c_freep) const char **env = NULL;
        const char *key, *value;
        size_t n_env = 0, z_env = 0;
        const char **t;
        int r;

        if (!peer_is_privileged(peer))
                return DRIVER_E_PEER_NOT_PRIVILEGED;

        c_dvar_read(in_v, "([");
        while (c_dvar_more(in_v)) {
                c_dvar_read(in_v, "{ss}", &key, &value);

                if (n_env + 1 >= z_env) {
                        z_env = (z_env * 2) ?: 128;
                        t = realloc(env, z_env * sizeof(*env));
                        if (!t)
                                return error_origin(-ENOMEM);

                        env = t;
                }

                env[n_env++] = key;
                env[n_env++] = value;
        }
        c_dvar_read(in_v, "])");

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        r = broker_update_environment(BROKER(peer->bus), env, n_env / 2);
        if (r)
                return error_fold(r);

        c_dvar_write(out_v, "()");

        r = driver_send_reply(peer, out_v, serial);
        if (r)
                return error_trace(r);

        return 0;
}

static int driver_method_get_name_owner(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        const char *name_str, *owner_str;
        Address addr;
        int r;

        c_dvar_read(in_v, "(s)", &name_str);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        if (!strcmp(name_str, "org.freedesktop.DBus")) {
                addr = (Address)ADDRESS_INIT_NAME("org.freedesktop.DBus");
        } else {
                Peer *owner;

                owner = bus_find_peer_by_name(peer->bus, NULL, name_str);
                if (!owner)
                        return DRIVER_E_NAME_OWNER_NOT_FOUND;

                addr = (Address)ADDRESS_INIT_ID(owner->id);
        }

        owner_str = address_to_string(&addr);

        c_dvar_write(out_v, "(s)", owner_str);

        r = driver_send_reply(peer, out_v, serial);
        if (r)
                return error_trace(r);

        return 0;
}

static int driver_method_get_connection_unix_user(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        Peer *connection;
        const char *name;
        int r;

        c_dvar_read(in_v, "(s)", &name);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        if (!strcmp(name, "org.freedesktop.DBus")) {
                c_dvar_write(out_v, "(u)", peer->bus->user->uid);
        } else {
                connection = bus_find_peer_by_name(peer->bus, NULL, name);
                if (!connection)
                        return DRIVER_E_PEER_NOT_FOUND;

                c_dvar_write(out_v, "(u)", connection->user->uid);
        }

        r = driver_send_reply(peer, out_v, serial);
        if (r)
                return error_trace(r);

        return 0;
}

static int driver_method_get_connection_unix_process_id(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        Peer *connection;
        const char *name;
        int r;

        c_dvar_read(in_v, "(s)", &name);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        if (!strcmp(name, "org.freedesktop.DBus")) {
                c_dvar_write(out_v, "(u)", peer->bus->pid);
        } else {
                connection = bus_find_peer_by_name(peer->bus, NULL, name);
                if (!connection)
                        return DRIVER_E_PEER_NOT_FOUND;

                c_dvar_write(out_v, "(u)", connection->pid);
        }

        r = driver_send_reply(peer, out_v, serial);
        if (r)
                return error_trace(r);

        return 0;
}

static void driver_fetch_credentials(Bus *bus, Peer *peer, DriverCredentials *credp) {
        if (peer) {
                credp->pid = peer->pid;
                credp->pid_fd = peer->pid_fd;
                credp->uid = peer->user->uid;
                credp->gids = peer->gids;
                credp->n_gids = peer->n_gids;
                credp->seclabel = peer->seclabel;
                credp->n_seclabel = peer->n_seclabel;
        } else {
                credp->pid = bus->pid;
                credp->pid_fd = bus->pid_fd;
                credp->uid = bus->user->uid;
                credp->gids = bus->gids;
                credp->n_gids = bus->n_gids;
                credp->seclabel = bus->seclabel;
                credp->n_seclabel = bus->n_seclabel;
        }
}

static void driver_append_credentials(CDVar *v, const DriverCredentials *cred, size_t *fd_iter) {
        c_dvar_write(v, "[");

        if (cred->uid != (uid_t)-1)
                c_dvar_write(v, "{s<u>}", "UnixUserID", c_dvar_type_u, cred->uid);
        if (cred->pid != 0)
                c_dvar_write(v, "{s<u>}", "ProcessID", c_dvar_type_u, cred->pid);

        /*
         * Append all groups of the peer as 'UnixGroupIDs'. This list includes
         * the primary group of the peer. Furthermore, it is sorted and
         * deduplicated, so its behavior is deterministic.
         *
         * Note that this also implies that the list cannot be empty, since the
         * primary group must exist. So if the list is present, it has at least
         * one element.
         */
        if (cred->n_gids > 0) {
                static const CDVarType type_au[] = {
                        C_DVAR_T_INIT(
                                C_DVAR_T_ARRAY(
                                        C_DVAR_T_u
                                )
                        )
                };

                c_dvar_write(v, "{s<[", "UnixGroupIDs", type_au);
                for (size_t i = 0; i < cred->n_gids; ++i)
                        c_dvar_write(v, "u", cred->gids[i]);
                c_dvar_write(v, "]>}");
        }

        if (cred->n_seclabel) {
                /*
                 * The DBus specification says that the security-label is a
                 * byte array of non-0 values. The kernel disagrees.
                 * Unfortunately, the spec does not provide any transformation
                 * rules. Hence, we simply ignore that part of the spec and
                 * insert the label unmodified, followed by a zero byte, which
                 * is mandated by the spec.
                 * Our seclabel-fields always have a trailing zero-byte,
                 * so we can safely copy from it.
                 */
                c_dvar_write(v, "{s<", "LinuxSecurityLabel", (const CDVarType[]){ C_DVAR_T_INIT(C_DVAR_T_ARRAY(C_DVAR_T_y)) });
                driver_write_bytes(v, cred->seclabel, cred->n_seclabel + 1);
                c_dvar_write(v, ">}");
        }

        if (fd_iter && cred->pid_fd >= 0) {
                /* If @fd_iter is set, it must refer to the pidfd. */
                c_dvar_write(v, "{s<h>}", "ProcessFD", c_dvar_type_h, *fd_iter);
                ++*fd_iter;
        }

        c_dvar_write(v, "]");
}

static int driver_method_get_connection_credentials(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        DriverCredentials cred = DRIVER_CREDENTIALS_NULL;
        Peer *connection = NULL;
        const char *name;
        size_t n_fds = 0, n_fds_expected;
        int r;

        c_dvar_read(in_v, "(s)", &name);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        if (strcmp(name, "org.freedesktop.DBus") != 0) {
                connection = bus_find_peer_by_name(peer->bus, NULL, name);
                if (!connection)
                        return DRIVER_E_PEER_NOT_FOUND;
        }

        driver_fetch_credentials(peer->bus, connection, &cred);
        n_fds_expected = (cred.pid_fd >= 0) ? 1 : 0;
        driver_write_reply_header(out_v, peer, serial, driver_type_out_apsv, n_fds_expected);

        c_dvar_write(out_v, "(");
        driver_append_credentials(out_v, &cred, &n_fds);
        c_dvar_write(out_v, ")");

        c_assert(n_fds == n_fds_expected);

        if (n_fds == 1)
                r = driver_send_reply_with_fds(peer, out_v, serial, &cred.pid_fd, n_fds);
        else
                r = driver_send_reply(peer, out_v, serial);
        if (r)
                return error_trace(r);

        return 0;
}

static int driver_method_get_adt_audit_session_data(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        Peer *connection;
        const char *name;
        int r;

        c_dvar_read(in_v, "(s)", &name);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        if (strcmp(name, "org.freedesktop.DBus")) {
                connection = bus_find_peer_by_name(peer->bus, NULL, name);
                if (!connection)
                        return DRIVER_E_PEER_NOT_FOUND;
        }

        /*
         * ADT Audit Session Data is not supported on Linux
         */
        return DRIVER_E_ADT_NOT_SUPPORTED;
}

static int driver_method_get_connection_selinux_security_context(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        const char *name, *seclabel;
        size_t n_seclabel;
        int r;

        c_dvar_read(in_v, "(s)", &name);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        if (!strcmp(name, "org.freedesktop.DBus")) {
                seclabel = peer->bus->seclabel;
                n_seclabel = peer->bus->n_seclabel;
        } else {
                Peer *connection;

                connection = bus_find_peer_by_name(peer->bus, NULL, name);
                if (!connection)
                        return DRIVER_E_PEER_NOT_FOUND;

                seclabel = connection->seclabel;
                n_seclabel = connection->n_seclabel;
        }

        /*
         * Unlike "LinuxSecurityLabel" in GetConnectionCredentials(), this
         * call is specific to SELinux. Hence, we better only return the
         * label if we are running on SELinux.
         */
        if (!bus_selinux_is_enabled())
                return DRIVER_E_SELINUX_NOT_SUPPORTED;

        /*
         * Unlike the "LinuxSecurityLabel", this call does not include a
         * trailing 0-byte in the data blob.
         */
        c_dvar_write(out_v, "(");
        driver_write_bytes(out_v, seclabel, n_seclabel);
        c_dvar_write(out_v, ")");

        r = driver_send_reply(peer, out_v, serial);
        if (r)
                return error_trace(r);

        return 0;
}

static int driver_method_add_match(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        const char *rule_string;
        int r;

        c_dvar_read(in_v, "(s)", &rule_string);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        r = peer_add_match(peer, rule_string);
        if (r) {
                if (r == PEER_E_QUOTA)
                        return DRIVER_E_QUOTA;
                else if (r == PEER_E_MATCH_INVALID)
                        return DRIVER_E_MATCH_INVALID;
                else
                        return error_trace(r);
        }

        c_dvar_write(out_v, "()");

        r = driver_send_reply(peer, out_v, serial);
        if (r)
                return error_trace(r);

        return 0;
}

static int driver_method_remove_match(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        const char *rule_string;
        int r;

        c_dvar_read(in_v, "(s)", &rule_string);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        r = peer_remove_match(peer, rule_string);
        if (r) {
                if (r == PEER_E_MATCH_NOT_FOUND)
                        return DRIVER_E_MATCH_NOT_FOUND;
                else if (r == PEER_E_MATCH_INVALID)
                        return DRIVER_E_MATCH_INVALID;
                else
                        return error_fold(r);
        }

        c_dvar_write(out_v, "()");

        r = driver_send_reply(peer, out_v, serial);
        if (r)
                return error_trace(r);

        return 0;
}

int driver_reload_config_completed(Bus *bus, uint64_t sender_id, uint32_t reply_serial) {
        Peer *sender;
        int r;

        sender = peer_registry_find_peer(&bus->peers, sender_id);
        if (sender) {
                _c_cleanup_(c_dvar_deinit) CDVar var = C_DVAR_INIT;

                c_dvar_begin_write(&var, (__BYTE_ORDER == __BIG_ENDIAN), driver_type_out_unit, 1);
                c_dvar_write(&var, "(");
                driver_write_reply_header(&var, sender, reply_serial, driver_type_out_unit, /* n_fds=*/ 0);
                c_dvar_write(&var, "()");

                r = driver_send_reply(sender, &var, reply_serial);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

int driver_reload_config_invalid(Bus *bus, uint64_t sender_id, uint32_t reply_serial) {
        Peer *sender;
        int r;

        sender = peer_registry_find_peer(&bus->peers, sender_id);
        if (sender) {
                r = driver_send_error(sender, reply_serial, "org.freedesktop.DBus.Error.Failed", "Config invalid. Reload ignored.");
                if (r)
                        return error_trace(r);
        }

        return 0;
}

static int driver_method_reload_config(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        int r;

        /* verify the input argument */
        c_dvar_read(in_v, "()");

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        r = broker_reload_config(BROKER(peer->bus), peer->user, peer->id, serial);
        if (r) {
                if (r == BROKER_E_FORWARD_FAILED)
                        return DRIVER_E_FORWARD_FAILED;

                return error_fold(r);
        }

        return 0;
}

static int driver_method_get_id(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        char buffer[sizeof(peer->bus->guid) * 2 + 1] = {};
        int r;

        /* verify the input argument */
        c_dvar_read(in_v, "()");

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        /* write the output message */
        string_to_hex(peer->bus->guid, sizeof(peer->bus->guid), buffer);
        c_dvar_write(out_v, "(s)", buffer);

        r = driver_send_reply(peer, out_v, serial);
        if (r)
                return error_trace(r);

        return 0;
}

static int driver_method_introspect(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        static const char *introspection_org_freedesktop_DBus =
                "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
                "\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
                "<node>\n"
                "  <interface name=\"org.freedesktop.DBus\">\n"
                "    <method name=\"Hello\">\n"
                "      <arg direction=\"out\" type=\"s\"/>\n"
                "    </method>\n"
                "    <method name=\"RequestName\">\n"
                "      <arg direction=\"in\" type=\"s\"/>\n"
                "      <arg direction=\"in\" type=\"u\"/>\n"
                "      <arg direction=\"out\" type=\"u\"/>\n"
                "    </method>\n"
                "    <method name=\"ReleaseName\">\n"
                "      <arg direction=\"in\" type=\"s\"/>\n"
                "      <arg direction=\"out\" type=\"u\"/>\n"
                "    </method>\n"
                "    <method name=\"StartServiceByName\">\n"
                "      <arg direction=\"in\" type=\"s\"/>\n"
                "      <arg direction=\"in\" type=\"u\"/>\n"
                "      <arg direction=\"out\" type=\"u\"/>\n"
                "    </method>\n"
                "    <method name=\"UpdateActivationEnvironment\">\n"
                "      <arg direction=\"in\" type=\"a{ss}\"/>\n"
                "    </method>\n"
                "    <method name=\"NameHasOwner\">\n"
                "      <arg direction=\"in\" type=\"s\"/>\n"
                "      <arg direction=\"out\" type=\"b\"/>\n"
                "    </method>\n"
                "    <method name=\"ListNames\">\n"
                "      <arg direction=\"out\" type=\"as\"/>\n"
                "    </method>\n"
                "    <method name=\"ListActivatableNames\">\n"
                "      <arg direction=\"out\" type=\"as\"/>\n"
                "    </method>\n"
                "    <method name=\"AddMatch\">\n"
                "      <arg direction=\"in\" type=\"s\"/>\n"
                "    </method>\n"
                "    <method name=\"RemoveMatch\">\n"
                "      <arg direction=\"in\" type=\"s\"/>\n"
                "    </method>\n"
                "    <method name=\"GetNameOwner\">\n"
                "      <arg direction=\"in\" type=\"s\"/>\n"
                "      <arg direction=\"out\" type=\"s\"/>\n"
                "    </method>\n"
                "    <method name=\"ListQueuedOwners\">\n"
                "      <arg direction=\"in\" type=\"s\"/>\n"
                "      <arg direction=\"out\" type=\"as\"/>\n"
                "    </method>\n"
                "    <method name=\"GetConnectionUnixUser\">\n"
                "      <arg direction=\"in\" type=\"s\"/>\n"
                "      <arg direction=\"out\" type=\"u\"/>\n"
                "    </method>\n"
                "    <method name=\"GetConnectionUnixProcessID\">\n"
                "      <arg direction=\"in\" type=\"s\"/>\n"
                "      <arg direction=\"out\" type=\"u\"/>\n"
                "    </method>\n"
                "    <method name=\"GetAdtAuditSessionData\">\n"
                "      <arg direction=\"in\" type=\"s\"/>\n"
                "      <arg direction=\"out\" type=\"ay\"/>\n"
                "    </method>\n"
                "    <method name=\"GetConnectionSELinuxSecurityContext\">\n"
                "      <arg direction=\"in\" type=\"s\"/>\n"
                "      <arg direction=\"out\" type=\"ay\"/>\n"
                "    </method>\n"
                "    <method name=\"ReloadConfig\">\n"
                "    </method>\n"
                "    <method name=\"GetId\">\n"
                "      <arg direction=\"out\" type=\"s\"/>\n"
                "    </method>\n"
                "    <method name=\"GetConnectionCredentials\">\n"
                "      <arg direction=\"in\" type=\"s\"/>\n"
                "      <arg direction=\"out\" type=\"a{sv}\"/>\n"
                "    </method>\n"
                "    <property name=\"Features\" type=\"as\" access=\"read\">\n"
                "      <annotation name=\"org.freedesktop.DBus.Property.EmitsChangedSignal\" value=\"const\"/>\n"
                "    </property>\n"
                "    <property name=\"Interfaces\" type=\"as\" access=\"read\">\n"
                "      <annotation name=\"org.freedesktop.DBus.Property.EmitsChangedSignal\" value=\"const\"/>\n"
                "    </property>\n"
                "    <signal name=\"NameOwnerChanged\">\n"
                "      <arg type=\"s\"/>\n"
                "      <arg type=\"s\"/>\n"
                "      <arg type=\"s\"/>\n"
                "    </signal>\n"
                "    <signal name=\"NameLost\">\n"
                "      <arg type=\"s\"/>\n"
                "    </signal>\n"
                "    <signal name=\"NameAcquired\">\n"
                "      <arg type=\"s\"/>\n"
                "    </signal>\n"
                "  </interface>\n"
                "  <interface name=\"org.freedesktop.DBus.Properties\">\n"
                "    <method name=\"Get\">\n"
                "      <arg direction=\"in\" type=\"s\"/>\n"
                "      <arg direction=\"in\" type=\"s\"/>\n"
                "      <arg direction=\"out\" type=\"v\"/>\n"
                "    </method>\n"
                "    <method name=\"GetAll\">\n"
                "      <arg direction=\"in\" type=\"s\"/>\n"
                "      <arg direction=\"out\" type=\"a{sv}\"/>\n"
                "    </method>\n"
                "    <method name=\"Set\">\n"
                "      <arg direction=\"in\" type=\"s\"/>\n"
                "      <arg direction=\"in\" type=\"s\"/>\n"
                "      <arg direction=\"in\" type=\"v\"/>\n"
                "    </method>\n"
                "    <signal name=\"PropertiesChanged\">\n"
                "      <arg type=\"s\" name=\"interface_name\"/>\n"
                "      <arg type=\"a{sv}\" name=\"changed_properties\"/>\n"
                "      <arg type=\"as\" name=\"invalidated_properties\"/>\n"
                "    </signal>\n"
                "  </interface>\n"
                "  <interface name=\"org.freedesktop.DBus.Introspectable\">\n"
                "    <method name=\"Introspect\">\n"
                "      <arg direction=\"out\" type=\"s\"/>\n"
                "    </method>\n"
                "  </interface>\n"
                "  <interface name=\"org.freedesktop.DBus.Monitoring\">\n"
                "    <method name=\"BecomeMonitor\">\n"
                "      <arg direction=\"in\" type=\"as\"/>\n"
                "      <arg direction=\"in\" type=\"u\"/>\n"
                "    </method>\n"
                "  </interface>\n"
                "  <interface name=\"org.freedesktop.DBus.Peer\">\n"
                "    <method name=\"GetMachineId\">\n"
                "      <arg direction=\"out\" type=\"s\"/>\n"
                "    </method>\n"
                "    <method name=\"Ping\">\n"
                "    </method>\n"
                "  </interface>\n"
                "  <interface name=\"org.freedesktop.DBus.Debug.Stats\">\n"
                "    <method name=\"GetStats\">\n"
                "      <arg direction=\"out\" type=\"a{sv}\"/>\n"
                "    </method>\n"
                "    <method name=\"GetConnectionStats\">\n"
                "      <arg direction=\"in\" type=\"s\"/>\n"
                "      <arg direction=\"out\" type=\"a{sv}\"/>\n"
                "    </method>\n"
                "    <method name=\"GetAllMatchRules\">\n"
                "      <arg direction=\"out\" type=\"a{sas}\"/>\n"
                "    </method>\n"
                "  </interface>\n"
                "</node>\n";
        static const char *introspection_org_freedesktop =
                "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
                "\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
                "<node>\n"
                "  <node name=\"DBus\"/>\n"
                "</node>\n";
        static const char *introspection_org =
                "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
                "\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
                "<node>\n"
                "  <node name=\"freedesktop/DBus\"/>\n"
                "</node>\n";
        static const char *introspection =
                "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
                "\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
                "<node>\n"
                "  <node name=\"org/freedesktop/DBus\"/>\n"
                "</node>\n";
        static const char *introspection_any =
                "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
                "\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
                "<node>\n"
                "</node>\n";
        int r;

        c_dvar_read(in_v, "()");

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        /*
         * We return the same intropsection data for the canonical path as the reference
         * implementation does, and all methods behave the same. However, we only expose
         * simplified intropsection data for all other paths, as if all interfaces were
         * only implemented on the canonical path. The only reason they are implemented
         * on arbitrary paths is for backwards compatibility.
         */
        if (!strcmp(path, "/org/freedesktop/DBus"))
                c_dvar_write(out_v, "(s)", introspection_org_freedesktop_DBus);
        else if (!strcmp(path, "/org/freedesktop"))
                c_dvar_write(out_v, "(s)", introspection_org_freedesktop);
        else if (!strcmp(path, "/org"))
                c_dvar_write(out_v, "(s)", introspection_org);
        else if (!strcmp(path, "/"))
                c_dvar_write(out_v, "(s)", introspection);
        else
                c_dvar_write(out_v, "(s)", introspection_any);

        r = driver_send_reply(peer, out_v, serial);
        if (r)
                return error_trace(r);

        return 0;
}

static int driver_method_become_monitor(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        MatchOwner owned_matches;
        const char *match_string;
        uint32_t flags;
        int r;

        if (!peer_is_privileged(peer))
                return DRIVER_E_PEER_NOT_PRIVILEGED;

        r = bus_apparmor_check_eavesdrop(peer->policy->apparmor, peer->policy->seclabel);
        if (r == BUS_APPARMOR_E_DENIED)
                return DRIVER_E_PEER_NOT_PRIVILEGED;
        else if (r)
                return error_fold(r);

        /* first create all the match objects before modifying the peer */
        match_owner_init(&owned_matches);

        c_dvar_read(in_v, "([");
        do {
                /*
                 * dbus-daemon treats an empty match-array as if an array with
                 * a single empty string was passed. This effectively becomes a
                 * wildcard match, thus the monitor receives everything.
                 */
                if (c_dvar_more(in_v))
                        c_dvar_read(in_v, "s", &match_string);
                else
                        match_string = "";

                /*
                 * We pass `true` for `allow_eavesdrop` for compatibility
                 * reasons. We do not support eavesdropping, but `dbus-monitor`
                 * seems to prepend `eavesdrop=true` unconditionally to all
                 * match-rules it installs. However, there is no reason to do
                 * that with `BecomeMonitor()`, because this is already
                 * implicitly set.
                 * Regardless, we must allow these rules to specify `eavesdrop`
                 * filters, even though we will just silently ignore them.
                 */
                r = match_owner_ref_rule(&owned_matches, NULL, peer->user, match_string, true);
                if (r) {
                        r = (r == MATCH_E_INVALID) ? DRIVER_E_MATCH_INVALID : error_fold(r);
                        goto error;
                }
        } while (c_dvar_more(in_v));
        c_dvar_read(in_v, "]u)", &flags);

        /* verify the input arguments*/
        r = driver_end_read(in_v);
        if (r) {
                r = error_trace(r);
                goto error;
        }

        if (flags) {
                r = DRIVER_E_UNEXPECTED_FLAGS;
                goto error;
        }

        /* write the output message */
        c_dvar_write(out_v, "()");

        r = driver_send_reply(peer, out_v, serial);
        if (r) {
                r = error_trace(r);
                goto error;
        }

        /* only fatal errors from here on */

        r = driver_goodbye(peer, false);
        if (r) {
                r = error_trace(r);
                goto error;
        }

        r = peer_become_monitor(peer, &owned_matches);
        if (r) {
                r = error_fold(r);
                goto error;
        }

        match_owner_deinit(&owned_matches);

        return 0;

error:
        while (owned_matches.rule_tree.root)
                match_rule_user_unref(c_container_of(owned_matches.rule_tree.root, MatchRule, owner_node));

        return r;
}

static int driver_method_ping(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        int r;

        c_dvar_read(in_v, "()");

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        c_dvar_write(out_v, "()");

        r = driver_send_reply(peer, out_v, serial);
        if (r)
                return error_trace(r);

        return 0;
}

static int driver_method_get_machine_id(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        int r;

        /* verify the input argument */
        c_dvar_read(in_v, "()");

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        /* write the output message */
        c_dvar_write(out_v, "(s)", peer->bus->machine_id);

        r = driver_send_reply(peer, out_v, serial);
        if (r)
                return error_trace(r);

        return 0;
}

static void driver_append_property_features(CDVar *v) {
        static const CDVarType variant_type[] = {
                C_DVAR_T_INIT(
                        C_DVAR_T_ARRAY(
                                C_DVAR_T_s
                        )
                )
        };

        c_dvar_write(v, "<[", variant_type);
        if (bus_selinux_is_enabled())
                c_dvar_write(v, "s", "SELinux");
        c_dvar_write(v, "]>");
}

static void driver_append_property_interfaces(CDVar *v) {
        static const CDVarType variant_type[] = {
                C_DVAR_T_INIT(
                        C_DVAR_T_ARRAY(
                                C_DVAR_T_s
                        )
                )
        };

        c_dvar_write(v, "<[s]>", variant_type, "org.freedesktop.DBus.Monitoring");
}

static int driver_method_get(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        const char *interface, *property;
        int r;

        /* verify the input argument */
        c_dvar_read(in_v, "(ss)", &interface, &property);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        /* only one interface is supported */
        if (strcmp(interface, "org.freedesktop.DBus") != 0)
                return DRIVER_E_UNEXPECTED_INTERFACE;

        c_dvar_write(out_v, "(");
        /* append the right property */
        if (strcmp(property, "Features") == 0)
                driver_append_property_features(out_v);
        else if (strcmp(property, "Interfaces") == 0)
                driver_append_property_interfaces(out_v);
        else
                return DRIVER_E_UNEXPECTED_PROPERTY;
        c_dvar_write(out_v, ")");

        r = driver_send_reply(peer, out_v, serial);
        if (r)
                return error_trace(r);

        return 0;
}

static int driver_method_set(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        const char *interface, *property;
        int r;

        c_dvar_read(in_v, "(ss", &interface, &property);
        c_dvar_skip(in_v, "<*>)", NULL);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        /* only one interface is supported */
        if (strcmp(interface, "org.freedesktop.DBus") != 0)
                return DRIVER_E_UNEXPECTED_INTERFACE;

        if (strcmp(property, "Features") != 0 && strcmp(property, "Interfaces") != 0)
                return DRIVER_E_UNEXPECTED_PROPERTY;

        return DRIVER_E_READONLY_PROPERTY;
}

static int driver_method_get_all(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        const char *interface;
        int r;

        /* verify the input argument */
        c_dvar_read(in_v, "(s)", &interface);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        /* only one interfaces is supported */
        if (strcmp(interface, "org.freedesktop.DBus") != 0)
                return DRIVER_E_UNEXPECTED_INTERFACE;

        /* append both supported properties */
        c_dvar_write(out_v, "([{s", "Features");
        driver_append_property_features(out_v);
        c_dvar_write(out_v, "}{s", "Interfaces");
        driver_append_property_interfaces(out_v);
        c_dvar_write(out_v, "}])");

        r = driver_send_reply(peer, out_v, serial);
        if (r)
                return error_trace(r);

        return 0;
}

static void driver_append_peer_accounting_stats(CDVar *v, Peer *peer) {
        unsigned int n_name_objects, n_match_bytes, n_matches, n_reply_objects,
                     n_conn_in_bytes, n_conn_in_fds, n_conn_out_bytes, n_conn_out_fds,
                     n_activation_bytes, n_activation_fds;

        name_owner_get_stats(&peer->owned_names, &n_name_objects);
        match_owner_get_stats(&peer->owned_matches, &n_match_bytes, &n_matches);
        reply_owner_get_stats(&peer->owned_replies, &n_reply_objects);
        connection_get_stats(&peer->connection, &n_conn_in_bytes, &n_conn_in_fds,
                             &n_conn_out_bytes, &n_conn_out_fds);
        name_registry_get_activation_stats_for(&peer->bus->names, peer->id,
                                               &n_activation_bytes, &n_activation_fds);

        c_dvar_write(v, "["
                        "{su}"
                        "{su}"
                        "{su}"
                        "{su}"
                        "{su}"
                        "{su}"
                        "{su}"
                        "{su}"
                        "{su}"
                        "{su}"
                        "]",
                        "NameObjects", n_name_objects,
                        "MatchBytes", n_match_bytes,
                        "Matches", n_matches,
                        "ReplyObjects", n_reply_objects,
                        "IncomingBytes", n_conn_in_bytes,
                        "IncomingFds", n_conn_in_fds,
                        "OutgoingBytes", n_conn_out_bytes,
                        "OutgoingFds", n_conn_out_fds,
                        "ActivationRequestBytes", n_activation_bytes,
                        "ActivationRequestFds", n_activation_fds);
}

static void driver_append_peer_accounting(CDVar *v, Bus *bus) {
        static const CDVarType dump_type[] = {
                C_DVAR_T_INIT(
                        C_DVAR_T_ARRAY(
                                C_DVAR_T_TUPLE3(
                                        C_DVAR_T_s,
                                        C_DVAR_T_ARRAY(
                                                C_DVAR_T_PAIR(
                                                        C_DVAR_T_s,
                                                        C_DVAR_T_v
                                                )
                                        ),
                                        C_DVAR_T_ARRAY(
                                                C_DVAR_T_PAIR(
                                                        C_DVAR_T_s,
                                                        C_DVAR_T_u
                                                )
                                        )
                                )
                        )
                )
        };
        Peer *p;

        c_dvar_write(v, "<[", dump_type);

        c_rbtree_for_each_entry(p, &bus->peers.peer_tree, registry_node) {
                DriverCredentials cred = DRIVER_CREDENTIALS_NULL;

                if (!peer_is_registered(p))
                        continue;

                c_dvar_write(v, "(");
                driver_dvar_write_unique_name(v, p);
                driver_fetch_credentials(bus, p, &cred);
                driver_append_credentials(v, &cred, NULL);
                driver_append_peer_accounting_stats(v, p);
                c_dvar_write(v, ")");
        }

        c_dvar_write(v, "]>");
}

static void driver_append_user_accounting(CDVar *v, Bus *bus) {
        static const CDVarType dump_type[] = {
                C_DVAR_T_INIT(
                        C_DVAR_T_ARRAY(
                                C_DVAR_T_TUPLE3(
                                        C_DVAR_T_u,
                                        C_DVAR_T_ARRAY(
                                                C_DVAR_T_TUPLE3(
                                                        C_DVAR_T_s,
                                                        C_DVAR_T_u,
                                                        C_DVAR_T_u
                                                )
                                        ),
                                        C_DVAR_T_ARRAY(
                                                C_DVAR_T_PAIR(
                                                        C_DVAR_T_u,
                                                        C_DVAR_T_ARRAY(
                                                                C_DVAR_T_PAIR(
                                                                        C_DVAR_T_s,
                                                                        C_DVAR_T_u
                                                                )
                                                        )
                                                )
                                        )
                                )
                        )
                )
        };
        UserUsage *usage;
        User *user;

        c_assert(_USER_SLOT_N == bus->users.n_slots);

        c_dvar_write(v, "<[", dump_type);

        c_rbtree_for_each_entry(user, &bus->users.user_tree, registry_node) {
                c_dvar_write(v, "(u["
                                "(suu)"
                                "(suu)"
                                "(suu)"
                                "(suu)"
                                "][",
                                user->uid,
                                "Bytes", user->slots[0].n, user->slots[0].max,
                                "Fds", user->slots[1].n, user->slots[1].max,
                                "Matches", user->slots[2].n, user->slots[2].max,
                                "Objects", user->slots[3].n, user->slots[3].max);
                c_rbtree_for_each_entry(usage, &user->usage_tree, user_node) {
                        c_dvar_write(v, "{u["
                                        "{su}"
                                        "{su}"
                                        "{su}"
                                        "{su}"
                                        "]}",
                                        usage->uid,
                                        "Bytes", usage->slots[0],
                                        "Fds", usage->slots[1],
                                        "Matches", usage->slots[2],
                                        "Objects", usage->slots[3]);
                }
                c_dvar_write(v, "])");
        }

        c_dvar_write(v, "]>");
}

static int driver_method_get_stats(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        int r;

        c_dvar_read(in_v, "()");

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        /*
         * Append all supported statistics. So far, none of the dbus-daemon
         * statistics are appended, since they are very specific to how the bus
         * is implemented. We do, however, add our own (namespaced) statistics.
         */
        c_dvar_write(out_v, "([{s", "org.bus1.DBus.Debug.Stats.PeerAccounting");
        driver_append_peer_accounting(out_v, peer->bus);
        c_dvar_write(out_v, "}{s", "org.bus1.DBus.Debug.Stats.UserAccounting");
        driver_append_user_accounting(out_v, peer->bus);
        c_dvar_write(out_v, "}])");

        r = driver_send_reply(peer, out_v, serial);
        if (r)
                return error_trace(r);

        return 0;
}

static int driver_method_get_connection_stats(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        return DRIVER_E_UNIMPLEMENTED;
}

static int driver_method_get_all_match_rules(Peer *peer, const char *path, CDVar *in_v, uint32_t serial, CDVar *out_v) {
        return DRIVER_E_UNIMPLEMENTED;
}

static int driver_handle_method(const DriverMethod *method, Peer *peer, const char *path, uint32_t serial, const char *signature_in, Message *message_in) {
        _c_cleanup_(c_dvar_deinit) CDVar var_in = C_DVAR_INIT, var_out = C_DVAR_INIT;
        int r;

        /*
         * Verify the path and the input signature and prepare the
         * input & output variants for input parsing and output marshaling.
         */

        if (method->path && strcmp(path, method->path) != 0)
                return DRIVER_E_UNEXPECTED_PATH;

        r = driver_dvar_verify_signature_in(method->in, signature_in);
        if (r)
                return error_trace(r);

        c_dvar_begin_read(&var_in, message_in->big_endian, method->in, 1, message_in->body, message_in->n_body);
        c_dvar_begin_write(&var_out, (__BYTE_ORDER == __BIG_ENDIAN), method->out, 1);

        /*
         * Note that some driver-methods are responsible for writing the
         * reply-header, given they might need to send file descriptors, which
         * needs a specific count field to be added.
         * They all are responsible for calling c_dvar_end_read(var_in), to
         * assert that all read data was correct.
         * We already verify that the payload matches the signature, and that
         * the signature matches the method call, so this is just to catch
         * programming errors in the broker.
         */

        c_dvar_write(&var_out, "(");
        if (!method->writes_own_header)
                driver_write_reply_header(&var_out, peer, serial, method->out, /* n_fds= */ 0);

        r = method->fn(peer, path, &var_in, serial, &var_out);
        if (r)
                return error_trace(r);

        return 0;
}

static const DriverMethod driver_methods[] = {
        { "Hello",                                      false,  NULL,                           driver_method_hello,                                            c_dvar_type_unit,       driver_type_out_s,     false },
        { "AddMatch",                                   true,   NULL,                           driver_method_add_match,                                        driver_type_in_s,       driver_type_out_unit,  false },
        { "RemoveMatch",                                true,   NULL,                           driver_method_remove_match,                                     driver_type_in_s,       driver_type_out_unit,  false },
        { "RequestName",                                true,   NULL,                           driver_method_request_name,                                     driver_type_in_su,      driver_type_out_u,     false },
        { "ReleaseName",                                true,   NULL,                           driver_method_release_name,                                     driver_type_in_s,       driver_type_out_u,     false },
        { "GetConnectionCredentials",                   true,   NULL,                           driver_method_get_connection_credentials,                       driver_type_in_s,       driver_type_out_apsv,  true  },
        { "GetConnectionUnixUser",                      true,   NULL,                           driver_method_get_connection_unix_user,                         driver_type_in_s,       driver_type_out_u,     false },
        { "GetConnectionUnixProcessID",                 true,   NULL,                           driver_method_get_connection_unix_process_id,                   driver_type_in_s,       driver_type_out_u,     false },
        { "GetAdtAuditSessionData",                     true,   NULL,                           driver_method_get_adt_audit_session_data,                       driver_type_in_s,       driver_type_out_ay,    false },
        { "GetConnectionSELinuxSecurityContext",        true,   NULL,                           driver_method_get_connection_selinux_security_context,          driver_type_in_s,       driver_type_out_ay,    false },
        { "StartServiceByName",                         true,   NULL,                           driver_method_start_service_by_name,                            driver_type_in_su,      driver_type_out_u,     false },
        { "ListQueuedOwners",                           true,   NULL,                           driver_method_list_queued_owners,                               driver_type_in_s,       driver_type_out_as,    false },
        { "ListNames",                                  true,   NULL,                           driver_method_list_names,                                       c_dvar_type_unit,       driver_type_out_as,    false },
        { "ListActivatableNames",                       true,   NULL,                           driver_method_list_activatable_names,                           c_dvar_type_unit,       driver_type_out_as,    false },
        { "NameHasOwner",                               true,   NULL,                           driver_method_name_has_owner,                                   driver_type_in_s,       driver_type_out_b,     false },
        { "UpdateActivationEnvironment",                true,   "/org/freedesktop/DBus",        driver_method_update_activation_environment,                    driver_type_in_apss,    driver_type_out_unit,  false },
        { "GetNameOwner",                               true,   NULL,                           driver_method_get_name_owner,                                   driver_type_in_s,       driver_type_out_s,     false },
        { "ReloadConfig",                               true,   NULL,                           driver_method_reload_config,                                    c_dvar_type_unit,       driver_type_out_unit,  false },
        { "GetId",                                      true,   NULL,                           driver_method_get_id,                                           c_dvar_type_unit,       driver_type_out_s,     false },
        { },
};

static const DriverMethod monitoring_methods[] = {
        { "BecomeMonitor",                              true,   "/org/freedesktop/DBus",        driver_method_become_monitor,                                   driver_type_in_asu,     driver_type_out_unit,  false },
        { },
};

static const DriverMethod introspectable_methods[] = {
        { "Introspect",                                 true,   NULL,                           driver_method_introspect,                                       c_dvar_type_unit,       driver_type_out_s,     false },
        { },
};

static const DriverMethod peer_methods[] = {
        { "Ping",                                       true,   NULL,                           driver_method_ping,                                             c_dvar_type_unit,       driver_type_out_unit,  false },
        { "GetMachineId",                               true,   NULL,                           driver_method_get_machine_id,                                   c_dvar_type_unit,       driver_type_out_s,     false },
        { },
};

static const DriverMethod properties_methods[] = {
        { "Get",                                        true,   "/org/freedesktop/DBus",        driver_method_get,                                              driver_type_in_ss,      driver_type_out_v,     false },
        { "Set",                                        true,   "/org/freedesktop/DBus",        driver_method_set,                                              driver_type_in_ssv,     driver_type_out_unit,  false },
        { "GetAll",                                     true,   "/org/freedesktop/DBus",        driver_method_get_all,                                          driver_type_in_s,       driver_type_out_apsv,  false },
        { },
};

static const DriverMethod debug_stats_methods[] = {
        { "GetStats",                                   true,   "/org/freedesktop/DBus",        driver_method_get_stats,                                        c_dvar_type_unit,       driver_type_out_apsv,  false },
        { "GetConnectionStats",                         true,   "/org/freedesktop/DBus",        driver_method_get_connection_stats,                             driver_type_in_s,       driver_type_out_apsv,  false },
        { "GetAllMatchRules",                           true,   "/org/freedesktop/DBus",        driver_method_get_all_match_rules,                              c_dvar_type_unit,       driver_type_out_apsas, false },
        { },
};

static int driver_dispatch_method(Peer *peer, const DriverMethod *methods, uint32_t serial, const char *method, const char *path, const char *signature, Message *message) {
        for (size_t i = 0; methods[i].name; i++) {
                if (strcmp(methods[i].name, method) != 0)
                        continue;

                if (_c_likely_(peer_is_registered(peer)) || !methods[i].needs_registration)
                        return driver_handle_method(methods + i, peer, path, serial, signature, message);
        }

        return DRIVER_E_UNEXPECTED_METHOD;
}

static int driver_map_denied_error(int err) {
        switch (err) {
        case POLICY_E_SELINUX_ACCESS_DENIED:
                return BUS_LOG_POLICY_TYPE_SELINUX;
        case POLICY_E_APPARMOR_ACCESS_DENIED:
                return BUS_LOG_POLICY_TYPE_APPARMOR;
        default:
                return BUS_LOG_POLICY_TYPE_INTERNAL;
        }
}

static int driver_dispatch_interface(Peer *peer, uint32_t serial, const char *interface, const char *member, const char *path, const char *signature, Message *message) {
        static const DriverInterface interfaces[] = {
                { "org.freedesktop.DBus", driver_methods },
                { "org.freedesktop.DBus.Monitoring", monitoring_methods },
                { "org.freedesktop.DBus.Introspectable", introspectable_methods },
                { "org.freedesktop.DBus.Peer", peer_methods },
                { "org.freedesktop.DBus.Properties", properties_methods },
                { "org.freedesktop.DBus.Debug.Stats", debug_stats_methods },
        };
        int r;

        if (message->header->type != DBUS_MESSAGE_TYPE_METHOD_CALL)
                /* ignore */
                return 0;

        r = policy_snapshot_check_send(peer->policy, NULL, NULL, 0, interface, member, path, message->header->type, false, message->metadata.fields.unix_fds);
        if (r) {
                if (r == POLICY_E_ACCESS_DENIED ||
                    r == POLICY_E_SELINUX_ACCESS_DENIED ||
                    r == POLICY_E_APPARMOR_ACCESS_DENIED) {
                        NameSet names = NAME_SET_INIT_FROM_OWNER(&peer->owned_names);

                        log_append_here(peer->bus->log, LOG_WARNING, 0, NULL);
                        bus_log_append_policy_send(peer->bus,
                                                   driver_map_denied_error(r),
                                                   peer->id, ADDRESS_ID_INVALID, &names, NULL, peer->policy->seclabel, peer->bus->seclabel, message);
                        r = log_commitf(peer->bus->log, "A security policy denied :1.%llu to send method call %s:%s.%s to org.freedesktop.DBus.",
                                        peer->id, path, interface, member);
                        if (r)
                                return error_fold(r);

                        return DRIVER_E_SEND_DENIED;
                }

                return error_fold(r);
        }

        if (interface) {
                for (size_t i = 0; i < C_ARRAY_SIZE(interfaces); ++i) {
                        if (strcmp(interfaces[i].name, interface) != 0)
                                continue;

                        return error_trace(driver_dispatch_method(peer, interfaces[i].methods, serial, member, path, signature, message));
                }

                return DRIVER_E_UNEXPECTED_INTERFACE;
        } else {
                for (size_t i = 0; i < C_ARRAY_SIZE(interfaces); ++i) {
                        r = driver_dispatch_method(peer, interfaces[i].methods, serial, member, path, signature, message);
                        if (r == DRIVER_E_UNEXPECTED_METHOD)
                                continue;

                        return error_trace(r);
                }

                return DRIVER_E_UNEXPECTED_METHOD;
        }
}

int driver_goodbye(Peer *peer, bool silent) {
        ReplySlot *reply, *reply_safe;
        NameOwnership *ownership, *ownership_safe;
        int r;

        peer_flush_matches(peer);

        c_list_for_each_entry_safe(reply, reply_safe, &peer->owned_replies.reply_list, owner_link)
                reply_slot_free(reply);

        match_registry_flush(&peer->sender_matches);

        c_rbtree_for_each_entry_safe_postorder_unlink(ownership, ownership_safe, &peer->owned_names.ownership_tree, owner_node) {
                NameChange change;

                name_change_init(&change);
                peer_release_name_ownership(peer, ownership, &change);
                if (!silent && change.name)
                        r = driver_name_owner_changed(peer->bus,
                                                      &change.name->name_owner_changed_matches,
                                                      change.name->name,
                                                      c_container_of(change.old_owner, Peer, owned_names),
                                                      c_container_of(change.new_owner, Peer, owned_names));
                else
                        r = 0;
                name_change_deinit(&change);
                if (r)
                        return error_fold(r);
        }

        if (peer_is_registered(peer)) {
                if (!silent) {
                        r = driver_name_owner_changed(peer->bus, &peer->name_owner_changed_matches, NULL, peer, NULL);
                        if (r)
                                return error_trace(r);
                }
                peer_unregister(peer);
        } else if (peer_is_monitor(peer)) {
                peer_stop_monitor(peer);
        }

        match_registry_flush(&peer->name_owner_changed_matches);

        c_rbtree_for_each_entry_safe_postorder_unlink(reply, reply_safe, &peer->replies.reply_tree, registry_node) {
                Peer *sender = c_container_of(reply->owner, Peer, owned_replies);

                if (!silent) {
                        r = driver_send_error(sender, reply->serial, "org.freedesktop.DBus.Error.NoReply", "Remote peer disconnected");
                        if (r)
                                return error_trace(r);
                }

                reply_slot_free(reply);
        }

        return 0;
}

static int driver_forward_unicast(Peer *sender, const char *destination, Message *message) {
        NameSet sender_names = NAME_SET_INIT_FROM_OWNER(&sender->owned_names);
        Peer *receiver;
        Name *name;
        int r;

        receiver = bus_find_peer_by_name(sender->bus, &name, destination);
        if (!receiver) {
                if (message->metadata.header.flags & DBUS_HEADER_FLAG_NO_AUTO_START)
                        return DRIVER_E_DESTINATION_NOT_FOUND;
                if (!name || !name->activation)
                        return DRIVER_E_NAME_NOT_ACTIVATABLE;

                r = activation_queue_message(name->activation, sender->user, &sender->owned_names, sender->policy, message);
                if (r) {
                        if (r == ACTIVATION_E_QUOTA)
                                return DRIVER_E_QUOTA;

                        return error_fold(r);
                }

                return 0;
        }

        r = peer_queue_unicast(sender->policy, &sender_names, &sender->owned_replies, sender->user, sender->id, receiver, message);
        if (r) {
                if (r == PEER_E_EXPECTED_REPLY_EXISTS)
                        return DRIVER_E_EXPECTED_REPLY_EXISTS;
                else if (r == PEER_E_QUOTA)
                        return DRIVER_E_QUOTA;
                else if (r == PEER_E_SEND_DENIED)
                        return DRIVER_E_SEND_DENIED;
                else if (r == PEER_E_RECEIVE_DENIED)
                        return DRIVER_E_RECEIVE_DENIED;
                else if (r == PEER_E_UNEXPECTED_FDS)
                        return DRIVER_E_UNEXPECTED_FDS;
                else
                        return error_fold(r);
        }

        return 0;
}

static int driver_forward_broadcast(Peer *sender, Message *message) {
        _c_cleanup_(c_list_flush) CList destinations = C_LIST_INIT(destinations);
        NameSet sender_names = NAME_SET_INIT_FROM_OWNER(&sender->owned_names);
        MatchOwner *match_owner;
        int r;

        bus_get_broadcast_destinations(sender->bus, &destinations, &sender->sender_matches, sender, &message->metadata);

        while ((match_owner = c_list_first_entry(&destinations, MatchOwner, destinations_link))) {
                Peer *receiver = c_container_of(match_owner, Peer, owned_matches);
                NameSet receiver_names = NAME_SET_INIT_FROM_OWNER(&receiver->owned_names);

                c_list_unlink(&match_owner->destinations_link);

                r = policy_snapshot_check_send(sender->policy,
                                               receiver->seclabel,
                                               &receiver_names,
                                               receiver->id,
                                               message->metadata.fields.interface,
                                               message->metadata.fields.member,
                                               message->metadata.fields.path,
                                               message->metadata.header.type,
                                               true,
                                               message->metadata.fields.unix_fds);
                if (r) {
                        if (r == POLICY_E_ACCESS_DENIED ||
                            r == POLICY_E_SELINUX_ACCESS_DENIED ||
                            r == POLICY_E_APPARMOR_ACCESS_DENIED)
                                continue;

                        return error_fold(r);
                }

                r = policy_snapshot_check_receive(receiver->policy,
                                                  sender->seclabel,
                                                  &sender_names,
                                                  sender->id,
                                                  message->metadata.fields.interface,
                                                  message->metadata.fields.member,
                                                  message->metadata.fields.path,
                                                  message->metadata.header.type,
                                                  true,
                                                  message->metadata.fields.unix_fds);
                if (r) {
                        if (r == POLICY_E_ACCESS_DENIED ||
                            r == POLICY_E_SELINUX_ACCESS_DENIED ||
                            r == POLICY_E_APPARMOR_ACCESS_DENIED)
                                continue;

                        return error_fold(r);
                }

                r = connection_queue(&receiver->connection, NULL, message);
                if (r) {
                        if (r == CONNECTION_E_QUOTA || r == CONNECTION_E_UNEXPECTED_FDS) {
                                connection_shutdown(&receiver->connection);

                                log_append_here(sender->bus->log, LOG_WARNING, 0, DBUS_BROKER_CATALOG_RECEIVE_FAILED);
                                bus_log_append_transaction(sender->bus, sender->id, receiver->id, &sender_names, &receiver_names,
                                                           sender->policy->seclabel, receiver->policy->seclabel,
                                                           message);
                                if (r == CONNECTION_E_QUOTA)
                                        r = log_commitf(sender->bus->log, "Peer :1.%llu is being disconnected as it does not have the resources to receive a signal it subscribed to.", receiver->id);
                                else
                                        r = log_commitf(sender->bus->log, "Peer :1.%llu is being disconnected as it does not support receiving the file descriptors it subscribed to.", receiver->id);
                                if (r)
                                        return error_fold(r);
                        } else {
                                return error_fold(r);
                        }
                }
        }

        return 0;
}

static int driver_dispatch_internal(Peer *peer, Message *message) {
        int r;

        r = driver_monitor(peer->bus, peer, message);
        if (r)
                return error_trace(r);

        if (_c_unlikely_(message->metadata.header.type == DBUS_MESSAGE_TYPE_METHOD_CALL &&
                         !message->metadata.fields.destination)) {
                /*
                 * The empty destination is treated as a special peer, only implementing the Peer
                 * interface.
                 */
                if (message->metadata.fields.interface &&
                    strcmp(message->metadata.fields.interface, "org.freedesktop.DBus.Peer") != 0)
                        return DRIVER_E_UNEXPECTED_METHOD;

                return error_trace(driver_dispatch_method(peer,
                                                          peer_methods,
                                                          message_read_serial(message),
                                                          message->metadata.fields.member,
                                                          message->metadata.fields.path,
                                                          message->metadata.fields.signature,
                                                          message));
        }

        if (string_equal(message->metadata.fields.destination, "org.freedesktop.DBus")) {
                r = driver_dispatch_interface(peer,
                                              message_read_serial(message),
                                              message->metadata.fields.interface,
                                              message->metadata.fields.member,
                                              message->metadata.fields.path,
                                              message->metadata.fields.signature,
                                              message);
                if (r) {
                        if (_c_unlikely_(!peer_is_registered(peer)) &&
                            (r == DRIVER_E_UNEXPECTED_INTERFACE ||
                             r == DRIVER_E_UNEXPECTED_METHOD))
                                return DRIVER_E_PEER_NOT_YET_REGISTERED;

                        return error_trace(r);
                }

                return 0;
        }

        if (!peer_is_registered(peer))
                return DRIVER_E_PEER_NOT_REGISTERED;

        if (!message->metadata.fields.destination) {
                if (message->metadata.header.type == DBUS_MESSAGE_TYPE_SIGNAL) {
                        r = driver_forward_broadcast(peer, message);
                        if (r)
                                return error_trace(r);

                        return 0;
                } else {
                        return DRIVER_E_UNEXPECTED_MESSAGE_TYPE;
                }
        }

        switch (message->metadata.header.type) {
        case DBUS_MESSAGE_TYPE_SIGNAL:
        case DBUS_MESSAGE_TYPE_METHOD_CALL:
                return error_trace(driver_forward_unicast(peer,
                                                          message->metadata.fields.destination,
                                                          message));
        case DBUS_MESSAGE_TYPE_METHOD_RETURN:
        case DBUS_MESSAGE_TYPE_ERROR:
                r = peer_queue_reply(peer,
                                     message->metadata.fields.destination,
                                     message->metadata.fields.reply_serial,
                                     message);
                if (r == PEER_E_UNEXPECTED_REPLY)
                        return DRIVER_E_UNEXPECTED_REPLY;
                else
                        return error_fold(r);
        default:
                return DRIVER_E_UNEXPECTED_MESSAGE_TYPE;
        }
}

int driver_dispatch(Peer *peer, Message *message) {
        int r;

        if (peer_is_monitor(peer))
                return DRIVER_E_MONITOR_READ_ONLY;

        r = driver_dispatch_internal(peer, message);
        switch (r) {
        case DRIVER_E_PEER_NOT_REGISTERED:
                return r;
        case DRIVER_E_UNIMPLEMENTED:
        case DRIVER_E_PEER_ALREADY_REGISTERED:
        case DRIVER_E_UNEXPECTED_FDS:
                r = driver_send_error(peer, message_read_serial(message), "org.freedesktop.DBus.Error.Failed", driver_error_to_string(r));
                break;
        case DRIVER_E_PEER_NOT_YET_REGISTERED:
        case DRIVER_E_UNEXPECTED_PATH:
        case DRIVER_E_UNEXPECTED_MESSAGE_TYPE:
        case DRIVER_E_UNEXPECTED_REPLY:
        case DRIVER_E_UNEXPECTED_ENVIRONMENT_UPDATE:
        case DRIVER_E_EXPECTED_REPLY_EXISTS:
        case DRIVER_E_SEND_DENIED:
        case DRIVER_E_RECEIVE_DENIED:
        case DRIVER_E_PEER_NOT_PRIVILEGED:
        case DRIVER_E_NAME_REFUSED:
                r = driver_send_error(peer, message_read_serial(message), "org.freedesktop.DBus.Error.AccessDenied", driver_error_to_string(r));
                break;
        case DRIVER_E_UNEXPECTED_INTERFACE:
                r = driver_send_error(peer, message_read_serial(message), "org.freedesktop.DBus.Error.UnknownInterface", driver_error_to_string(r));
                break;
        case DRIVER_E_UNEXPECTED_METHOD:
                r = driver_send_error(peer, message_read_serial(message), "org.freedesktop.DBus.Error.UnknownMethod", driver_error_to_string(r));
                break;
        case DRIVER_E_UNEXPECTED_PROPERTY:
                r = driver_send_error(peer, message_read_serial(message), "org.freedesktop.DBus.Error.UnkonwnProperty", driver_error_to_string(r));
                break;
        case DRIVER_E_READONLY_PROPERTY:
                r = driver_send_error(peer, message_read_serial(message), "org.freedesktop.DBus.Error.PropertyReadOnly", driver_error_to_string(r));
                break;
        case DRIVER_E_UNEXPECTED_SIGNATURE:
        case DRIVER_E_UNEXPECTED_FLAGS:
        case DRIVER_E_NAME_RESERVED:
        case DRIVER_E_NAME_UNIQUE:
        case DRIVER_E_NAME_INVALID:
                r = driver_send_error(peer, message_read_serial(message), "org.freedesktop.DBus.Error.InvalidArgs", driver_error_to_string(r));
                break;
        case DRIVER_E_FORWARD_FAILED:
        case DRIVER_E_QUOTA:
                r = driver_send_error(peer, message_read_serial(message), "org.freedesktop.DBus.Error.LimitsExceeded", driver_error_to_string(r));
                break;
        case DRIVER_E_PEER_NOT_FOUND:
        case DRIVER_E_NAME_NOT_FOUND:
        case DRIVER_E_NAME_OWNER_NOT_FOUND:
        case DRIVER_E_DESTINATION_NOT_FOUND:
                r = driver_send_error(peer, message_read_serial(message), "org.freedesktop.DBus.Error.NameHasNoOwner", driver_error_to_string(r));
                break;
        case DRIVER_E_NAME_NOT_ACTIVATABLE:
                r = driver_send_error(peer, message_read_serial(message), "org.freedesktop.DBus.Error.ServiceUnknown", driver_error_to_string(r));
                break;
        case DRIVER_E_MATCH_INVALID:
                r = driver_send_error(peer, message_read_serial(message), "org.freedesktop.DBus.Error.MatchRuleInvalid", driver_error_to_string(r));
                break;
        case DRIVER_E_MATCH_NOT_FOUND:
                r = driver_send_error(peer, message_read_serial(message), "org.freedesktop.DBus.Error.MatchRuleNotFound", driver_error_to_string(r));
                break;
        case DRIVER_E_ADT_NOT_SUPPORTED:
                r = driver_send_error(peer, message_read_serial(message), "org.freedesktop.DBus.Error.AdtAuditDataUnknown", driver_error_to_string(r));
                break;
        case DRIVER_E_SELINUX_NOT_SUPPORTED:
                r = driver_send_error(peer, message_read_serial(message), "org.freedesktop.DBus.Error.SELinuxSecurityContextUnknown", driver_error_to_string(r));
                break;
        default:
                break;
        }

        return error_trace(r);
}
