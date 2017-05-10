/*
 * DBus Driver
 */

#include <c-dvar.h>
#include <c-dvar-type.h>
#include <c-macro.h>
#include <c-string.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include "activation.h"
#include "bus.h"
#include "dbus/message.h"
#include "dbus/protocol.h"
#include "dbus/socket.h"
#include "dbus/unique-name.h"
#include "driver.h"
#include "match.h"
#include "peer.h"
#include "util/error.h"

typedef struct DriverMethod DriverMethod;
typedef int (*DriverMethodFn) (Peer *peer, CDVar *var_in, CDVar *var_out, NameChange *change);

struct DriverMethod {
        const char *name;
        const char *path;
        DriverMethodFn fn;
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
static const CDVarType driver_type_out_ab[] = {
        C_DVAR_T_INIT(
                DRIVER_T_MESSAGE(
                        C_DVAR_T_TUPLE1(
                                C_DVAR_T_ARRAY(
                                        C_DVAR_T_b
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

static void driver_write_bytes(CDVar *var, char *bytes, size_t n_bytes) {
        c_dvar_write(var, "[");
        for (size_t i = 0; i < n_bytes; ++i)
                c_dvar_write(var, "y", bytes[i]);
        c_dvar_write(var, "]");
}

static void driver_dvar_write_unique_name(CDVar *var, Peer *peer) {
        char unique_name[UNIQUE_NAME_STRING_MAX + 1];

        if (!peer) {
                c_dvar_write(var, "s", "");
                return;
        }

        unique_name_from_id(unique_name, peer->id);

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
        if (type->length != strlen(signature) + 2)
                return DRIVER_E_UNEXPECTED_SIGNATURE;

        assert(type[0].element == '(');
        assert(type[type->length - 1].element == ')');

        for (unsigned int i = 1; i + 1 < type->length; i++)
                if (signature[i - 1] != type[i].element)
                        return DRIVER_E_UNEXPECTED_SIGNATURE;

        return 0;
}

static void driver_write_reply_header(CDVar *var, Peer *peer, uint32_t serial, const CDVarType *type) {
        c_dvar_write(var, "(yyyyuu[(y<u>)(y<s>)(y<",
                     c_dvar_is_big_endian(var) ? 'B' : 'l', DBUS_MESSAGE_TYPE_METHOD_RETURN, DBUS_HEADER_FLAG_NO_REPLY_EXPECTED, 1, 0, (uint32_t)-1,
                     DBUS_MESSAGE_FIELD_REPLY_SERIAL, c_dvar_type_u, serial,
                     DBUS_MESSAGE_FIELD_SENDER, c_dvar_type_s, "org.freedesktop.DBus",
                     DBUS_MESSAGE_FIELD_DESTINATION, c_dvar_type_s);
        driver_dvar_write_unique_name(var, peer);
        c_dvar_write(var, ">)(y<",
                     DBUS_MESSAGE_FIELD_SIGNATURE, c_dvar_type_g);
        driver_dvar_write_signature_out(var, type);
        c_dvar_write(var, ">)])");
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

/* XXX: move this where it belongs */
int activation_send_signal(Connection *controller, const char *path) {
        static const CDVarType type[] = {
                C_DVAR_T_INIT(
                        DRIVER_T_MESSAGE(
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
        c_dvar_write(&var, "((yyyyuu[(y<o>)(y<s>)(y<s>)])())",
                     c_dvar_is_big_endian(&var) ? 'B' : 'l', DBUS_MESSAGE_TYPE_SIGNAL, DBUS_HEADER_FLAG_NO_REPLY_EXPECTED, 1, 0, (uint32_t)-1,
                     DBUS_MESSAGE_FIELD_PATH, c_dvar_type_o, path,
                     DBUS_MESSAGE_FIELD_INTERFACE, c_dvar_type_s, "org.bus1.DBus.Name",
                     DBUS_MESSAGE_FIELD_MEMBER, c_dvar_type_s, "Activate");

        r = c_dvar_end_write(&var, &data, &n_data);
        if (r)
                return error_origin(r);

        r = message_new_outgoing(&message, data, n_data);
        if (r)
                return error_fold(r);

        r = connection_queue_message(controller, message);
        if (r)
                return error_fold(r);

        return 0;
}

static int driver_send_error(Peer *peer, uint32_t serial, const char *error) {
        static const CDVarType type[] = {
                C_DVAR_T_INIT(
                        DRIVER_T_MESSAGE(
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
        c_dvar_write(&var, "((yyyyuu[(y<u>)(y<s>)(y<s>)(y<",
                     c_dvar_is_big_endian(&var) ? 'B' : 'l', DBUS_MESSAGE_TYPE_ERROR, DBUS_HEADER_FLAG_NO_REPLY_EXPECTED, 1, 0, (uint32_t)-1,
                     DBUS_MESSAGE_FIELD_REPLY_SERIAL, c_dvar_type_u, serial,
                     DBUS_MESSAGE_FIELD_SENDER, c_dvar_type_s, "org.freedesktop.DBus",
                     DBUS_MESSAGE_FIELD_ERROR_NAME, c_dvar_type_s, error,
                     DBUS_MESSAGE_FIELD_DESTINATION, c_dvar_type_s);
        driver_dvar_write_unique_name(&var, peer);
        c_dvar_write(&var, ">)])())");

        r = c_dvar_end_write(&var, &data, &n_data);
        if (r)
                return error_origin(r);

        r = message_new_outgoing(&message, data, n_data);
        if (r)
                return error_fold(r);

        r = connection_queue_message(&peer->connection, message);
        if (r)
                return error_fold(r);

        return 0;
}

static int driver_queue_message_on_peer(Peer *receiver, Peer *sender, Message *message) {
        _c_cleanup_(reply_slot_freep) ReplySlot *slot = NULL;
        int r;

        if (sender &&
            (message->header->type == DBUS_MESSAGE_TYPE_METHOD_CALL) &&
            !(message->header->flags & DBUS_HEADER_FLAG_NO_REPLY_EXPECTED)) {
                r = reply_slot_new(&slot, &receiver->replies_outgoing, &sender->owned_replies, sender->id, message_read_serial(message));
                if (r == REPLY_E_EXISTS)
                        return DRIVER_E_EXPECTED_REPLY_EXISTS;
                else if (r)
                        return error_fold(r);
        }

        r = connection_queue_message(&receiver->connection, message);
        if (r)
                return error_fold(r);

        slot = NULL;
        return 0;
}

static int driver_send_broadcast_to_matches(MatchRegistry *matches, MatchFilter *filter, Message *message) {
        MatchRule *rule;
        int r;

        for (rule = match_rule_next(matches, NULL, filter); rule; rule = match_rule_next(matches, rule, filter)) {
                Peer *peer = c_container_of(rule->owner, Peer, owned_matches);

                r = connection_queue_message(&peer->connection, message);
                if (r)
                        return error_fold(r);
        }

        return 0;
}

static int driver_forward_unicast(Peer *sender, const char *destination, Message *message) {
        Peer *receiver;
        int r;

        if (*destination != ':') {
                Name *name;
                NameOwnership *ownership;

                name = name_registry_find_name(&sender->bus->names, destination);
                if (!name)
                        return DRIVER_E_DESTINATION_NOT_FOUND;

                ownership = c_list_first_entry(&name->ownership_list, NameOwnership, name_link);
                if (!ownership) {
                        if (!name->activation)
                                return DRIVER_E_DESTINATION_NOT_FOUND;

                        r = activation_queue_message(name->activation, message);
                        if (r)
                                return error_fold(r);

                        if (!name->activation->requested) {
                                r = activation_send_signal(sender->bus->controller, name->activation->path);
                                if (r)
                                        return error_fold(r);

                                name->activation->requested = true;
                        }

                        return 0;
                } else {
                        receiver = c_container_of(ownership->owner, Peer, owned_names);
                }
        } else {
                uint64_t id;

                r = unique_name_to_id(destination, &id);
                if (r)
                        return error_trace(r);

                receiver = peer_registry_find_peer(&sender->bus->peers, id);
                if (!receiver)
                        return DRIVER_E_DESTINATION_NOT_FOUND;
        }

        return error_trace(driver_queue_message_on_peer(receiver, sender, message));
}

static int driver_forward_reply(Peer *sender, const char *destination, uint32_t reply_serial, Message *message) {
        ReplySlot *slot;
        Peer *receiver;
        uint64_t id;
        int r;

        r = unique_name_to_id(destination, &id);
        if (r)
                return error_fold(r);

        slot = reply_slot_get_by_id(&sender->replies_outgoing, id, reply_serial);
        if (!slot)
                return DRIVER_E_UNEXPECTED_REPLY;

        receiver = c_container_of(slot->owner, Peer, owned_replies);

        r = connection_queue_message(&receiver->connection, message);
        if (r)
                return error_fold(r);

        reply_slot_free(slot);

        return 0;
}

static int driver_forward_broadcast(Peer *sender, const char *interface, const char *member, const char *path, const char *siganture, Message *message) {
        MatchFilter filter = {
                .type = message->header->type,
                .interface = interface,
                .member = member,
                .path = path,
        };
        int r;

        /* XXX: parse the message to verify the marshalling and read out the arguments for filtering */

        r = driver_send_broadcast_to_matches(&sender->bus->wildcard_matches, &filter, message);
        if (r < 0)
                return error_trace(r);

        for (CRBNode *node = c_rbtree_first(&sender->owned_names.ownership_tree); node; node = c_rbnode_next(node)) {
                NameOwnership *ownership = c_container_of(node, NameOwnership, owner_node);

                if (!name_ownership_is_primary(ownership))
                        continue;

                r = driver_send_broadcast_to_matches(&ownership->name->matches, &filter, message);
                if (r)
                        return error_trace(r);
        }

        r = driver_send_broadcast_to_matches(&sender->matches, &filter, message);
        if (r < 0)
                return error_trace(r);

        return 0;
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
        _c_cleanup_(c_dvar_deinitp) CDVar var = C_DVAR_INIT;
        _c_cleanup_(message_unrefp) Message *message = NULL;
        void *data;
        size_t n_data;
        int r;

        c_dvar_begin_write(&var, type, 1);
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

        r = connection_queue_message(&peer->connection, message);
        if (r)
                return error_fold(r);

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
        _c_cleanup_(c_dvar_deinitp) CDVar var = C_DVAR_INIT;
        _c_cleanup_(message_unrefp) Message *message = NULL;
        void *data;
        size_t n_data;
        int r;

        c_dvar_begin_write(&var, type, 1);
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

        r = connection_queue_message(&peer->connection, message);
        if (r)
                return error_fold(r);

        return 0;
}

static int driver_notify_name_owner_changed(Bus *bus, const char *name, Peer *old_owner, Peer *new_owner) {
        MatchFilter filter = {
                .type = DBUS_MESSAGE_TYPE_SIGNAL,
                .interface = "org.freedesktop.DBus",
                .member = "NameOwnerChanged",
                .path = "/org/freedesktop/DBus",
        };
        char old_owner_str[UNIQUE_NAME_STRING_MAX + 1],
             new_owner_str[UNIQUE_NAME_STRING_MAX + 1];
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
        _c_cleanup_(c_dvar_deinitp) CDVar var = C_DVAR_INIT;
        _c_cleanup_(message_unrefp) Message *message = NULL;
        void *data;
        size_t n_data;
        int r;

        c_dvar_begin_write(&var, type, 1);
        c_dvar_write(&var, "(");
        driver_write_signal_header(&var, NULL, "NameOwnerChanged", "sss");
        c_dvar_write(&var, "(s", name);
        driver_dvar_write_unique_name(&var, old_owner);
        driver_dvar_write_unique_name(&var, new_owner);
        c_dvar_write(&var, ")");
        c_dvar_write(&var, ")");
        r = c_dvar_end_write(&var, &data, &n_data);
        if (r)
                return error_origin(r);

        r = message_new_outgoing(&message, data, n_data);
        if (r)
                return error_fold(r);

        filter.args[0] = name;
        filter.argpaths[0] = name;

        if (old_owner) {
                unique_name_from_id(old_owner_str, old_owner->id);
                filter.args[1] = old_owner_str;
                filter.argpaths[1] = old_owner_str;
        }

        if (new_owner) {
                unique_name_from_id(new_owner_str, new_owner->id);
                filter.args[2] = new_owner_str;
                filter.argpaths[2] = new_owner_str;
        }

        r = driver_send_broadcast_to_matches(&bus->wildcard_matches, &filter, message);
        if (r)

                return error_trace(r);
        r = driver_send_broadcast_to_matches(&bus->driver_matches, &filter, message);
        if (r)
                return error_trace(r);

        return 0;
}

static int driver_name_owner_changed(const char *name, Peer *old_owner, Peer *new_owner) {
        Peer *peer = new_owner ? : old_owner;
        char unique_name[UNIQUE_NAME_STRING_MAX + 1];
        int r;

        assert(old_owner || new_owner);
        assert(name || !old_owner || !new_owner);

        if (!name) {
                unique_name_from_id(unique_name, peer->id);
                name = unique_name;
        }

        if (old_owner) {
                r = driver_notify_name_lost(old_owner, name);
                if (r)
                        return error_trace(r);
        }

        r = driver_notify_name_owner_changed(peer->bus, name, old_owner, new_owner);
        if (r)
                return error_trace(r);

        if (new_owner) {
                r = driver_notify_name_acquired(new_owner, name);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

static int driver_name_activated(Activation *activation, Peer *receiver) {
        SocketBuffer *skb, *safe;
        int r;

        if (!activation)
                return 0;

        c_list_for_each_entry_safe(skb, safe, &activation->socket_buffers, link) {
                Message *message = skb->message;
                Peer *sender;

                sender = peer_registry_find_peer(&receiver->bus->peers, message->sender_id);

                r = driver_queue_message_on_peer(receiver, sender, message);
                if (r) {
                        if (r == DRIVER_E_EXPECTED_REPLY_EXISTS)
                                r = driver_send_error(sender, message_read_serial(message), "org.freedesktop.DBus.Error.AccessDenied");

                        return error_fold(r);
                }

                socket_buffer_free(skb);
        }

        return 0;
}

static int driver_end_read(CDVar *var) {
        int r;

        r = c_dvar_end_read(var);
        switch (r) {
        case C_DVAR_E_CORRUPT_DATA:
        case C_DVAR_E_OUT_OF_BOUNDS:
        case C_DVAR_E_TYPE_MISMATCH:
                return DRIVER_E_INVALID_MESSAGE;
        default:
                return error_origin(r);
        }
}

static int driver_method_hello(Peer *peer, CDVar *in_v, CDVar *out_v, NameChange *change) {
        int r;

        if (_c_unlikely_(peer_is_registered(peer)))
                return DRIVER_E_PEER_ALREADY_REGISTERED;

        /* verify the input argument */
        c_dvar_read(in_v, "()");

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        /* write the output message */
        c_dvar_write(out_v, "(");
        driver_dvar_write_unique_name(out_v, peer);
        c_dvar_write(out_v, ")");

        /* register on the bus */
        peer_register(peer);

        return 0;
}

static int driver_method_request_name(Peer *peer, CDVar *in_v, CDVar *out_v, NameChange *change) {
        const char *name;
        uint32_t flags, reply;
        int r;

        c_dvar_read(in_v, "(su)", &name, &flags);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        if (strcmp(name, "org.freedesktop.DBus") == 0)
                return DRIVER_E_NAME_RESERVED;

        if (peer->user->n_names == 0)
                return DRIVER_E_QUOTA;

        r = name_registry_request_name(&peer->bus->names, &peer->owned_names, name, flags, change);
        if (r == 0) {
                reply = DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER;
        } else if (r == NAME_E_OWNER_NEW || r == NAME_E_OWNER_UPDATED) {
                reply = DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER;
                if (r == NAME_E_OWNER_NEW)
                        --peer->user->n_names;
        } else if (r == NAME_E_IN_QUEUE_NEW || r == NAME_E_IN_QUEUE_UPDATED) {
                reply = DBUS_REQUEST_NAME_REPLY_IN_QUEUE;
                if (r == NAME_E_IN_QUEUE_NEW)
                        --peer->user->n_names;
        } else if (r == NAME_E_EXISTS) {
                reply = DBUS_REQUEST_NAME_REPLY_EXISTS;
        } else {
                return error_fold(r);
        }

        c_dvar_write(out_v, "(u)", reply);

        return 0;
}

static int driver_method_release_name(Peer *peer, CDVar *in_v, CDVar *out_v, NameChange *change) {
        const char *name;
        uint32_t reply;
        int r;

        c_dvar_read(in_v, "(s)", &name);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        if (strcmp(name, "org.freedesktop.DBus") == 0)
                return DRIVER_E_NAME_RESERVED;

        r = name_registry_release_name(&peer->bus->names, &peer->owned_names, name, change);
        if (r == 0) {
                reply = DBUS_RELEASE_NAME_REPLY_RELEASED;
                ++peer->user->n_names;
        } else if (r == NAME_E_NOT_FOUND) {
                reply = DBUS_RELEASE_NAME_REPLY_NON_EXISTENT;
        } else if (r == NAME_E_NOT_OWNER) {
                reply = DBUS_RELEASE_NAME_REPLY_NOT_OWNER;
        } else {
                return error_fold(r);
        }

        c_dvar_write(out_v, "(u)", reply);

        return 0;
}

static int driver_method_list_queued_owners(Peer *peer, CDVar *in_v, CDVar *out_v, NameChange *change) {
        Name *name;
        NameOwnership *ownership;
        const char *name_str;
        int r;

        c_dvar_read(in_v, "(s)", &name_str);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        name = name_registry_find_name(&peer->bus->names, name_str);
        if (!name)
                return DRIVER_E_NAME_NOT_FOUND;

        c_dvar_write(out_v, "([");
        c_list_for_each_entry(ownership, &name->ownership_list, name_link)
                driver_dvar_write_unique_name(out_v, c_container_of(ownership->owner, Peer, owned_names));
        c_dvar_write(out_v, "])");

        return 0;
}

static int driver_method_list_names(Peer *peer, CDVar *in_v, CDVar *out_v, NameChange *change) {
        int r;

        c_dvar_read(in_v, "()");

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        c_dvar_write(out_v, "([");
        c_dvar_write(out_v, "s", "org.freedesktop.DBus");
        for (CRBNode *n = c_rbtree_first(&peer->bus->names.name_tree); n; n = c_rbnode_next(n)) {
                Name *name = c_container_of(n, Name, registry_node);

                if (!name_is_owned(name))
                        continue;

                c_dvar_write(out_v, "s", name->name);
        }
        for (CRBNode *n = c_rbtree_first(&peer->bus->peers.peer_tree); n; n = c_rbnode_next(n)) {
                Peer *p = c_container_of(n, Peer, registry_node);

                if (!peer_is_registered(p))
                        continue;

                driver_dvar_write_unique_name(out_v, p);
        }
        c_dvar_write(out_v, "])");

        return 0;
}

static int driver_method_list_activatable_names(Peer *peer, CDVar *in_v, CDVar *out_v, NameChange *change) {
        int r;

        c_dvar_read(in_v, "()");

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        c_dvar_write(out_v, "([");
        for (CRBNode *n = c_rbtree_first(&peer->bus->names.name_tree); n; n = c_rbnode_next(n)) {
                Name *name = c_container_of(n, Name, registry_node);

                if (!name->activation)
                        continue;

                c_dvar_write(out_v, "s", name->name);
        }
        c_dvar_write(out_v, "])");

        return 0;
}

static int driver_method_name_has_owner(Peer *peer, CDVar *in_v, CDVar *out_v, NameChange *change) {
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
                connection = bus_find_peer_by_name(peer->bus, name);

                c_dvar_write(out_v, "(b)", !!connection);
        }

        return 0;
}

static int driver_method_start_service_by_name(Peer *peer, CDVar *in_v, CDVar *out_v, NameChange *change) {
        /* XXX */

        return 0;
}

static int driver_method_update_activation_environment(Peer *peer, CDVar *in_v, CDVar *out_v, NameChange *change) {
        /* XXX */

        return 0;
}

static int driver_method_get_name_owner(Peer *peer, CDVar *in_v, CDVar *out_v, NameChange *change) {
        const char *name_str;
        int r;

        c_dvar_read(in_v, "(s)", &name_str);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        c_dvar_write(out_v, "(");

        if (strcmp(name_str, "org.freedesktop.DBus") == 0) {
                c_dvar_write(out_v, "org.freedesktop.DBus");
        } else {
                Peer *owner;

                owner = bus_find_peer_by_name(peer->bus, name_str);
                if (!owner)
                        return DRIVER_E_NAME_OWNER_NOT_FOUND;

                driver_dvar_write_unique_name(out_v, owner);
        }

        c_dvar_write(out_v, ")");

        return 0;
}

static int driver_method_get_connection_unix_user(Peer *peer, CDVar *in_v, CDVar *out_v, NameChange *change) {
        Peer *connection;
        const char *name;
        int r;

        c_dvar_read(in_v, "(s)", &name);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        connection = bus_find_peer_by_name(peer->bus, name);
        if (!connection)
                return DRIVER_E_PEER_NOT_FOUND;

        c_dvar_write(out_v, "(u)", connection->user->uid);

        return 0;
}

static int driver_method_get_connection_unix_process_id(Peer *peer, CDVar *in_v, CDVar *out_v, NameChange *change) {
        Peer *connection;
        const char *name;
        int r;

        c_dvar_read(in_v, "(s)", &name);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        connection = bus_find_peer_by_name(peer->bus, name);
        if (!connection)
                return DRIVER_E_PEER_NOT_FOUND;

        c_dvar_write(out_v, "u", connection->pid);

        return 0;
}

static int driver_method_get_connection_credentials(Peer *peer, CDVar *in_v, CDVar *out_v, NameChange *change) {
        Peer *connection;
        const char *name;
        int r;

        c_dvar_read(in_v, "(s)", &name);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        connection = bus_find_peer_by_name(peer->bus, name);
        if (!connection)
                return DRIVER_E_PEER_NOT_FOUND;

        c_dvar_write(out_v, "[{s<u>}{s<u>}",
                     "UnixUserID", c_dvar_type_u, connection->user->uid,
                     "ProcessID", c_dvar_type_u, connection->pid);

        if (connection->seclabel) {
                /*
                 * The DBus specification says that the security-label is a
                 * byte array of non-0 values. The kernel disagrees.
                 * Unfortunately, the spec does not provide any transformation
                 * rules. Hence, we simply ignore that part of the spec and
                 * insert the label unmodified, followed by a zero byte, which
                 * is mandated by the spec.
                 * The @peer->seclabel field always has a trailing zero-byte,
                 * so we can safely copy from it.
                 */
                c_dvar_write(out_v, "{s<", "LinuxSecurityLabel", (const CDVarType[]){ C_DVAR_T_INIT(C_DVAR_T_ARRAY(C_DVAR_T_y)) });
                driver_write_bytes(out_v, connection->seclabel, connection->n_seclabel + 1);
                c_dvar_write(out_v, ">}");
        }

        c_dvar_write(out_v, "]");

        return 0;
}

static int driver_method_get_adt_audit_session_data(Peer *peer, CDVar *in_v, CDVar *out_v, NameChange *change) {
        return DRIVER_E_ADT_NOT_SUPPORTED;
}

static int driver_method_get_connection_selinux_security_context(Peer *peer, CDVar *in_v, CDVar *out_v, NameChange *change) {
        Peer *connection;
        const char *name;
        int r;

        /*
         * XXX: Unlike "LinuxSecurityLabel" in GetConnectionCredentials(), this
         *      call is specific to SELinux. Hence, we better only return the
         *      label if we are running on SELinux.
         */

        c_dvar_read(in_v, "(s)", &name);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        connection = bus_find_peer_by_name(peer->bus, name);
        if (!connection)
                return DRIVER_E_PEER_NOT_FOUND;

        if (!connection->seclabel)
                return DRIVER_E_SELINUX_NOT_SUPPORTED;

        /*
         * Unlike the "LinuxSecurityLabel", this call does not include a
         * trailing 0-byte in the data blob.
         */
        driver_write_bytes(out_v, connection->seclabel, connection->n_seclabel);

        return 0;
}

static int driver_method_add_match(Peer *peer, CDVar *in_v, CDVar *out_v, NameChange *change) {
        _c_cleanup_(match_rule_user_unrefp) MatchRule *rule = NULL;
        const char *rule_string;
        int r;

        c_dvar_read(in_v, "(s)", &rule_string);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        if (peer->user->n_matches == 0)
                return DRIVER_E_QUOTA;

        r = match_rule_new(&rule, &peer->owned_matches, rule_string);
        if (r) {
                if (r == MATCH_E_INVALID)
                        return DRIVER_E_MATCH_INVALID;
                else
                        return error_fold(r);
        }

        if (!rule->keys.sender)
                match_rule_link(rule, &peer->bus->wildcard_matches);
        else if (*rule->keys.sender == ':') {
                Peer *sender;
                uint64_t id;

                r = unique_name_to_id(rule->keys.sender, &id);
                if (r)
                        return error_fold(r);

                sender = peer_registry_find_peer(&peer->bus->peers, id);
                if (!sender)
                        return -ENOTRECOVERABLE;

                match_rule_link(rule, &sender->matches);
        } else if (strcmp(rule->keys.sender, "org.freedesktop.DBus") == 0) {
                match_rule_link(rule, &peer->bus->driver_matches);
        } else {
                _c_cleanup_(name_unrefp) Name *name = NULL;

                r = name_get(&name, &peer->bus->names, rule->keys.sender);
                if (r)
                        return error_fold(r);

                match_rule_link(rule, &name->matches);
                name_ref(name); /* this reference must be explicitly released */
        }

        c_dvar_write(out_v, "()");

        --peer->user->n_matches;
        rule = NULL;

        return 0;
}

static int driver_method_remove_match(Peer *peer, CDVar *in_v, CDVar *out_v, NameChange *change) {
        _c_cleanup_(name_unrefp) Name *name = NULL;
        MatchRule *rule;
        const char *rule_string;
        int r;

        c_dvar_read(in_v, "(s)", &rule_string);

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        r = match_rule_get(&rule, &peer->owned_matches, rule_string);
        if (r) {
                if (r == MATCH_E_NOT_FOUND)
                        return DRIVER_E_MATCH_NOT_FOUND;
                else if (r == MATCH_E_INVALID)
                        return DRIVER_E_MATCH_INVALID;
                else
                        return error_fold(r);
        }

        if (rule->keys.sender && *rule->keys.sender != ':' && strcmp(rule->keys.sender, "org.freedesktop.DBus") != 0)
                name = c_container_of(rule->registry, Name, matches);

        match_rule_user_unref(rule);
        ++peer->user->n_matches;

        c_dvar_write(out_v, "()");

        return 0;
}

static int driver_method_get_id(Peer *peer, CDVar *in_v, CDVar *out_v, NameChange *change) {
        char buffer[sizeof(peer->bus->guid) * 2];
        int r;

        /* verify the input argument */
        c_dvar_read(in_v, "()");

        r = driver_end_read(in_v);
        if (r)
                return error_trace(r);

        /* write the output message */
        c_string_to_hex(peer->bus->guid, sizeof(peer->bus->guid), buffer);
        c_dvar_write(out_v, "(s)", buffer);

        return 0;
}

static int driver_method_become_monitor(Peer *peer, CDVar *in_v, CDVar *out_v, NameChange *change) {
        /* XXX */

        return 0;
}

static int driver_handle_method(const DriverMethod *method, Peer *peer, const char *path, uint32_t serial, const char *signature_in, Message *message_in) {
        _c_cleanup_(c_dvar_deinitp) CDVar var_in = C_DVAR_INIT, var_out = C_DVAR_INIT;
        _c_cleanup_(message_unrefp) Message *message_out = NULL;
        NameChange change = {};
        void *data;
        size_t n_data;
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
        c_dvar_begin_write(&var_out, method->out, 1);

        /*
         * Write the generic reply-header and then call into the method-handler
         * of the specific driver method. Note that the driver-methods are
         * responsible to call driver_end_read(var_in), to verify all read data
         * was correct.
         */

        c_dvar_write(&var_out, "(");
        driver_write_reply_header(&var_out, peer, serial, method->out);

        r = method->fn(peer, &var_in, &var_out, &change);
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

        r = connection_queue_message(&peer->connection, message_out);
        if (r)
                return error_fold(r);

        if (change.name) {
                Peer *old_peer = NULL, *new_peer = NULL;

                if (change.old_owner)
                        old_peer = c_container_of(change.old_owner, Peer, owned_names);

                if (change.new_owner)
                        new_peer = c_container_of(change.new_owner, Peer, owned_names);

                r = driver_name_owner_changed(change.name->name, old_peer, new_peer);
                if (r)
                        return error_trace(r);

                if (new_peer) {
                        r = driver_name_activated(change.name->activation, new_peer);
                        if (r)
                                return error_trace(r);
                }

                name_change_deinit(&change);
        } else if (strcmp(method->name, "Hello") == 0) {
                /* XXX: special casing this is a bit of a hack */
                r = driver_name_owner_changed(NULL, NULL, peer);
                if (r)
                        return error_trace(r);
        }


        return 0;
}

static int driver_dispatch_method(Peer *peer, uint32_t serial, const char *method, const char *path, const char *signature, Message *message) {
        static const DriverMethod methods[] = {
                { "Hello",                                      NULL,                           driver_method_hello,                                            c_dvar_type_unit,       driver_type_out_s },
                { "RequestName",                                NULL,                           driver_method_request_name,                                     driver_type_in_su,      driver_type_out_u },
                { "ReleaseName",                                NULL,                           driver_method_release_name,                                     driver_type_in_s,       driver_type_out_u },
                { "ListQueuedOwners",                           NULL,                           driver_method_list_queued_owners,                               driver_type_in_s,       driver_type_out_as },
                { "ListNames",                                  NULL,                           driver_method_list_names,                                       c_dvar_type_unit,       driver_type_out_as },
                { "ListActivatableNames",                       NULL,                           driver_method_list_activatable_names,                           c_dvar_type_unit,       driver_type_out_as },
                { "NameHasOwner",                               NULL,                           driver_method_name_has_owner,                                   driver_type_in_s,       driver_type_out_b },
                { "StartServiceByName",                         NULL,                           driver_method_start_service_by_name,                            driver_type_in_s,       driver_type_out_u },
                { "UpdateActivationEnvironment",                "/org/freedesktop/DBus",        driver_method_update_activation_environment,                    driver_type_in_apss,    driver_type_out_unit },
                { "GetNameOwner",                               NULL,                           driver_method_get_name_owner,                                   driver_type_in_s,       driver_type_out_s },
                { "GetConnectionUnixUser",                      NULL,                           driver_method_get_connection_unix_user,                         driver_type_in_s,       driver_type_out_u },
                { "GetConnectionUnixProcessID",                 NULL,                           driver_method_get_connection_unix_process_id,                   driver_type_in_s,       driver_type_out_u },
                { "GetConnectionCredentials",                   NULL,                           driver_method_get_connection_credentials,                       driver_type_in_s,       driver_type_out_apsv },
                { "GetAdtAuditSessionData",                     NULL,                           driver_method_get_adt_audit_session_data,                       driver_type_in_s,       driver_type_out_ab },
                { "GetConnectionSELinuxSecurityContext",        NULL,                           driver_method_get_connection_selinux_security_context,          driver_type_in_s,       driver_type_out_ab },
                { "AddMatch",                                   NULL,                           driver_method_add_match,                                        driver_type_in_s,       driver_type_out_unit },
                { "RemoveMatch",                                NULL,                           driver_method_remove_match,                                     driver_type_in_s,       driver_type_out_unit },
                { "GetId",                                      NULL,                           driver_method_get_id,                                           c_dvar_type_unit,       driver_type_out_s },
                { "BecomeMonitor",                              "/org/freedesktop/DBus",        driver_method_become_monitor,                                   driver_type_in_asu,     driver_type_out_unit },
        };

        if (_c_unlikely_(!peer_is_registered(peer)) && strcmp(method, "Hello") != 0)
                return DRIVER_E_PEER_NOT_REGISTERED;

        for (size_t i = 0; i < C_ARRAY_SIZE(methods); i++) {
                if (strcmp(methods[i].name, method) != 0)
                        continue;

                return driver_handle_method(&methods[i], peer, path, serial, signature, message);
        }

        return DRIVER_E_UNEXPECTED_METHOD;
}

static int driver_dispatch_interface(Peer *peer, uint32_t serial, const char *interface, const char *member, const char *path, const char *signature, Message *message) {
        if (message->header->type != DBUS_MESSAGE_TYPE_METHOD_CALL)
                /* ignore */
                return 0;

        if (interface && _c_unlikely_(strcmp(interface, "org.freedesktop.DBus") != 0))
                return DRIVER_E_UNEXPECTED_INTERFACE;

        return driver_dispatch_method(peer, serial, member, path, signature, message);
}

int driver_goodbye(Peer *peer, bool silent) {
        CRBNode *node;
        int r;

        while ((node = peer->owned_matches.rule_tree.root)) {
                _c_cleanup_(name_unrefp) Name *name = NULL;
                MatchRule *rule = c_container_of(node, MatchRule, owner_node);

                if (rule->keys.sender && *rule->keys.sender != ':' && strcmp(rule->keys.sender, "org.freedesktop.DBus") != 0)
                        name = c_container_of(rule->registry, Name, matches);

                match_rule_user_unref(rule);
                ++peer->user->n_matches;
        }

        while ((node = peer->owned_names.ownership_tree.root)) {
                NameOwnership *ownership = c_container_of(node, NameOwnership, owner_node);
                NameChange change;
                int r = 0;

                name_change_init(&change);
                name_ownership_release(ownership, &change);
                ++peer->user->n_names;
                if (!silent && change.name)
                        r = driver_name_owner_changed(change.name->name,
                                                      c_container_of(change.old_owner, Peer, owned_names),
                                                      c_container_of(change.new_owner, Peer, owned_names));
                name_change_deinit(&change);
                if (r)
                        return error_fold(r);
        }

        if (!silent) {
                r = driver_name_owner_changed(NULL, peer, NULL);
                if (r)
                        return error_trace(r);
        }
        peer_unregister(peer);

        while ((node = peer->replies_outgoing.reply_tree.root)) {
                ReplySlot *slot = c_container_of(node, ReplySlot, registry_node);
                Peer *sender = c_container_of(slot->owner, Peer, owned_replies);

                if (!silent) {
                        r = driver_send_error(sender, slot->serial, "org.freedesktop.DBus.Error.NoReply");
                        if (r)
                                return error_trace(r);
                }

                reply_slot_free(slot);
        }

        return 0;
}

static int driver_dispatch_internal(Peer *peer, MessageMetadata *metadata, Message *message) {
        const char *signature;
        int r;

        /* no signature implies empty signature */
        signature = metadata->fields.signature ?: "";

        if (_c_unlikely_(c_string_equal(metadata->fields.destination, "org.freedesktop.DBus")))
                return error_trace(driver_dispatch_interface(peer,
                                                             metadata->header.serial,
                                                             metadata->fields.interface,
                                                             metadata->fields.member,
                                                             metadata->fields.path,
                                                             signature,
                                                             message));

        r = message_stitch_sender(message, peer->id);
        if (r)
                return error_fold(r);

        if (!metadata->fields.destination) {
                if (metadata->header.type != DBUS_MESSAGE_TYPE_SIGNAL)
                        return DRIVER_E_UNEXPECTED_MESSAGE_TYPE;

                return error_trace(driver_forward_broadcast(peer,
                                                            metadata->fields.interface,
                                                            metadata->fields.member,
                                                            metadata->fields.path,
                                                            signature,
                                                            message));
        }

        switch (metadata->header.type) {
        case DBUS_MESSAGE_TYPE_SIGNAL:
        case DBUS_MESSAGE_TYPE_METHOD_CALL:
                return error_trace(driver_forward_unicast(peer,
                                                          metadata->fields.destination,
                                                          message));
        case DBUS_MESSAGE_TYPE_METHOD_RETURN:
        case DBUS_MESSAGE_TYPE_ERROR:
                return error_trace(driver_forward_reply(peer,
                                                        metadata->fields.destination,
                                                        metadata->fields.reply_serial,
                                                        message));
        default:
                return DRIVER_E_UNEXPECTED_MESSAGE_TYPE;
        }
}

int driver_dispatch(Peer *peer, Message *message) {
        MessageMetadata metadata;
        int r;

        r = message_parse_metadata(message, &metadata);
        if (r > 0)
                return DRIVER_E_DISCONNECT;
        else if (r < 0)
                return error_fold(r);

        r = driver_dispatch_internal(peer, &metadata, message);
        switch (r) {
        case DRIVER_E_INVALID_MESSAGE:
        case DRIVER_E_PEER_NOT_REGISTERED:
                return DRIVER_E_DISCONNECT;
        case DRIVER_E_PEER_ALREADY_REGISTERED:
                r = driver_send_error(peer, metadata.header.serial, "org.freedesktop.DBus.Error.Failed");
                break;
        case DRIVER_E_UNEXPECTED_PATH:
        case DRIVER_E_UNEXPECTED_MESSAGE_TYPE:
        case DRIVER_E_UNEXPECTED_REPLY:
        case DRIVER_E_EXPECTED_REPLY_EXISTS:
                r = driver_send_error(peer, metadata.header.serial, "org.freedesktop.DBus.Error.AccessDenied");
                break;
        case DRIVER_E_UNEXPECTED_INTERFACE:
                r = driver_send_error(peer, metadata.header.serial, "org.freedesktop.DBus.Error.UnknownInterface");
                break;
        case DRIVER_E_UNEXPECTED_METHOD:
                r = driver_send_error(peer, metadata.header.serial, "org.freedesktop.DBus.Error.UnknownMethod");
                break;
        case DRIVER_E_UNEXPECTED_SIGNATURE:
                r = driver_send_error(peer, metadata.header.serial, "org.freedesktop.DBus.Error.InvalidArgs");
                break;
        case DRIVER_E_QUOTA:
                r = driver_send_error(peer, metadata.header.serial, "org.freedesktop.DBus.Error.LimitsExceeded");
                break;
        case DRIVER_E_PEER_NOT_FOUND:
        case DRIVER_E_NAME_NOT_FOUND:
        case DRIVER_E_NAME_OWNER_NOT_FOUND:
        case DRIVER_E_DESTINATION_NOT_FOUND:
                r = driver_send_error(peer, metadata.header.serial, "org.freedesktop.DBus.Error.NameHasNoOwner");
                break;
        case DRIVER_E_NAME_RESERVED:
                r = driver_send_error(peer, metadata.header.serial, "org.freedesktop.DBus.Error.InvalidArgs");
                break;
        case DRIVER_E_MATCH_INVALID:
                r = driver_send_error(peer, metadata.header.serial, "org.freedesktop.DBus.Error.MatchRuleInvalid");
                break;
        case DRIVER_E_MATCH_NOT_FOUND:
                r = driver_send_error(peer, metadata.header.serial, "org.freedesktop.DBus.Error.MatchRuleNotFound");
                break;
        case DRIVER_E_ADT_NOT_SUPPORTED:
                r = driver_send_error(peer, metadata.header.serial, "org.freedesktop.DBus.Error.AdtAuditDataUnknown");
                break;
        case DRIVER_E_SELINUX_NOT_SUPPORTED:
                r = driver_send_error(peer, metadata.header.serial, "org.freedesktop.DBus.Error.SELinuxSecurityContextUnknown");
                break;
        default:
                break;
        }

        return error_trace(r);
}
