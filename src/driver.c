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
#include "dbus-protocol.h"
#include "driver.h"
#include "message.h"
#include "peer.h"
#include "socket.h"

typedef struct DriverMethod DriverMethod;
typedef int (*DriverMethodFn) (Peer *peer, CDVar *var_in, CDVar *var_out);

struct DriverMethod {
        const char *name;
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
        peer_registry_link_peer(&peer->bus->peers, peer);

        return 0;
}

static int driver_method_request_name(Peer *peer, CDVar *in_v, CDVar *out_v) {
        const char *name;
        uint32_t flags, reply;
        int r;

        c_dvar_read(in_v, "(su)", &name, &flags);

        r = c_dvar_end_read(in_v);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        r = name_registry_request_name(&peer->bus->names, peer, name, flags, &reply);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        c_dvar_write(out_v, "u", reply);

        return 0;
}

static int driver_method_release_name(Peer *peer, CDVar *in_v, CDVar *out_v) {
        const char *name;
        uint32_t reply;
        int r;

        c_dvar_read(in_v, "(s)", &name);

        r = c_dvar_end_read(in_v);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        name_registry_release_name(&peer->bus->names, peer, name, &reply);

        c_dvar_write(out_v, "u", reply);

        return 0;
}

static int driver_method_list_queued_owners(Peer *peer, CDVar *in_v, CDVar *out_v) {
        NameEntry *entry;
        NameOwner *owner;
        const char *name;
        int r;

        c_dvar_read(in_v, "(s)", &name);

        r = c_dvar_end_read(in_v);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        entry = name_registry_find_entry(&peer->bus->names, name);
        if (!entry)
                return -ENOTRECOVERABLE;

        /* XXX: verify if the actual owner should be included */
        c_dvar_write(out_v, "(");
        c_list_for_each_entry(owner, &entry->owners, entry_link)
                driver_dvar_write_unique_name(out_v, owner->peer);
        c_dvar_write(out_v, ")");

        return 0;
}

static int driver_method_list_names(Peer *peer, CDVar *in_v, CDVar *out_v) {
        int r;

        c_dvar_read(in_v, "()");

        r = c_dvar_end_read(in_v);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        c_dvar_write(out_v, "(");
        for (CRBNode *n = c_rbtree_first(&peer->bus->names.entries); n; n = c_rbnode_next(n)) {
                NameEntry *entry = c_container_of(n, NameEntry, rb);

                c_dvar_write(out_v, "s", entry->name);
        }
        c_dvar_write(out_v, ")");

        return 0;
}

static int driver_method_list_activatable_names(Peer *peer, CDVar *in_v, CDVar *out_v) {
        /* XXX */

        return 0;
}

static int driver_method_name_has_owner(Peer *peer, CDVar *in_v, CDVar *out_v) {
        Peer *connection;
        const char *name;
        int r;

        c_dvar_read(in_v, "(s)", &name);

        r = c_dvar_end_read(in_v);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        connection = bus_find_peer_by_name(peer->bus, name);

        c_dvar_write(out_v, "b", !!connection);

        return 0;
}

static int driver_method_start_service_by_name(Peer *peer, CDVar *in_v, CDVar *out_v) {
        /* XXX */

        return 0;
}

static int driver_method_update_activation_environment(Peer *peer, CDVar *in_v, CDVar *out_v) {
        /* XXX */

        return 0;
}

static int driver_method_get_name_owner(Peer *peer, CDVar *in_v, CDVar *out_v) {
        Peer *owner;
        const char *name;
        int r;

        c_dvar_read(in_v, "(s)", &name);

        r = c_dvar_end_read(in_v);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        owner = name_registry_resolve_name(&peer->bus->names, name);
        if (!owner)
                return -ENOTRECOVERABLE;

        driver_dvar_write_unique_name(out_v, owner);

        return 0;
}

static int driver_method_get_connection_unix_user(Peer *peer, CDVar *in_v, CDVar *out_v) {
        Peer *connection;
        const char *name;
        int r;

        c_dvar_read(in_v, "(s)", &name);

        r = c_dvar_end_read(in_v);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        connection = bus_find_peer_by_name(peer->bus, name);
        if (!connection)
                return -ENOTRECOVERABLE;

        c_dvar_write(out_v, "u", connection->user->uid);

        return 0;
}

static int driver_method_get_connection_unix_process_id(Peer *peer, CDVar *in_v, CDVar *out_v) {
        Peer *connection;
        const char *name;
        int r;

        c_dvar_read(in_v, "(s)", &name);

        r = c_dvar_end_read(in_v);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        connection = bus_find_peer_by_name(peer->bus, name);
        if (!connection)
                return -ENOTRECOVERABLE;

        c_dvar_write(out_v, "u", connection->pid);

        return 0;
}

static int driver_method_get_connection_credentials(Peer *peer, CDVar *in_v, CDVar *out_v) {
        Peer *connection;
        const char *name;
        int r;

        c_dvar_read(in_v, "(s)", &name);

        r = c_dvar_end_read(in_v);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        connection = bus_find_peer_by_name(peer->bus, name);
        if (!connection)
                return -ENOTRECOVERABLE;

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

static int driver_method_get_adt_audit_session_data(Peer *peer, CDVar *in_v, CDVar *out_v) {
        /* XXX */

        return 0;
}

static int driver_method_get_connection_selinux_security_context(Peer *peer, CDVar *in_v, CDVar *out_v) {
        Peer *connection;
        const char *name;
        int r;

        /*
         * XXX: Unlike "LinuxSecurityLabel" in GetConnectionCredentials(), this
         *      call is specific to SELinux. Hence, we better only return the
         *      label if we are running on SELinux.
         */

        c_dvar_read(in_v, "(s)", &name);

        r = c_dvar_end_read(in_v);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        connection = bus_find_peer_by_name(peer->bus, name);
        if (!connection)
                return -ENOTRECOVERABLE;

        if (!connection->seclabel)
                return -ENOTRECOVERABLE;

        /*
         * Unlike the "LinuxSecurityLabel", this call does not include a
         * trailing 0-byte in the data blob.
         */
        driver_write_bytes(out_v, connection->seclabel, connection->n_seclabel);

        return 0;
}

static int driver_method_add_match(Peer *peer, CDVar *in_v, CDVar *out_v) {
        MatchRule *rule;
        const char *rule_string;
        int r;

        c_dvar_read(in_v, "(s)", &rule_string);

        r = c_dvar_end_read(in_v);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        r = match_rule_new(&rule, peer, rule_string);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        match_rule_link(rule, &peer->bus->matches);

        c_dvar_write(out_v, "()");

        return 0;
}

static int driver_method_remove_match(Peer *peer, CDVar *in_v, CDVar *out_v) {
        MatchRule *rule;
        const char *rule_string;
        int r;

        c_dvar_read(in_v, "(s)", &rule_string);

        r = c_dvar_end_read(in_v);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        r = match_rule_get(&rule, peer, rule_string);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        match_rule_unref(rule);

        c_dvar_write(out_v, "()");

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
        /* XXX */

        return 0;
}

static int driver_handle_method(const DriverMethod *method, Peer *peer, uint32_t serial, const char *signature_in, Message *message_in) {
        _c_cleanup_(c_dvar_freep) CDVar *var_in = NULL, *var_out = NULL;
        _c_cleanup_(message_unrefp) Message *message_out = NULL;
        void *data;
        size_t n_data;
        int r;

        /*
         * Verify the input signature and prepare the input & output variants
         * for input parsing and output marshaling.
         */

        r = driver_dvar_verify_signature_in(method->in, signature_in);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        r = c_dvar_new(&var_in);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        r = c_dvar_new(&var_out);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        c_dvar_begin_read(var_in, message_in->big_endian, method->in, message_in->body, message_in->n_body);
        c_dvar_begin_write(var_out, method->out);

        /*
         * Write the generic reply-header and then call into the method-handler
         * of the specific driver method. Note that the driver-methods are
         * responsible to call c_dvar_end_read(var_in), to verify all read data
         * was correct.
         */

        c_dvar_write(var_out, "(");
        driver_write_reply_header(var_out, peer, serial, method->out);

        r = method->fn(peer, var_in, var_out);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        c_dvar_write(var_out, ")");

        /*
         * The message was correctly handled and the reply is serialized in
         * @var_out. Lets finish it up and queue the reply on the destination.
         * Note that any failure in doing so must be a fatal error, so there is
         * no point in reverting the operation on failure.
         */

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
                { "Hello",                                      driver_method_hello,                                            c_dvar_type_unit,       driver_type_out_s },
                { "RequestName",                                driver_method_request_name,                                     driver_type_in_su,      driver_type_out_u },
                { "ReleaseName",                                driver_method_release_name,                                     driver_type_in_s,       driver_type_out_u },
                { "ListQueuedOwners",                           driver_method_list_queued_owners,                               driver_type_in_s,       driver_type_out_as },
                { "ListNames",                                  driver_method_list_names,                                       c_dvar_type_unit,       driver_type_out_as },
                { "ListActivatableNames",                       driver_method_list_activatable_names,                           c_dvar_type_unit,       driver_type_out_as },
                { "NameHasOwner",                               driver_method_name_has_owner,                                   driver_type_in_s,       driver_type_out_b },
                { "StartServiceByName",                         driver_method_start_service_by_name,                            driver_type_in_s,       driver_type_out_u },
                { "UpdateActivationEnvironment",                driver_method_update_activation_environment,                    driver_type_in_apss,    driver_type_out_unit },
                { "GetNameOwner",                               driver_method_get_name_owner,                                   driver_type_in_s,       driver_type_out_s },
                { "GetConnectionUnixUser",                      driver_method_get_connection_unix_user,                         driver_type_in_s,       driver_type_out_u },
                { "GetConnectionUnixProcessID",                 driver_method_get_connection_unix_process_id,                   driver_type_in_s,       driver_type_out_u },
                { "GetConnectionCredentials",                   driver_method_get_connection_credentials,                       driver_type_in_s,       driver_type_out_apsv },
                { "GetAdtAuditSessionData",                     driver_method_get_adt_audit_session_data,                       driver_type_in_s,       driver_type_out_ab },
                { "GetConnectionSELinuxSecurityContext",        driver_method_get_connection_selinux_security_context,          driver_type_in_s,       driver_type_out_ab },
                { "AddMatch",                                   driver_method_add_match,                                        driver_type_in_s,       driver_type_out_unit },
                { "RemoveMatch",                                driver_method_remove_match,                                     driver_type_in_s,       driver_type_out_unit },
                { "GetId",                                      driver_method_get_id,                                           c_dvar_type_unit,       driver_type_out_s },
                { "BecomeMonitor",                              driver_method_become_monitor,                                   driver_type_in_asu,     driver_type_out_unit },
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

int driver_dispatch_interface(Peer *peer,
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

void driver_notify_name_owner_change(const char *name, Peer *old_peer, Peer *new_peer) {
        assert(old_peer || new_peer);
        assert(!old_peer || c_rbnode_is_linked(&old_peer->rb));
        assert(!new_peer || c_rbnode_is_linked(&new_peer->rb));
        assert(name || !old_peer || !new_peer);
}
