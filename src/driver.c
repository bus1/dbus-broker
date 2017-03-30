/*
 * DBus Driver
 */

#include <c-macro.h>
#include <stdlib.h>
#include "bus.h"
#include "dbus-message.h"
#include "driver.h"
#include "peer.h"

typedef struct DriverMethod DriverMethod;
typedef int (*DriverMethodFn) (Bus *bus, Peer *peer, DBusMessage *message);

struct DriverMethod {
        const char *name;
        DriverMethodFn fn;
};

int driver_method_hello(Bus *bus, Peer *peer, DBusMessage *message) {
        bus_register_peer(bus, peer);

        return 0;
}

int driver_method_list_names(Bus *bus, Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_list_activatable_names(Bus *bus, Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_name_has_owner(Bus *bus, Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_start_service_by_name(Bus *bus, Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_update_activation_environment(Bus *bus, Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_get_name_owner(Bus *bus, Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_get_connection_unix_user(Bus *bus, Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_get_connection_unix_process_id(Bus *bus, Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_get_connection_credentials(Bus *bus, Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_get_adt_audit_session_data(Bus *bus, Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_get_connection_selinux_security_context(Bus *bus, Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_add_match(Bus *bus, Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_remove_match(Bus *bus, Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_get_id(Bus *bus, Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_become_monitor(Bus *bus, Peer *peer, DBusMessage *message) {
        return 0;
}

/* XXX: use gperf */
static int driver_dispatch_method(Bus *bus,
                              Peer *peer,
                              const char *method,
                              DBusMessage *message) {
        static const DriverMethod methods[] = {
                { "Hello", driver_method_hello },
                { "ListNames", driver_method_list_names },
                { "ListActivatableNames", driver_method_list_activatable_names },
                { "NameHasOwner", driver_method_name_has_owner },
                { "StartServiceByName", driver_method_start_service_by_name },
                { "UpdateActivationEnvironment", driver_method_update_activation_environment },
                { "GetNameOwner", driver_method_get_name_owner },
                { "GetConnectionUnixUser", driver_method_get_connection_unix_user },
                { "GetConnectionUnixProcessID", driver_method_get_connection_unix_process_id },
                { "GetConnecitonCredentials", driver_method_get_connection_credentials },
                { "GetAdtAuditSessionData", driver_method_get_adt_audit_session_data },
                { "GetConnectionSELinuxSecurityContext", driver_method_get_connection_selinux_security_context },
                { "AddMatch", driver_method_add_match },
                { "RemoveMatch", driver_method_remove_match },
                { "GetId", driver_method_get_id },
                { "BecomeMonitor", driver_method_become_monitor },
        };

        for (unsigned int i = 0; i < C_ARRAY_SIZE(methods); i++) {
                if (strcmp(methods[i].name, method) == 0)
                        return methods[i].fn(bus, peer, message);
        }

        return 0;
}

/* XXX: this needs access to the bus object */
int driver_handle_message(Peer *peer, DBusMessage *message) {
        return 0;
}

void driver_notify_name_owner_change(const char *name, Peer *old_peer, Peer *new_peer) {
        assert(old_peer || new_peer);
        assert(!old_peer || c_rbnode_is_linked(&old_peer->rb));
        assert(!new_peer || c_rbnode_is_linked(&new_peer->rb));
        assert(name || !old_peer || !new_peer);
}
