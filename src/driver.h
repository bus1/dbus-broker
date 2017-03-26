#pragma once

/*
 * DBus Driver
 */

#include <stdlib.h>
#include "peer.h"

typedef struct DBusMessage DBusMessage;
typedef struct Peer Peer;

int driver_method_hello(Bus *bus, Peer *peer, DBusMessage *message);
int driver_method_list_names(Bus *bus, Peer *peer, DBusMessage *message);
int driver_method_list_activatable_names(Bus *bus, Peer *peer, DBusMessage *message);
int driver_method_name_has_owner(Bus *bus, Peer *peer, DBusMessage *message);
int driver_method_start_service_by_name(Bus *bus, Peer *peer, DBusMessage *message);
int driver_method_update_activation_environment(Bus *bus, Peer *peer, DBusMessage *message);
int driver_method_get_name_owner(Bus *bus, Peer *peer, DBusMessage *message);
int driver_method_get_connection_unix_user(Bus *bus, Peer *peer, DBusMessage *message);
int driver_method_get_connection_unix_process_id(Bus *bus, Peer *peer, DBusMessage *message);
int driver_method_get_connection_credentials(Bus *bus, Peer *peer, DBusMessage *message);
int driver_method_get_adt_audit_session_data(Bus *bus, Peer *peer, DBusMessage *message);
int driver_method_get_connection_selinux_security_context(Bus *bus, Peer *peer, DBusMessage *message);
int driver_method_add_match(Bus *bus, Peer *peer, DBusMessage *message);
int driver_method_remove_match(Bus *bus, Peer *peer, DBusMessage *message);
int driver_method_get_id(Bus *bus, Peer *peer, DBusMessage *message);
int driver_method_become_monitor(Bus *bus, Peer *peer, DBusMessage *message);

int driver_dispatch_method(Bus *bus, Peer *peer, const char *method, DBusMessage *message);

void driver_notify_name_owner_change(const char *name, Peer *old_peer, Peer *new_peer);
