#pragma once

/*
 * DBus Driver
 */

#include <stdlib.h>

typedef struct Message Message;
typedef struct Peer Peer;

int driver_method_hello(Peer *peer, const char *signature, Message *message);
int driver_method_list_names(Peer *peer, const char *signature, Message *message);
int driver_method_list_activatable_names(Peer *peer, const char *signature, Message *message);
int driver_method_name_has_owner(Peer *peer, const char *signature, Message *message);
int driver_method_start_service_by_name(Peer *peer, const char *signature, Message *message);
int driver_method_update_activation_environment(Peer *peer, const char *signature, Message *message);
int driver_method_get_name_owner(Peer *peer, const char *signature, Message *message);
int driver_method_get_connection_unix_user(Peer *peer, const char *signature, Message *message);
int driver_method_get_connection_unix_process_id(Peer *peer, const char *signature, Message *message);
int driver_method_get_connection_credentials(Peer *peer, const char *signature, Message *message);
int driver_method_get_adt_audit_session_data(Peer *peer, const char *signature, Message *message);
int driver_method_get_connection_selinux_security_context(Peer *peer, const char *signature, Message *message);
int driver_method_add_match(Peer *peer, const char *signature, Message *message);
int driver_method_remove_match(Peer *peer, const char *signature, Message *message);
int driver_method_get_id(Peer *peer, const char *signature, Message *message);
int driver_method_become_monitor(Peer *peer, const char *signature, Message *message);

int driver_handle_message(Peer *peer, Message *message);

void driver_notify_name_owner_change(const char *name, Peer *old_peer, Peer *new_peer);
