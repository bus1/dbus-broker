#pragma once

/*
 * DBus Driver
 */

#include <c-stdaux.h>
#include <stdlib.h>

typedef struct Bus Bus;
typedef struct MatchOwner MatchOwner;
typedef struct Message Message;
typedef struct Peer Peer;
typedef struct User User;

enum {
        _DRIVER_E_SUCCESS,

        DRIVER_E_UNIMPLEMENTED,

        DRIVER_E_PEER_ALREADY_REGISTERED,
        DRIVER_E_PEER_NOT_YET_REGISTERED,
        DRIVER_E_PEER_NOT_REGISTERED,
        DRIVER_E_PEER_NOT_PRIVILEGED,

        DRIVER_E_MONITOR_READ_ONLY,

        DRIVER_E_UNEXPECTED_FDS,
        DRIVER_E_UNEXPECTED_MESSAGE_TYPE,
        DRIVER_E_UNEXPECTED_PATH,
        DRIVER_E_UNEXPECTED_INTERFACE,
        DRIVER_E_UNEXPECTED_METHOD,
        DRIVER_E_UNEXPECTED_PROPERTY,
        DRIVER_E_READONLY_PROPERTY,
        DRIVER_E_UNEXPECTED_SIGNATURE,
        DRIVER_E_UNEXPECTED_REPLY,

        DRIVER_E_FORWARD_FAILED,

        DRIVER_E_QUOTA,

        DRIVER_E_UNEXPECTED_FLAGS,
        DRIVER_E_UNEXPECTED_ENVIRONMENT_UPDATE,

        DRIVER_E_SEND_DENIED,
        DRIVER_E_RECEIVE_DENIED,
        DRIVER_E_EXPECTED_REPLY_EXISTS,

        DRIVER_E_NAME_RESERVED,
        DRIVER_E_NAME_UNIQUE,
        DRIVER_E_NAME_INVALID,
        DRIVER_E_NAME_REFUSED,
        DRIVER_E_NAME_NOT_FOUND,
        DRIVER_E_NAME_NOT_ACTIVATABLE,
        DRIVER_E_NAME_OWNER_NOT_FOUND,
        DRIVER_E_PEER_NOT_FOUND,
        DRIVER_E_DESTINATION_NOT_FOUND,

        DRIVER_E_MATCH_INVALID,
        DRIVER_E_MATCH_NOT_FOUND,

        DRIVER_E_ADT_NOT_SUPPORTED,
        DRIVER_E_SELINUX_NOT_SUPPORTED,

        _DRIVER_E_MAX,
};

int driver_name_activation_failed(Bus *bus, Activation *activation, uint64_t serial, unsigned int name_error);
int driver_reload_config_completed(Bus *bus, uint64_t sender_id, uint32_t reply_serial);
int driver_reload_config_invalid(Bus *bus, uint64_t sender_id, uint32_t reply_serial);

int driver_dispatch(Peer *peer, Message *message);
int driver_goodbye(Peer *peer, bool silent);
