#pragma once

/*
 * Broker Controller
 */

#include <stdlib.h>

typedef struct Bus Bus;
typedef struct Connection Connection;
typedef struct Message Message;

enum {
        _CONTROLLER_E_SUCCESS,

        CONTROLLER_E_DISCONNECT,

        CONTROLLER_E_INVALID_MESSAGE,

        CONTROLLER_E_UNEXPECTED_MESSAGE_TYPE,
        CONTROLLER_E_UNEXPECTED_PATH,
        CONTROLLER_E_UNEXPECTED_INTERFACE,
        CONTROLLER_E_UNEXPECTED_METHOD,
        CONTROLLER_E_UNEXPECTED_SIGNATURE,
        CONTROLLER_E_UNEXPECTED_REPLY,
};

int controller_dispatch(Bus *bus, Connection *connection, Message *message);
