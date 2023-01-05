#pragma once

#include <stdlib.h>
#include "broker/broker.h"

#define LINE_LENGTH_MAX 51200
#define FD_LENGTH_MAX 12
#define PID_LENGTH_MAX 12
#define UID_LENGTH_MAX 12
#define ID_LENGTH_MAX 21
#define SASL_ELEMENT_LENGTH_MAX 5
#define SASL_LENGTH_MAX 20
#define NAME_LENGTH_MAX 256

enum {
        PEER_INDEX_FD,
        PEER_INDEX_ID,
        PEER_INDEX_PID,
        PEER_INDEX_UID,
        PEER_INDEX_NAME,
        PEER_INDEX_MATCH_RULE,
        PEER_INDEX_SASL,
        _PEER_INDEX_MAX,
};

enum {
        SASL_INDEX_SERVER_STATE,
        SASL_INDEX_SERVER_FDSALLOWED,
        SASL_INDEX_CLIENT_STATE,
        _SASL_INDEX_MAX,
};

int state_file_init(FILE **ret);
int serialize_basic(FILE *f, char *key, const char *format, ...);
int serialize_peers(FILE *f, Broker *broker);
