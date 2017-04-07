#pragma once

/*
 * DBus SASL Parser
 */

#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>

/* the longest reply line is "OK 0123456789abcdef0123456789abdcef\r\n" */
#define DBUS_SASL_MAX_OUT_LINE_LENGTH (37)

typedef struct DBusSASL DBusSASL;
typedef enum DBusSASLState DBusSASLState;

enum DBusSASLState {
        DBUS_SASL_STATE_INIT,
        DBUS_SASL_STATE_CHALLENGE,
        DBUS_SASL_STATE_AUTHENTICATED,
        DBUS_SASL_STATE_NEGOTIATED_FDS,
};

struct DBusSASL {
        DBusSASLState state;
        uid_t uid;
        char ok_response[DBUS_SASL_MAX_OUT_LINE_LENGTH];
};

void dbus_sasl_init(DBusSASL *sasl, uid_t uid, char *guid);
void dbus_sasl_deinit(DBusSASL *sasl);

int dbus_sasl_dispatch(DBusSASL *sasl,
                       char *input,
                       char *buffer,
                       size_t *posp);
