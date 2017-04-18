#pragma once

/*
 * Server-Side SASL Parser
 */

#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct SASLServer SASLServer;
typedef enum SASLServerState SASLServerState;

enum SASLServerState {
        SASL_SERVER_STATE_INIT,
        SASL_SERVER_STATE_CHALLENGE,
        SASL_SERVER_STATE_AUTHENTICATED,
        SASL_SERVER_STATE_NEGOTIATED_FDS,
};

struct SASLServer {
        SASLServerState state;
        uid_t uid;
        char ok_response[sizeof("OK 0123456789abcdef0123456789abdcef") - 1];
};

void sasl_server_init(SASLServer *sasl, uid_t uid, const char *guid);
void sasl_server_deinit(SASLServer *sasl);

int sasl_server_dispatch(SASLServer *sasl, const char *input, size_t n_input, const char **outputp, size_t *n_outputp);
