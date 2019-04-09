#pragma once

/*
 * Server-Side SASL Parser
 */

#include <c-stdaux.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct SASLClient SASLClient;
typedef struct SASLServer SASLServer;

enum {
        _SASL_E_SUCCESS,

        SASL_E_FAILURE,
        SASL_E_PROTOCOL_VIOLATION,
};

/* client */

enum {
        SASL_CLIENT_STATE_INIT,
        SASL_CLIENT_STATE_DONE,
        SASL_CLIENT_STATE_AUTH,
        SASL_CLIENT_STATE_DATA,
        SASL_CLIENT_STATE_UNIX_FD,
};

struct SASLClient {
        unsigned int state;
};

#define SASL_CLIENT_NULL {}

void sasl_client_init(SASLClient *sasl);
void sasl_client_deinit(SASLClient *sasl);

int sasl_client_dispatch(SASLClient *sasl, const char *input, size_t n_input, const char **outputp, size_t *n_outputp);

C_DEFINE_CLEANUP(SASLClient *, sasl_client_deinit);

/* server */

enum {
        SASL_SERVER_STATE_INIT,
        SASL_SERVER_STATE_DONE,
        SASL_SERVER_STATE_AUTH,
        SASL_SERVER_STATE_CHALLENGE,
        SASL_SERVER_STATE_AUTHENTICATED,
        SASL_SERVER_STATE_NEGOTIATED_FDS,
};

struct SASLServer {
        unsigned int state;
        bool fds_allowed;
        uid_t uid;
        char ok_response[sizeof("OK 0123456789abcdef0123456789abdcef") - 1];
};

#define SASL_SERVER_NULL {}

void sasl_server_init(SASLServer *sasl, uid_t uid, const char *guid);
void sasl_server_deinit(SASLServer *sasl);

int sasl_server_dispatch(SASLServer *sasl, const char *input, size_t n_input, const char **outputp, size_t *n_outputp);

C_DEFINE_CLEANUP(SASLServer *, sasl_server_deinit);

/* inline helpers */

static inline bool sasl_client_is_done(SASLClient *client) {
        return _c_likely_(client->state == SASL_CLIENT_STATE_DONE);
}

static inline bool sasl_server_is_done(SASLServer *server) {
        return _c_likely_(server->state == SASL_SERVER_STATE_DONE);
}
