#pragma once

/*
 * DBus SASL Parser
 */

#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct SASL SASL;
typedef enum SASLState SASLState;

enum SASLState {
        SASL_STATE_INIT,
        SASL_STATE_CHALLENGE,
        SASL_STATE_AUTHENTICATED,
        SASL_STATE_NEGOTIATED_FDS,
};

struct SASL {
        SASLState state;
        uid_t uid;
        char ok_response[sizeof("OK 0123456789abcdef0123456789abdcef") - 1];
};

void sasl_init(SASL *sasl, uid_t uid, const char *guid);
void sasl_deinit(SASL *sasl);

int sasl_dispatch(SASL *sasl, const char *input, size_t n_input, const char **outputp, size_t *n_outputp);
