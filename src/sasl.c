/*
 * Server-Side SASL Parser
 *
 * This wraps the SASL state machine. Only the EXTERNAL mechanism is supported.
 * The broker knows the UID of a peer from the peer credentials obtained from its
 * socket, which is used for authenticating. For the purposes of the broker SASL
 * is a no-op needed only for compatibility.
 *
 * The SASL exchange does not need to be synchronous, so a client can typically
 * implement SASL by simply prepending the string
 *   "\0AUTH EXTERNAL\r\nDATA\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n"
 * to the first message it sends, and discarding the first
 *   strlen("DATA\r\nOK 0123456789abcdef0123456789abcdef\r\nAGREE_UNIX_FD\r\n")
 * bytes from the beginning of the first message it receives.
 */

#include <c-macro.h>
#include <c-string.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "sasl.h"

static void sasl_split(const char *input, size_t n_input,
                       const char **cmd, size_t *n_cmd,
                       const char **arg, size_t *n_arg) {
        /*
         * Split @cmd into a command and argument. This splits after the
         * first occurrence of whitespace characters. If the argument is empty
         * it is treated as non-existant (which is what legacy D-Bus
         * applications expect).
         */

        *cmd = input;
        *arg = memchr(input, ' ', n_input);

        if (*arg) {
                *n_cmd = *arg - input;
                *n_arg = n_input - *n_cmd;

                do {
                        ++*arg;
                        --*n_arg;
                } while (*n_arg && **arg == ' ');
        } else {
                *n_cmd = n_input;
                *n_arg = 0;
        }
}

void sasl_client_init(SASLClient *sasl) {
        sasl->state = SASL_CLIENT_STATE_INIT;
}

void sasl_client_deinit(SASLClient *sasl) {
        /* nothing to do */
}

int sasl_client_dispatch(SASLClient *sasl, const char *input, size_t n_input, const char **outputp, size_t *n_outputp) {
        static const char request[] = {
                "AUTH EXTERNAL\r\n"
                "DATA\r\n"
                "NEGOTIATE_UNIX_FD\r\n"
                "BEGIN"
        };
        const char *cmd, *arg;
        size_t n_cmd, n_arg;

        sasl_split(input, n_input, &cmd, &n_cmd, &arg, &n_arg);

        switch (sasl->state) {
        case SASL_CLIENT_STATE_INIT:
                if (cmd)
                        return SASL_E_PROTOCOL_VIOLATION;

                *outputp = request;
                *n_outputp = sizeof(request) - 1;

                sasl->state = SASL_CLIENT_STATE_AUTH;
                break;

        case SASL_CLIENT_STATE_AUTH:
                if (!cmd)
                        break;

                if (n_cmd != strlen("DATA") || strncmp(cmd, "DATA", n_cmd))
                        return SASL_E_FAILURE;
                if (n_arg)
                        return SASL_E_PROTOCOL_VIOLATION;

                sasl->state = SASL_CLIENT_STATE_DATA;
                break;

        case SASL_CLIENT_STATE_DATA:
                if (!cmd)
                        break;

                if (n_cmd != strlen("OK") || strncmp(cmd, "OK", n_cmd))
                        return SASL_E_FAILURE;
                if (n_arg != strlen("0123456789abcdef0123456789abcdef"))
                        return SASL_E_PROTOCOL_VIOLATION;

                sasl->state = SASL_CLIENT_STATE_UNIX_FD;
                break;

        case SASL_CLIENT_STATE_UNIX_FD:
                if (!cmd)
                        break;

                if (n_cmd != strlen("AGREE_UNIX_FD") || strncmp(cmd, "AGREE_UNIX_FD", n_cmd))
                        return SASL_E_FAILURE;
                if (n_arg)
                        return SASL_E_PROTOCOL_VIOLATION;

                sasl->state = SASL_CLIENT_STATE_DONE;
                break;

        default:
                assert(0);
                return -ENOTRECOVERABLE;
        }

        return 0;
}

void sasl_server_init(SASLServer *sasl, uid_t uid, const char *guid) {
        *sasl = (SASLServer){};
        sasl->uid = uid;
        sasl->ok_response[0] = 'O';
        sasl->ok_response[1] = 'K';
        sasl->ok_response[2] = ' ';
        c_string_to_hex(guid, 16, &sasl->ok_response[3]);
};

void sasl_server_deinit(SASLServer *sasl) {
        *sasl = (SASLServer){};
};

static int sasl_server_handle_data(SASLServer *sasl, const char *input, size_t n_input, const char **outputp, size_t *n_outputp) {
        char hexbuf[2 * C_DECIMAL_MAX(uint32_t) + 1];
        char uidbuf[C_DECIMAL_MAX(uint32_t) + 1];
        int n;

        /*
         * The EXTERNAL mechanism requires the UID to authenticate as as
         * argument. If omitted, the server deduces the UID from the socket, in
         * which case we rely on the kernel to verify its correctness.
         */
        if (n_input) {
                n = snprintf(uidbuf, sizeof(uidbuf), "%" PRIu32, sasl->uid);
                assert(n >= 0 && n < sizeof(uidbuf));

                c_string_to_hex(uidbuf, n, hexbuf);
                if (n_input != 2 * n || memcmp(input, hexbuf, 2 * n)) {
                        *outputp = "REJECTED EXTERNAL";
                        *n_outputp = strlen("REJECTED EXTERNAL");
                        sasl->state = SASL_SERVER_STATE_INIT;
                        return 0;
                }
        }

        *outputp = sasl->ok_response;
        *n_outputp = sizeof(sasl->ok_response);
        sasl->state = SASL_SERVER_STATE_AUTHENTICATED;

        return 0;
}

static int sasl_server_handle_auth(SASLServer *sasl, const char *input, size_t n_input, const char **outputp, size_t *n_outputp) {
        const char *protocol, *arg;
        size_t n_protocol, n_arg;

        sasl_split(input, n_input, &protocol, &n_protocol, &arg, &n_arg);

        if (n_protocol == strlen("EXTERNAL") && !strncmp(protocol, "EXTERNAL", n_protocol)) {
                if (n_arg)
                        return sasl_server_handle_data(sasl, arg, n_arg, outputp, n_outputp);

                *outputp = "DATA";
                *n_outputp = strlen("DATA");
                sasl->state = SASL_SERVER_STATE_CHALLENGE;
        } else {
                *outputp = "REJECTED EXTERNAL";
                *n_outputp = strlen("REJECTED EXTERNAL");
                sasl->state = SASL_SERVER_STATE_INIT;
        }

        return 0;
}

int sasl_server_dispatch(SASLServer *sasl, const char *input, size_t n_input, const char **outputp, size_t *n_outputp) {
        const char *cmd, *arg;
        size_t n_cmd, n_arg;

        sasl_split(input, n_input, &cmd, &n_cmd, &arg, &n_arg);

        switch (sasl->state) {
        case SASL_SERVER_STATE_INIT:
                if (n_cmd == strlen("AUTH") && !strncmp(cmd, "AUTH", n_cmd)) {
                        return sasl_server_handle_auth(sasl, arg, n_arg, outputp, n_outputp);
                } else if (n_cmd == strlen("ERROR") && !strncmp(cmd, "ERROR", n_cmd)) {
                        *outputp = "REJECTED EXTERNAL";
                        *n_outputp = strlen("REJECTED EXTERNAL");
                        sasl->state = SASL_SERVER_STATE_INIT;
                } else if (n_cmd == strlen("BEGIN") && !strncmp(cmd, "BEGIN", n_cmd) && !n_arg) {
                        return SASL_E_FAILURE;
                } else {
                        *outputp = "ERROR";
                        *n_outputp = strlen("ERROR");
                }

                break;

        case SASL_SERVER_STATE_CHALLENGE:
                if (n_cmd == strlen("DATA") && !strncmp(cmd, "DATA", n_cmd)) {
                        return sasl_server_handle_data(sasl, arg, n_arg, outputp, n_outputp);
                } else if ((n_cmd == strlen("ERROR") && !strncmp(cmd, "ERROR", n_cmd)) ||
                           (n_cmd == strlen("CANCEL") && !strncmp(cmd, "CANCEL", n_cmd) && !n_arg)) {
                        *outputp = "REJECTED EXTERNAL";
                        *n_outputp = strlen("REJECTED EXTERNAL");
                        sasl->state = SASL_SERVER_STATE_INIT;
                } else if (n_cmd == strlen("BEGIN") && !strncmp(cmd, "BEGIN", n_cmd) && !n_arg) {
                        return SASL_E_FAILURE;
                } else {
                        *outputp = "ERROR";
                        *n_outputp = strlen("ERROR");
                }

                break;

        case SASL_SERVER_STATE_AUTHENTICATED:
        case SASL_SERVER_STATE_NEGOTIATED_FDS:
                if (n_cmd == strlen("NEGOTIATE_UNIX_FD") && !strncmp(cmd, "NEGOTIATE_UNIX_FD", n_cmd) && !n_arg) {
                        *outputp = "AGREE_UNIX_FD";
                        *n_outputp = strlen("AGREE_UNIX_FD");
                        sasl->state = SASL_SERVER_STATE_NEGOTIATED_FDS;
                } else if (n_cmd == strlen("BEGIN") && !strncmp(cmd, "BEGIN", n_cmd) && !n_arg) {
                        return 1;
                } else if ((n_cmd == strlen("ERROR") && !strncmp(cmd, "ERROR", n_cmd)) ||
                           (n_cmd == strlen("CANCEL") && !strncmp(cmd, "CANCEL", n_cmd) && !n_arg)) {
                        *outputp = "REJECTED EXTERNAL";
                        *n_outputp = strlen("REJECTED EXTERNAL");
                        sasl->state = SASL_SERVER_STATE_INIT;
                } else {
                        *outputp = "ERROR";
                        *n_outputp = strlen("ERROR");
                }

                break;

        default:
                assert(0);
                return -ENOTRECOVERABLE;
        }

        return 0;
}
