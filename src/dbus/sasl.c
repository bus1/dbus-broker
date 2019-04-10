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

#include <c-stdaux.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "dbus/sasl.h"
#include "util/error.h"
#include "util/string.h"

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
        /* memchr(NULL, ..) is UB */
        *arg = !n_input ? NULL : memchr(input, ' ', n_input);

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

/**
 * sasl_client_init() - initialize SASL client
 * @sasl:               the client to operate on
 *
 * This initializes the SASL client object @sasl.
 */
void sasl_client_init(SASLClient *sasl) {
        sasl->state = SASL_CLIENT_STATE_INIT;
}

/**
 * sasl_client_deinit() - deinitialize SASL client
 * @sasl:               the client to operate on
 *
 * This deinitializes the SASL client object @sasl. It is safe to call deinit several times.
 */
void sasl_client_deinit(SASLClient *sasl) {
        *sasl = (SASLClient){};
}

/**
 * sasl_client_dispatch() - dispatch SASL client
 * @sasl:               the client to dispatch
 * @input:              the input to consume
 * @n_input:            the length of the input
 * @outputp:            return pointer to the output
 * @n_outputp:          return pointer to the size of the output
 *
 * This dispatches the SASL object, consuming the given input string and providing a pointer to
 * an output string to send, if applicable. Neither input nor output strings are nul-terminated.
 *
 * We hardcode the EXTERNAL mechanism, relying on the UDS providing the credentials, so not
 * attaching them ourselves. Note that we do not necessarily know the UID the remote end will
 * see us as, in the case of crossing a namespace boundary, so providing an UID is not
 * straight-forward. We also hard-code the requirement for unix FD support.
 *
 * If either the EXTERNAL mechanism or FD support is not supported by the remote side, we fail
 * the negotiation, we do not fall back to anything else.
 *
 * Return: SASL_E_FAILURE if the server did not support what we requested,
 *         SASL_E_PROTOCOL_VIOLATION if the server violated the protocol, or
 *         0 on success.
 */
int sasl_client_dispatch(SASLClient *sasl, const char *input, size_t n_input, const char **outputp, size_t *n_outputp) {
        static const char request[] = {
                "\0AUTH EXTERNAL\r\n"
                "DATA\r\n"
                "NEGOTIATE_UNIX_FD\r\n"
                "BEGIN"
        };
        const char *cmd, *arg, *output = NULL;
        size_t n_cmd, n_arg, n_output = 0;

        sasl_split(input, n_input, &cmd, &n_cmd, &arg, &n_arg);

        switch (sasl->state) {
        case SASL_CLIENT_STATE_INIT:
                if (cmd)
                        return SASL_E_PROTOCOL_VIOLATION;

                output = request;
                n_output = sizeof(request) - 1;

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
                return error_origin(-ENOTRECOVERABLE);
        }

        *outputp = output;
        *n_outputp = n_output;
        return 0;
}

/**
 * sasl_server_init() - initialize SASL server
 * @sasl:               the server to operate on
 * @uid:                the UID of the connecting client
 * @guid:               the GUID associated with the listening socket
 *
 * This initializes the SASL server object @sasl, for authenticating with UID
 * @uid. The GUID @guid is used to identify the connection. This should be
 * unique per listening socket, but shared beteewn all connections to the same
 * socket.
 */
void sasl_server_init(SASLServer *sasl, uid_t uid, const char *guid) {
        *sasl = (SASLServer){};
        sasl->uid = uid;
        sasl->ok_response[0] = 'O';
        sasl->ok_response[1] = 'K';
        sasl->ok_response[2] = ' ';
        string_to_hex(guid, 16, &sasl->ok_response[3]);
};

/**
 * sasl_server_deinit() - deinitialize SASL server
 * @sasl:               the server to operate on
 *
 * This deinitializes the SASL server object @sasl. It is safe to call deinit several times.
 */
void sasl_server_deinit(SASLServer *sasl) {
        *sasl = (SASLServer){};
};

static void sasl_server_handle_data(SASLServer *sasl, const char *input, size_t n_input, const char **outputp, size_t *n_outputp) {
        char hexbuf[2 * C_DECIMAL_MAX(uint32_t) + 1];
        char uidbuf[C_DECIMAL_MAX(uint32_t) + 1];
        bool failed = false;
        int n;

        /*
         * The EXTERNAL mechanism requires the UID to authenticate as as
         * argument. If omitted, the server deduces the UID from the socket, in
         * which case we rely on the kernel to verify its correctness.
         */
        if (n_input) {
                n = snprintf(uidbuf, sizeof(uidbuf), "%" PRIu32, sasl->uid);
                c_assert(n >= 0 && (size_t)n < sizeof(uidbuf));

                string_to_hex(uidbuf, n, hexbuf);
                if (n_input != 2 * (size_t)n || memcmp(input, hexbuf, 2 * n))
                        failed = true;
        }

        if (failed) {
                *outputp = "REJECTED EXTERNAL";
                *n_outputp = strlen("REJECTED EXTERNAL");
                sasl->state = SASL_SERVER_STATE_AUTH;
        } else {
                *outputp = sasl->ok_response;
                *n_outputp = sizeof(sasl->ok_response);
                sasl->state = SASL_SERVER_STATE_AUTHENTICATED;
        }
}

static void sasl_server_handle_auth(SASLServer *sasl, const char *input, size_t n_input, const char **outputp, size_t *n_outputp) {
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
                sasl->state = SASL_SERVER_STATE_AUTH;
        }
}

/**
 * sasl_server_dispatch() - dispatch SASL server
 * @sasl:               the server to dispatch
 * @input:              the input to consume
 * @n_input:            the length of the input
 * @outputp:            return pointer to the output
 * @n_outputp:          return pointer to the size of the output
 *
 * This dispatches the SASL object, consuming the given input string and providing a pointer to
 * an output string to send, if applicable. Neither input nor output strings are nul-terminated.
 *
 * Only the EXTERNAL mechanism is supported, so if the client tries to use anything else, we
 * reject that and inform them that only EXTERNAL is supported. If the client provides their
 * UID, then we verify that this is as expected, but if it is ommitted, we use the expected
 * one.
 *
 * We will optionally allow unix FD support to be negotiated if the client requests that.
 *
 * Note that even though each output string has a fixed size, the server will potentially
 * produce an unbounded amount of output over all, as it will only terminate the exchange
 * in case it succeeded or the protocol was violated.
 *
 * Return: SASL_E_PROTOCOL_VIOLATION if the client violated the protocol, or 0 on success.
 */
int sasl_server_dispatch(SASLServer *sasl, const char *input, size_t n_input, const char **outputp, size_t *n_outputp) {
        const char *cmd, *arg;
        size_t n_cmd, n_arg;

        sasl_split(input, n_input, &cmd, &n_cmd, &arg, &n_arg);

        switch (sasl->state) {
        case SASL_SERVER_STATE_INIT:
                /* first byte must be the zero-byte */
                if (n_cmd < 1 || *cmd)
                        return SASL_E_PROTOCOL_VIOLATION;

                --n_cmd;
                ++cmd;
                /* fallthrough */
        case SASL_SERVER_STATE_AUTH:
                if (n_cmd == strlen("AUTH") && !strncmp(cmd, "AUTH", n_cmd)) {
                        sasl_server_handle_auth(sasl, arg, n_arg, outputp, n_outputp);
                } else if (n_cmd == strlen("ERROR") && !strncmp(cmd, "ERROR", n_cmd)) {
                        *outputp = "REJECTED EXTERNAL";
                        *n_outputp = strlen("REJECTED EXTERNAL");
                        sasl->state = SASL_SERVER_STATE_AUTH;
                } else if (n_cmd == strlen("BEGIN") && !strncmp(cmd, "BEGIN", n_cmd) && !n_arg) {
                        return SASL_E_PROTOCOL_VIOLATION;
                } else {
                        *outputp = "ERROR";
                        *n_outputp = strlen("ERROR");
                }

                break;

        case SASL_SERVER_STATE_CHALLENGE:
                if (n_cmd == strlen("DATA") && !strncmp(cmd, "DATA", n_cmd)) {
                        sasl_server_handle_data(sasl, arg, n_arg, outputp, n_outputp);
                } else if ((n_cmd == strlen("ERROR") && !strncmp(cmd, "ERROR", n_cmd)) ||
                           (n_cmd == strlen("CANCEL") && !strncmp(cmd, "CANCEL", n_cmd) && !n_arg)) {
                        *outputp = "REJECTED EXTERNAL";
                        *n_outputp = strlen("REJECTED EXTERNAL");
                        sasl->state = SASL_SERVER_STATE_AUTH;
                } else if (n_cmd == strlen("BEGIN") && !strncmp(cmd, "BEGIN", n_cmd) && !n_arg) {
                        return SASL_E_PROTOCOL_VIOLATION;
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
                        sasl->fds_allowed = true;
                        sasl->state = SASL_SERVER_STATE_NEGOTIATED_FDS;
                } else if (n_cmd == strlen("BEGIN") && !strncmp(cmd, "BEGIN", n_cmd) && !n_arg) {
                        *outputp = NULL;
                        *n_outputp = 0;
                        sasl->state = SASL_SERVER_STATE_DONE;
                } else if ((n_cmd == strlen("ERROR") && !strncmp(cmd, "ERROR", n_cmd)) ||
                           (n_cmd == strlen("CANCEL") && !strncmp(cmd, "CANCEL", n_cmd) && !n_arg)) {
                        *outputp = "REJECTED EXTERNAL";
                        *n_outputp = strlen("REJECTED EXTERNAL");
                        sasl->fds_allowed = false;
                        sasl->state = SASL_SERVER_STATE_AUTH;
                } else {
                        *outputp = "ERROR";
                        *n_outputp = strlen("ERROR");
                }

                break;

        default:
                return error_origin(-ENOTRECOVERABLE);
        }

        return 0;
}
