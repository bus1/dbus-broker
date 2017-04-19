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

static void sasl_server_send_rejected(SASLServer *sasl, const char **replyp, size_t *lenp) {
        const char *rejected = "REJECTED EXTERNAL";

        sasl->state = SASL_SERVER_STATE_INIT;

        *replyp = rejected;
        *lenp = strlen(rejected);
}

static void sasl_server_send_ok(SASLServer *sasl, const char **replyp, size_t *lenp) {
        sasl->state = SASL_SERVER_STATE_AUTHENTICATED;

        *replyp = sasl->ok_response;
        *lenp = sizeof(sasl->ok_response);
}

static void sasl_server_send_data(SASLServer *sasl, const char **replyp, size_t *lenp) {
        const char *data = "DATA";

        sasl->state = SASL_SERVER_STATE_CHALLENGE;

        *replyp = data;
        *lenp = strlen(data);
}

static void sasl_server_send_error(SASLServer *sasl, const char **replyp, size_t *lenp) {
        const char *error = "ERROR";

        *replyp = error;
        *lenp = strlen(error);
}

static void sasl_server_send_agree_unix_fd(SASLServer *sasl, const char **replyp, size_t *lenp) {
        const char *agree_unix_fd = "AGREE_UNIX_FD";

        sasl->state = SASL_SERVER_STATE_NEGOTIATED_FDS;

        *replyp = agree_unix_fd;
        *lenp = strlen(agree_unix_fd);
}

/*
 * A command should be followed by a space, and optionally by an argumnet.
 * However, we alse accept command that do not have a trailing space, given
 * there are no arguments. We reject commansd that have argumnets even though
 * none are expected.
 */
static bool sasl_server_command_match(const char *command, const char *input, size_t n_input, const char **argumentp, size_t *n_argumentp) {
        const char *argument;
        size_t n_argument;

        if (n_input < strlen(command))
                return false;

        if (strncmp(input, command, strlen(command)) != 0)
                return false;

        argument = input + strlen(command);
        n_argument = n_input - strlen(command);

        if (n_argument == 0) {
                if (argumentp) {
                        *argumentp = NULL;
                        *n_argumentp = 0;
                }
                return true;
        }

        if (*argument != ' ')
                return false;

        ++argument;
        --n_argument;

        if (n_argument == 0) {
                if (argumentp) {
                        *argumentp = NULL;
                        *n_argumentp = 0;
                }

                return true;
        }

        if (argumentp) {
                *argumentp = argument;
                *n_argumentp = n_argument;

                return true;
        }

        return false;
}

static int sasl_server_handle_data(SASLServer *sasl, const char *input, size_t n_input, const char **replyp, size_t *lenp) {
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
                        sasl_server_send_rejected(sasl, replyp, lenp);
                        return 0;
                }
        }

        sasl_server_send_ok(sasl, replyp, lenp);
        return 0;
}

static int sasl_server_handle_auth(SASLServer *sasl, const char *input, size_t n_input, const char **replyp, size_t *lenp) {
        const char *data;
        size_t n_data;

        if (!input) {
                sasl_server_send_rejected(sasl, replyp, lenp);
                return 0;
        }

        if (sasl_server_command_match("EXTERNAL", input, n_input, &data, &n_data)) {
                if (data)
                        return sasl_server_handle_data(sasl, data, n_data, replyp, lenp);
                else {
                        sasl_server_send_data(sasl, replyp, lenp);
                        return 0;
                }
        } else {
                sasl_server_send_rejected(sasl, replyp, lenp);
                return 0;
        }
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
                        sasl_server_send_rejected(sasl, outputp, n_outputp);
                } else if (n_cmd == strlen("BEGIN") && !strncmp(cmd, "BEGIN", n_cmd) && !n_arg) {
                        return SASL_E_FAILURE;
                } else {
                        sasl_server_send_error(sasl, outputp, n_outputp);
                }

                break;

        case SASL_SERVER_STATE_CHALLENGE:
                if (n_cmd == strlen("DATA") && !strncmp(cmd, "DATA", n_cmd)) {
                        return sasl_server_handle_data(sasl, arg, n_arg, outputp, n_outputp);
                } else if ((n_cmd == strlen("ERROR") && !strncmp(cmd, "ERROR", n_cmd)) ||
                           (n_cmd == strlen("CANCEL") && !strncmp(cmd, "CANCEL", n_cmd) && !n_arg)) {
                        sasl_server_send_rejected(sasl, outputp, n_outputp);
                } else if (n_cmd == strlen("BEGIN") && !strncmp(cmd, "BEGIN", n_cmd) && !n_arg) {
                        return SASL_E_FAILURE;
                } else {
                        sasl_server_send_error(sasl, outputp, n_outputp);
                }

                break;

        case SASL_SERVER_STATE_AUTHENTICATED:
        case SASL_SERVER_STATE_NEGOTIATED_FDS:
                if (n_cmd == strlen("NEGOTIATE_UNIX_FD") && !strncmp(cmd, "NEGOTIATE_UNIX_FD", n_cmd) && !n_arg) {
                        sasl_server_send_agree_unix_fd(sasl, outputp, n_outputp);
                } else if (n_cmd == strlen("BEGIN") && !strncmp(cmd, "BEGIN", n_cmd) && !n_arg) {
                        return 1;
                } else if ((n_cmd == strlen("ERROR") && !strncmp(cmd, "ERROR", n_cmd)) ||
                           (n_cmd == strlen("CANCEL") && !strncmp(cmd, "CANCEL", n_cmd) && !n_arg)) {
                        sasl_server_send_rejected(sasl, outputp, n_outputp);
                } else {
                        sasl_server_send_error(sasl, outputp, n_outputp);
                }

                break;

        default:
                assert(0);
                return -ENOTRECOVERABLE;
        }

        return 0;
}
