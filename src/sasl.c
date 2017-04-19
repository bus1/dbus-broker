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

        /*
         * Split @input into a command and argument. This splits after the
         * first occurrence of whitespace characters. If the argument is empty
         * it is treated as non-existant (which is what legacy D-Bus
         * applications expect).
         */
        n_cmd = n_input;
        n_arg = 0;
        cmd = input;
        arg = memchr(input, ' ', n_input);
        if (arg) {
                n_cmd = arg - cmd;
                n_arg = n_input - n_cmd;

                do {
                        ++arg;
                        --n_arg;
                } while (n_arg && *arg == ' ');
        }

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

static int uid_from_hexstring(const char *hex, size_t n_hex, uid_t *uidp) {
        char uid_string[C_DECIMAL_MAX(uid_t)];
        char *end;
        unsigned long uid = 0;
        bool valid;

        if (n_hex / 2 > sizeof(uid_string))
                return -EBADMSG;

        valid = c_string_from_hex(uid_string, n_hex / 2, hex);
        if (!valid)
                return -EBADMSG;

        uid_string[n_hex / 2] = '\0';

        if (uid_string[0] == '-')
                return -EBADMSG;

        errno = 0;
        uid = strtoul(uid_string, &end, 10);
        if (errno != 0)
                return -errno;
        if (*end || uid_string == end)
                return -EBADMSG;
        if ((unsigned long)(long) uid != uid)
                return -EBADMSG;

        *uidp = uid;
        return 0;
}

static int sasl_server_handle_data(SASLServer *sasl, const char *input, size_t n_input, const char **replyp, size_t *lenp) {
        uid_t uid;
        int r;

        if (!input) {
                /* for the EXTERNAL mechanism data is optional */
                sasl_server_send_ok(sasl, replyp, lenp);
                return 0;
        }

        /* if data was provided it must be valid and match what we expect */
        r = uid_from_hexstring(input, n_input, &uid);
        if (r < 0) {
                sasl_server_send_error(sasl, replyp, lenp);
                return 0;
        }

        if (uid == sasl->uid)
                sasl_server_send_ok(sasl, replyp, lenp);
        else
                sasl_server_send_rejected(sasl, replyp, lenp);

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

int sasl_server_dispatch_init(SASLServer *sasl, const char *input, size_t n_input, const char **replyp, size_t *lenp) {
        const char *argument;
        size_t n_argument;

        if (sasl_server_command_match("AUTH", input, n_input, &argument, &n_argument))
                return sasl_server_handle_auth(sasl, argument, n_argument, replyp, lenp);
        else if (sasl_server_command_match("ERROR", input, n_input, &argument, &n_argument))
                sasl_server_send_rejected(sasl, replyp, lenp);
        else if (sasl_server_command_match("BEGIN", input, n_input, NULL, NULL))
                return -EBADMSG;
        else
                sasl_server_send_error(sasl, replyp, lenp);

        return 0;
}

int sasl_server_dispatch_challenge(SASLServer *sasl, const char *input, size_t n_input, const char **replyp, size_t *lenp) {
        const char *argument;
        size_t n_argument;

        if (sasl_server_command_match("DATA", input, n_input, &argument, &n_argument))
                return sasl_server_handle_data(sasl, argument, n_argument, replyp, lenp);
        else if (sasl_server_command_match("ERROR", input, n_input, &argument, &n_argument) ||
                 sasl_server_command_match("CANCEL", input, n_input, NULL, NULL))
                sasl_server_send_rejected(sasl, replyp, lenp);
        else if (sasl_server_command_match("BEGIN", input, n_input, NULL, NULL))
                return -EBADMSG;
        else
                sasl_server_send_error(sasl, replyp, lenp);

        return 0;
}

int sasl_server_dispatch_authenticated(SASLServer *sasl, const char *input, size_t n_input, const char **replyp, size_t *lenp) {
        const char *argument;
        size_t n_argument;

        if (sasl_server_command_match("NEGOTIATE_UNIX_FD", input, n_input, NULL, NULL))
                sasl_server_send_agree_unix_fd(sasl, replyp, lenp);
        else if (sasl_server_command_match("BEGIN", input, n_input, NULL, NULL))
                return 1;
        else if (sasl_server_command_match("ERROR", input, n_input, &argument, &n_argument) ||
                   sasl_server_command_match("CANCEL", input, n_input, NULL, NULL))
                sasl_server_send_rejected(sasl, replyp, lenp);
        else
                sasl_server_send_error(sasl, replyp, lenp);

        return 0;
}

int sasl_server_dispatch(SASLServer *sasl, const char *input, size_t n_input, const char **replyp, size_t *lenp) {
        switch (sasl->state) {
        case SASL_SERVER_STATE_INIT:
                return sasl_server_dispatch_init(sasl, input, n_input, replyp, lenp);
        case SASL_SERVER_STATE_CHALLENGE:
                return sasl_server_dispatch_challenge(sasl, input, n_input, replyp, lenp);
        case SASL_SERVER_STATE_AUTHENTICATED:
                return sasl_server_dispatch_authenticated(sasl, input, n_input, replyp, lenp);
        case SASL_SERVER_STATE_NEGOTIATED_FDS:
                return sasl_server_dispatch_authenticated(sasl, input, n_input, replyp, lenp);
        default:
                assert(0);
        }
}
