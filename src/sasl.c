/*
 * DBus SASL Parser
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

void sasl_init(SASL *sasl, uid_t uid, char *guid) {
        *sasl = (SASL){};
        sasl->uid = uid;
        sasl->ok_response[0] = 'O';
        sasl->ok_response[1] = 'K';
        sasl->ok_response[2] = ' ';
        c_string_to_hex(guid, 16, &sasl->ok_response[3]);
        sasl->ok_response[3 + 16 * 2] = '\r';
        sasl->ok_response[3 + 16 * 2 + 1] = '\n';
};

void sasl_deinit(SASL *sasl) {
        *sasl = (SASL){};
};

static void sasl_send_rejected(SASL *sasl, const char **replyp, size_t *lenp) {
        const char *rejected = "REJECTED EXTERNAL\r\n";

        sasl->state = SASL_STATE_INIT;

        *replyp = rejected;
        *lenp = strlen(rejected);
}

static void sasl_send_ok(SASL *sasl, const char **replyp, size_t *lenp) {
        sasl->state = SASL_STATE_AUTHENTICATED;

        *replyp = sasl->ok_response;
        *lenp = sizeof(sasl->ok_response);
}

static void sasl_send_data(SASL *sasl, const char **replyp, size_t *lenp) {
        const char *data = "DATA\r\n";

        sasl->state = SASL_STATE_CHALLENGE;

        *replyp = data;
        *lenp = strlen(data);
}

static void sasl_send_error(SASL *sasl, const char **replyp, size_t *lenp) {
        const char *error = "ERROR\r\n";

        *replyp = error;
        *lenp = strlen(error);
}

static void sasl_send_agree_unix_fd(SASL *sasl, const char **replyp, size_t *lenp) {
        const char *agree_unix_fd = "AGREE_UNIX_FD\r\n";

        sasl->state = SASL_STATE_NEGOTIATED_FDS;

        *replyp = agree_unix_fd;
        *lenp = strlen(agree_unix_fd);
}

/*
 * A command should be followed by a space, and optionally by an argumnet.
 * However, we alse accept command that do not have a trailing space, given
 * there are no arguments. We reject commansd that have argumnets even though
 * none are expected.
 */
static bool sasl_command_match(const char *command, char *input, char **argumentp) {
        char *argument;

        if (strncmp(input, command, strlen(command)) != 0)
                return false;

        argument = input + strlen(command);
        if (*argument == '\0') {
                if (argumentp)
                        *argumentp = NULL;
                return true;
        } else if (*argument != ' ')
                return false;

        argument ++;

        if (*argument == '\0') {
                if (argumentp)
                        *argumentp = NULL;
        } else {
                if (argumentp)
                        *argumentp = argument;
                else
                        return false;
        }

        return true;
}

static int uid_from_hexstring(char *hex, uid_t *uidp) {
        char uid_string[C_DECIMAL_MAX(uid_t)];
        char *end;
        unsigned long uid = 0;
        bool valid;

        if (strlen(hex) / 2 > sizeof(uid_string))
                return -EBADMSG;

        valid = c_string_from_hex(uid_string, strlen(hex) / 2, hex);
        if (!valid)
                return -EBADMSG;

        uid_string[strlen(hex) / 2] = '\0';

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

static int sasl_handle_data(SASL *sasl, char *input, const char **replyp, size_t *lenp) {
        uid_t uid;
        int r;

        if (!input) {
                /* for the EXTERNAL mechanism data is optional */
                sasl_send_ok(sasl, replyp, lenp);
                return 0;
        }

        /* if data was provided it must be valid and match what we expect */
        r = uid_from_hexstring(input, &uid);
        if (r < 0) {
                sasl_send_error(sasl, replyp, lenp);
                return 0;
        }

        if (uid == sasl->uid)
                sasl_send_ok(sasl, replyp, lenp);
        else
                sasl_send_rejected(sasl, replyp, lenp);

        return 0;
}

static int sasl_handle_auth(SASL *sasl, char *input, const char **replyp, size_t *lenp) {
        char *data;

        if (!input) {
                sasl_send_rejected(sasl, replyp, lenp);
                return 0;
        }

        if (sasl_command_match("EXTERNAL", input, &data)) {
                if (data)
                        return sasl_handle_data(sasl, data, replyp, lenp);
                else {
                        sasl_send_data(sasl, replyp, lenp);
                        return 0;
                }
        } else {
                sasl_send_rejected(sasl, replyp, lenp);
                return 0;
        }
}

int sasl_dispatch_init(SASL *sasl, char *input, const char **replyp, size_t *lenp) {
        char *argument;

        if (sasl_command_match("AUTH", input, &argument))
                return sasl_handle_auth(sasl, argument, replyp, lenp);
        else if (sasl_command_match("ERROR", input, &argument))
                sasl_send_rejected(sasl, replyp, lenp);
        else if (sasl_command_match("BEGIN", input, NULL))
                return -EBADMSG;
        else
                sasl_send_error(sasl, replyp, lenp);

        return 0;
}

int sasl_dispatch_challenge(SASL *sasl, char *input, const char **replyp, size_t *lenp) {
        char *argument;

        if (sasl_command_match("DATA", input, &argument))
                return sasl_handle_data(sasl, argument, replyp, lenp);
        else if (sasl_command_match("ERROR", input, &argument) ||
                 sasl_command_match("CANCEL", input, NULL))
                sasl_send_rejected(sasl, replyp, lenp);
        else if (sasl_command_match("BEGIN", input, NULL))
                return -EBADMSG;
        else
                sasl_send_error(sasl, replyp, lenp);

        return 0;
}

int sasl_dispatch_authenticated(SASL *sasl, char *input, const char **replyp, size_t *lenp) {
        char *argument;

        if (sasl_command_match("NEGOTIATE_UNIX_FD", input, NULL))
                sasl_send_agree_unix_fd(sasl, replyp, lenp);
        else if (sasl_command_match("BEGIN", input, NULL))
                return 1;
        else if (sasl_command_match("ERROR", input, &argument) ||
                   sasl_command_match("CANCEL", input, NULL))
                sasl_send_rejected(sasl, replyp, lenp);
        else
                sasl_send_error(sasl, replyp, lenp);

        return 0;
}

int sasl_dispatch(SASL *sasl, char *input, const char **replyp, size_t *lenp) {
        switch (sasl->state) {
        case SASL_STATE_INIT:
                return sasl_dispatch_init(sasl, input, replyp, lenp);
        case SASL_STATE_CHALLENGE:
                return sasl_dispatch_challenge(sasl, input, replyp, lenp);
        case SASL_STATE_AUTHENTICATED:
                return sasl_dispatch_authenticated(sasl, input, replyp, lenp);
        case SASL_STATE_NEGOTIATED_FDS:
                return sasl_dispatch_authenticated(sasl, input, replyp, lenp);
        default:
                assert(0);
        }
}
