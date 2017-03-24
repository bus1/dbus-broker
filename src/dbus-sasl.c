/*
 * DBus SASL Parser
 *
 * This wraps the SASL state machine. Only two mechanisms are supported;
 * EXTERNAL and ANONYMOUS. Either way, the bus always knows the UID of a peer
 * from the peer credentials obtained from its socket, which is used for
 * accounting. However, if the ANONYMOUS mechanism is used, the identity of the
 * peer will not be used for anything other than accounting.
 *
 * The peer creds are authorotative, so appart from selecting between anonymous
 * or non-anonymous operation, and whether or not FD passing should be enabled,
 * SASL has no effect.
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
#include "dbus-sasl.h"

void dbus_sasl_init(DBusSASL *sasl, uid_t uid, char *guid) {
        *sasl = (DBusSASL){};
        sasl->uid = uid;
        sasl->mechanism = _DBUS_SASL_MECHANISM_INVALID;
        sasl->ok_response[0] = 'O';
        sasl->ok_response[1] = 'K';
        sasl->ok_response[2] = ' ';
        c_string_to_hex(guid, 16, &sasl->ok_response[3]);
        sasl->ok_response[3 + 16 * 2] = '\r';
        sasl->ok_response[3 + 16 * 2 + 1] = '\n';
};

void dbus_sasl_deinit(DBusSASL *sasl) {
        *sasl = (DBusSASL){};
};

static void dbus_sasl_send_rejected(DBusSASL *sasl,
                                    char *buffer,
                                    size_t *n_bufferp) {
        const char *rejected = "REJECTED EXTERNAL ANONYMOUS\r\n";

        sasl->state = DBUS_SASL_STATE_INIT;

        memcpy(buffer, rejected, strlen(rejected));
        *n_bufferp = strlen(rejected);
}

static void dbus_sasl_send_ok(DBusSASL *sasl,
                              char *buffer,
                              size_t *n_bufferp) {

        sasl->state = DBUS_SASL_STATE_AUTHENTICATED;

        memcpy(buffer, sasl->ok_response, sizeof(sasl->ok_response));
        *n_bufferp = sizeof(sasl->ok_response);
}

static void dbus_sasl_send_data(DBusSASL *sasl,
                                char *buffer,
                                size_t *n_bufferp) {
        const char *data = "DATA\r\n";

        sasl->state = DBUS_SASL_STATE_CHALLENGE;

        memcpy(buffer, data, strlen(data));
        *n_bufferp = strlen(data);
}

static void dbus_sasl_send_error(DBusSASL *sasl,
                                 char *buffer,
                                 size_t *n_bufferp) {
        const char *error = "ERROR\r\n";

        memcpy(buffer, error, strlen(error));
        *n_bufferp = strlen(error);
}

static void dbus_sasl_send_agree_unix_fd(DBusSASL *sasl,
                                         char *buffer,
                                         size_t *n_bufferp) {
        const char *agree_unix_fd = "AGREE_UNIX_FD\r\n";

        sasl->state = DBUS_SASL_STATE_NEGOTIATED_FDS;

        memcpy(buffer, agree_unix_fd, strlen(agree_unix_fd));
        *n_bufferp = strlen(agree_unix_fd);
}

/*
 * A command should be followed by a space, and optionally by an argumnet.
 * However, we alse accept command that do not have a trailing space, given
 * there are no arguments. We reject commansd that have argumnets even though
 * none are expected.
 */
static bool dbus_sasl_command_match(const char *command,
                                    char *input,
                                    char **argumentp) {
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

/* only called if data was provided, in which case it must be valid and match */
static int dbus_sasl_handle_data_external(DBusSASL *sasl,
                                          char *input,
                                          char *buffer,
                                          size_t *n_bufferp) {
        uid_t uid;
        int r;

        r = uid_from_hexstring(input, &uid);
        if (r < 0) {
                dbus_sasl_send_error(sasl, buffer, n_bufferp);
                return 0;
        }

        if (uid == sasl->uid)
                dbus_sasl_send_ok(sasl, buffer, n_bufferp);
        else
                dbus_sasl_send_rejected(sasl, buffer, n_bufferp);

        return 0;
}

static int dbus_sasl_handle_data_anonymous(DBusSASL *sasl,
                                           char *input,
                                           char *buffer,
                                           size_t *n_bufferp) {
        /* we ignore the trace string, and do not verify it */
        dbus_sasl_send_ok(sasl, buffer, n_bufferp);

        return 0;
}

static int dbus_sasl_handle_data(DBusSASL *sasl,
                                 char *input,
                                 char *buffer,
                                 size_t *n_bufferp) {
        if (!input) {
                /* for both EXTERNAL and ANONYMOUS the data is optional */
                dbus_sasl_send_ok(sasl, buffer, n_bufferp);
                return 0;
        }

        switch (sasl->mechanism) {
        case DBUS_SASL_MECHANISM_EXTERNAL:
                return dbus_sasl_handle_data_external(sasl,
                                                      input,
                                                      buffer,
                                                      n_bufferp);
        case DBUS_SASL_MECHANISM_ANONYMOUS:
                return dbus_sasl_handle_data_anonymous(sasl,
                                                       input,
                                                       buffer,
                                                       n_bufferp);
        default:
                assert(0);
        }
}

static int dbus_sasl_handle_auth(DBusSASL *sasl,
                                 char *input,
                                 char *buffer,
                                 size_t *n_bufferp) {
        char *data;

        if (!input) {
                dbus_sasl_send_rejected(sasl, buffer, n_bufferp);
                return 0;
        }

        if (dbus_sasl_command_match("EXTERNAL", input, &data)) {
                sasl->mechanism = DBUS_SASL_MECHANISM_EXTERNAL;
                if (data)
                        return dbus_sasl_handle_data_external(sasl,
                                                              data,
                                                              buffer,
                                                              n_bufferp);
        } else if (dbus_sasl_command_match("ANONYMOUS", input, &data)) {
                sasl->mechanism = DBUS_SASL_MECHANISM_ANONYMOUS;
                if (data)
                        return dbus_sasl_handle_data_anonymous(sasl,
                                                               data,
                                                               buffer,
                                                               n_bufferp);
        } else {
                dbus_sasl_send_rejected(sasl, buffer, n_bufferp);
                return 0;
        }

        dbus_sasl_send_data(sasl, buffer, n_bufferp);

        return 0;
}

int dbus_sasl_dispatch_init(DBusSASL *sasl,
                            char *input,
                            char *buffer,
                            size_t *n_bufferp) {
        char *argument;

        if (dbus_sasl_command_match("AUTH", input, &argument))
                return dbus_sasl_handle_auth(sasl, argument, buffer, n_bufferp);
        else if (dbus_sasl_command_match("ERROR", input, &argument))
                dbus_sasl_send_rejected(sasl, buffer, n_bufferp);
        else if (dbus_sasl_command_match("BEGIN", input, NULL))
                return -EBADMSG;
        else
                dbus_sasl_send_error(sasl, buffer, n_bufferp);

        return 0;
}

int dbus_sasl_dispatch_challenge(DBusSASL *sasl,
                                 char *input,
                                 char *buffer,
                                 size_t *n_bufferp) {
        char *argument;

        if (dbus_sasl_command_match("DATA", input, &argument))
                return dbus_sasl_handle_data(sasl, argument, buffer, n_bufferp);
        else if (dbus_sasl_command_match("ERROR", input, &argument) ||
                 dbus_sasl_command_match("CANCEL", input, NULL))
                dbus_sasl_send_rejected(sasl, buffer, n_bufferp);
        else if (dbus_sasl_command_match("BEGIN", input, NULL))
                return -EBADMSG;
        else
                dbus_sasl_send_error(sasl, buffer, n_bufferp);

        return 0;
}

int dbus_sasl_dispatch_authenticated(DBusSASL *sasl,
                                     char *input,
                                     char *buffer,
                                     size_t *n_bufferp) {
        char *argument;

        if (dbus_sasl_command_match("NEGOTIATE_UNIX_FD", input, NULL))
                dbus_sasl_send_agree_unix_fd(sasl, buffer, n_bufferp);
        else if (dbus_sasl_command_match("BEGIN", input, NULL))
                return 1;
        else if (dbus_sasl_command_match("ERROR", input, &argument) ||
                   dbus_sasl_command_match("CANCEL", input, NULL))
                dbus_sasl_send_rejected(sasl, buffer, n_bufferp);
        else
                dbus_sasl_send_error(sasl, buffer, n_bufferp);

        return 0;
}

int dbus_sasl_dispatch(DBusSASL *sasl,
                       char *input,
                       char *buffer,
                       size_t *n_bufferp) {
        switch (sasl->state) {
        case DBUS_SASL_STATE_INIT:
                return dbus_sasl_dispatch_init(sasl, input, buffer, n_bufferp);
        case DBUS_SASL_STATE_CHALLENGE:
                return dbus_sasl_dispatch_challenge(sasl, input, buffer, n_bufferp);
        case DBUS_SASL_STATE_AUTHENTICATED:
                return dbus_sasl_dispatch_authenticated(sasl, input, buffer, n_bufferp);
        case DBUS_SASL_STATE_NEGOTIATED_FDS:
                return dbus_sasl_dispatch_authenticated(sasl, input, buffer, n_bufferp);
        default:
                assert(0);
        }
}
