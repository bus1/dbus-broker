#pragma once

/*
 * Name Activation
 */

#include <c-list.h>
#include <c-macro.h>
#include <stdlib.h>
#include "util/user.h"

typedef struct Activation Activation;
typedef struct ActivationMessage ActivationMessage;
typedef struct ActivationRequest ActivationRequest;
typedef struct Message Message;
typedef struct Name Name;

enum {
        _ACTIVATION_E_SUCCESS,

        ACTIVATION_E_QUOTA,

        ACTIVATION_E_ALREADY_ACTIVATABLE,
};

struct ActivationRequest {
        UserCharge charge;
        uint64_t sender_id;
        uint32_t serial;
        CList link;
};

struct ActivationMessage {
        UserCharge charges[2];
        CList link;
        Message *message;
};

struct Activation {
        Name *name;
        User *user;
        CList activation_messages;
        CList activation_requests;
        bool requested : 1;
};

#define ACTIVATION_NULL(_x) {                                                   \
                .activation_messages = C_LIST_INIT((_x).activation_messages),   \
                .activation_requests = C_LIST_INIT((_x).activation_requests),   \
        }

/* requests */

ActivationRequest *activation_request_free(ActivationRequest *request);

/* messages */

ActivationMessage *activation_message_free(ActivationMessage *message);

/* activation */

int activation_init(Activation *activation, Name *name, User *user);
void activation_deinit(Activation *activation);

int activation_queue_message(Activation *activation, User *user, Message *m);
int activation_queue_request(Activation *activation, User *user, uint64_t sender_id, uint32_t serial);

int activation_flush(Activation *activation);

C_DEFINE_CLEANUP(Activation *, activation_deinit);
