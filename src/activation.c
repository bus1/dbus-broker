/*
 * Name Activation
 */

#include <c-list.h>
#include <c-macro.h>
#include <stdlib.h>
#include "activation.h"
#include "dbus/message.h"
#include "name.h"
#include "util/error.h"
#include "util/user.h"

ActivationRequest *activation_request_free(ActivationRequest *request) {
        if (!request)
                return NULL;

        c_list_unlink_init(&request->link);
        free(request);

        return NULL;
}

ActivationMessage *activation_message_free(ActivationMessage *message) {
        if (!message)
                return NULL;

        message_unref(message->message);
        c_list_unlink_init(&message->link);
        free(message);

        return NULL;
}

/**
 * activation_init() - XXX
 */
int activation_init(Activation *a, Name *name, User *user) {
        _c_cleanup_(activation_deinitp) Activation *activation = a;

        if (name->activation)
                return ACTIVATION_E_ALREADY_ACTIVATABLE;

        *activation = (Activation)ACTIVATION_NULL(*activation);
        activation->name = name_ref(name);
        activation->user = user_ref(user);

        name->activation = activation;
        activation = NULL;
        return 0;
}

/**
 * activation_deinit() - XXX
 */
void activation_deinit(Activation *activation) {
        activation_flush(activation);

        assert(c_list_is_empty(&activation->activation_messages));
        assert(c_list_is_empty(&activation->activation_requests));

        activation->user = user_unref(activation->user);

        if (activation->name) {
                activation->name->activation = NULL;
                activation->name = name_unref(activation->name);
        }
}

int activation_flush(Activation *activation) {
        ActivationRequest *request;
        ActivationMessage *message;

        /* XXX: send out error replies */

        while ((message = c_list_first_entry(&activation->activation_messages, ActivationMessage, link)))
                activation_message_free(message);

        while ((request = c_list_first_entry(&activation->activation_requests, ActivationRequest, link)))
                activation_request_free(request);

        return 0;
}

int activation_queue_message(Activation *activation, Message *m) {
        ActivationMessage *message;

        message = calloc(1, sizeof(*message));
        if (!message)
                return error_origin(-ENOMEM);

        message->link = (CList)C_LIST_INIT(message->link);
        message->message = message_ref(m);

        c_list_link_tail(&activation->activation_messages, &message->link);
        return 0;
}

int activation_queue_request(Activation *activation, uint64_t sender_id, uint32_t serial) {
        ActivationRequest *request;

        request = calloc(1, sizeof(*request));
        if (!request)
                return error_origin(-ENOMEM);

        c_list_link_tail(&activation->activation_requests, &request->link);
        request->sender_id = sender_id;
        request->serial = serial;

        return 0;
}
