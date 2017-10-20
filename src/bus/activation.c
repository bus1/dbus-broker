/*
 * Name Activation
 */

#include <c-list.h>
#include <c-macro.h>
#include <stdlib.h>
#include "broker/controller.h"
#include "bus/activation.h"
#include "bus/name.h"
#include "bus/policy.h"
#include "dbus/message.h"
#include "util/error.h"
#include "util/fdlist.h"
#include "util/user.h"

ActivationRequest *activation_request_free(ActivationRequest *request) {
        if (!request)
                return NULL;

        c_list_unlink_init(&request->link);
        user_charge_deinit(&request->charge);
        free(request);

        return NULL;
}

C_DEFINE_CLEANUP(ActivationRequest *, activation_request_free);

ActivationMessage *activation_message_free(ActivationMessage *message) {
        if (!message)
                return NULL;

        name_snapshot_free(message->senders_names);
        policy_snapshot_free(message->senders_policy);
        message_unref(message->message);
        c_list_unlink_init(&message->link);
        user_charge_deinit(&message->charges[1]);
        user_charge_deinit(&message->charges[0]);
        user_unref(message->user);
        free(message);

        return NULL;
}

C_DEFINE_CLEANUP(ActivationMessage *, activation_message_free);

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
        ActivationRequest *request;
        ActivationMessage *message;

        while ((message = c_list_first_entry(&activation->activation_messages, ActivationMessage, link)))
                activation_message_free(message);

        while ((request = c_list_first_entry(&activation->activation_requests, ActivationRequest, link)))
                activation_request_free(request);

        activation->user = user_unref(activation->user);

        if (activation->name) {
                activation->name->activation = NULL;
                activation->name = name_unref(activation->name);
        }
}

static int activation_request(Activation *activation) {
        int r;

        if (activation->requested)
                return 0;

        r = controller_name_activate(CONTROLLER_NAME(activation));
        if (r)
                return error_fold(r);

        activation->requested = true;
        return 0;
}

int activation_queue_message(Activation *activation,
                             User *user,
                             NameOwner *names,
                             PolicySnapshot *policy,
                             Message *m) {
        _c_cleanup_(activation_message_freep) ActivationMessage *message = NULL;
        int r;

        r = activation_request(activation);
        if (r)
                return error_trace(r);

        message = calloc(1, sizeof(*message));
        if (!message)
                return error_origin(-ENOMEM);

        message->user = user_ref(user);
        message->charges[0] = (UserCharge)USER_CHARGE_INIT;
        message->charges[1] = (UserCharge)USER_CHARGE_INIT;
        message->link = (CList)C_LIST_INIT(message->link);
        message->message = message_ref(m);

        r = user_charge(activation->user, &message->charges[0], user, USER_SLOT_BYTES,
                        sizeof(ActivationMessage) + sizeof(Message) + m->n_data);
        r = r ?: user_charge(activation->user, &message->charges[1], user, USER_SLOT_FDS,
                             fdlist_count(m->fds));
        if (r)
                return (r == USER_E_QUOTA) ? ACTIVATION_E_QUOTA : error_fold(r);

        r = policy_snapshot_dup(policy, &message->senders_policy);
        if (r)
                return error_fold(r);

        r = name_snapshot_new(&message->senders_names, names);
        if (r)
                return error_fold(r);

        c_list_link_tail(&activation->activation_messages, &message->link);
        message = NULL;
        return 0;
}

int activation_queue_request(Activation *activation, User *user, uint64_t sender_id, uint32_t serial) {
        _c_cleanup_(activation_request_freep) ActivationRequest *request = NULL;
        int r;

        r = activation_request(activation);
        if (r)
                return error_trace(r);

        /* If no reply is expected, don't store the request. */
        if (!serial)
                return 0;

        request = calloc(1, sizeof(*request));
        if (!request)
                return error_origin(-ENOMEM);

        request->charge = (UserCharge)USER_CHARGE_INIT;
        request->link = (CList)C_LIST_INIT(request->link);
        request->sender_id = sender_id;
        request->serial = serial;

        r = user_charge(activation->user, &request->charge, user, USER_SLOT_BYTES, sizeof(ActivationRequest));
        if (r)
                return (r == USER_E_QUOTA) ? ACTIVATION_E_QUOTA : error_fold(r);

        c_list_link_tail(&activation->activation_requests, &request->link);
        request = NULL;
        return 0;
}
