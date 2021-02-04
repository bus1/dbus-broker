/*
 * Name Activation
 */

#include <c-list.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include "broker/controller.h"
#include "bus/activation.h"
#include "bus/bus.h"
#include "bus/name.h"
#include "bus/policy.h"
#include "dbus/message.h"
#include "util/error.h"
#include "util/fdlist.h"
#include "util/user.h"

ActivationRequest *activation_request_free(ActivationRequest *request) {
        if (!request)
                return NULL;

        c_list_unlink(&request->link);
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
        c_list_unlink(&message->link);
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
int activation_init(Activation *a, Bus *bus, Name *name, User *user) {
        _c_cleanup_(activation_deinitp) Activation *activation = a;

        if (name->activation)
                return ACTIVATION_E_ALREADY_ACTIVATABLE;

        *activation = (Activation)ACTIVATION_NULL(*activation);
        activation->bus = bus;
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

/**
 * activation_get_stats_for() - XXX
 */
void activation_get_stats_for(Activation *activation,
                              uint64_t owner_id,
                              unsigned int *n_bytesp,
                              unsigned int *n_fdsp) {
        ActivationRequest *request;
        ActivationMessage *message;
        unsigned int n_bytes = 0, n_fds = 0;

        c_list_for_each_entry(message, &activation->activation_messages, link) {
                if (owner_id == message->message->metadata.sender_id) {
                        n_bytes += message->charges[0].charge;
                        n_fds += message->charges[1].charge;
                }
        }

        c_list_for_each_entry(request, &activation->activation_requests, link)
                if (owner_id == request->sender_id)
                        n_bytes += request->charge.charge;

        *n_bytesp = n_bytes;
        *n_fdsp = n_fds;
}

static int activation_request(Activation *activation) {
        int r;

        if (activation->pending)
                return 0;

        r = controller_name_activate(CONTROLLER_NAME(activation),
                                     ++activation->bus->activation_ids);
        if (r)
                return error_fold(r);

        activation->pending = activation->bus->activation_ids;
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
