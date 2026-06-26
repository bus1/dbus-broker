/*
 * Name Activation
 */

#include <c-list.h>
#include <c-stdaux.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include "broker/broker.h"
#include "broker/controller.h"
#include "bus/activation.h"
#include "bus/bus.h"
#include "bus/driver.h"
#include "bus/name.h"
#include "bus/policy.h"
#include "dbus/message.h"
#include "util/dispatch.h"
#include "util/error.h"
#include "util/fdlist.h"
#include "util/nsec.h"
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

        activation_timeout_disarm(activation);

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

static int activation_timeout_rearm(Broker *broker) {
        struct itimerspec spec = {};
        Activation *head;

        if (broker->activation_timer_fd < 0)
                return 0;

        /*
         * Arm the timerfd to the head (oldest/soonest) deadline, or leave the
         * spec all-zero to disarm it when no activation is pending.
         */
        head = c_list_first_entry(&broker->pending_activations, Activation, timeout_link);
        if (head) {
                spec.it_value.tv_sec = head->deadline / UINT64_C(1000000000);
                spec.it_value.tv_nsec = head->deadline % UINT64_C(1000000000);
        }

        if (timerfd_settime(broker->activation_timer_fd, TFD_TIMER_ABSTIME, &spec, NULL) < 0)
                return error_origin(-errno);

        return 0;
}

static int activation_timeout_dispatch(DispatchFile *file) {
        Broker *broker = c_container_of(file, Broker, activation_timer_file);
        Bus *bus = &broker->bus;
        Activation *activation, *activation_safe;
        uint64_t now, v;
        ssize_t l;
        int r;

        c_assert(dispatch_file_events(file) == EPOLLIN);

        /*
         * The timerfd is edge-triggered, so we must drain it and clear the
         * cached event, or the dispatcher busy-loops on the ready-list.
         */
        l = read(broker->activation_timer_fd, &v, sizeof(v));
        if (l < 0) {
                if (errno == EAGAIN) {
                        dispatch_file_clear(file, EPOLLIN);
                        return 0;
                }

                return error_origin(-errno);
        }

        c_assert(l == sizeof(v));
        dispatch_file_clear(file, EPOLLIN);

        now = nsec_now(CLOCK_MONOTONIC);

        /*
         * Walk the FIFO head-first and fail every activation whose deadline has
         * passed. driver_name_activation_failed() clears `pending`, flushes the
         * queued requests/messages (releasing their fd/byte charges and closing
         * fds), and via the disarm hook in driver.c unlinks the node from
         * `broker->pending_activations` and re-arms the timer to the new head.
         * Because the timeout is constant, deadlines are sorted, so we can stop
         * at the first entry that has not yet aged out.
         */
        c_list_for_each_entry_safe(activation, activation_safe, &broker->pending_activations, timeout_link) {
                if (activation->deadline > now)
                        break;

                r = driver_name_activation_failed(bus, activation, activation->pending,
                                                  CONTROLLER_NAME_ERROR_ACTIVATION_TIMEOUT);
                if (r)
                        return error_fold(r);
        }

        return 0;
}

int activation_timer_init(Broker *broker) {
        int r;

        /* a zero timeout disables the activation timeout entirely */
        if (!broker->activation_timeout_nsec)
                return 0;

        /*
         * A single broker-wide timerfd multiplexes all pending-activation
         * deadlines. It is created once for the broker's lifetime and wrapped
         * in a DispatchFile, mirroring the signalfd in broker.c. It is armed
         * (always to the head/soonest deadline) and disarmed as activations
         * come and go, so an idle broker never wakes up for it.
         */
        broker->activation_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
        if (broker->activation_timer_fd < 0)
                return error_origin(-errno);

        r = dispatch_file_init(&broker->activation_timer_file,
                               &broker->dispatcher,
                               activation_timeout_dispatch,
                               broker->activation_timer_fd,
                               EPOLLIN,
                               0);
        if (r)
                return error_fold(r);

        dispatch_file_select(&broker->activation_timer_file, EPOLLIN);
        return 0;
}

void activation_timer_deinit(Broker *broker) {
        if (broker->activation_timer_fd < 0)
                return;

        dispatch_file_deinit(&broker->activation_timer_file);
        broker->activation_timer_fd = c_close(broker->activation_timer_fd);
}

static int activation_timeout_arm(Activation *activation) {
        Broker *broker = BROKER(activation->bus);

        /* timeout disabled: no timerfd was created, nothing to arm */
        if (broker->activation_timer_fd < 0)
                return 0;

        /*
         * Append to the tail. The timeout is constant, so append order ==
         * deadline order: the head is always the oldest/soonest to expire.
         */
        activation->deadline = nsec_now(CLOCK_MONOTONIC) + broker->activation_timeout_nsec;
        c_list_link_tail(&broker->pending_activations, &activation->timeout_link);
        return activation_timeout_rearm(broker);
}

int activation_timeout_disarm(Activation *activation) {
        if (!c_list_is_linked(&activation->timeout_link))
                return 0;

        c_list_unlink(&activation->timeout_link);
        return activation_timeout_rearm(BROKER(activation->bus));
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

        r = activation_timeout_arm(activation);
        if (r)
                return error_trace(r);

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
