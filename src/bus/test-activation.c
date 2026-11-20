/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: D-Bus Broker Developers */

/*
 * Test Name Activation
 */

#undef NDEBUG
#include <c-dvar.h>
#include <c-dvar-type.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "broker/broker.h"
#include "broker/controller.h"
#include "bus/activation.h"
#include "bus/name.h"
#include "bus/policy.h"
#include "dbus/message.h"
#include "dbus/protocol.h"
#include "util/user.h"

static Message *test_new_message(void) {
        static const CDVarType type[] = {
                C_DVAR_T_INIT(
                        C_DVAR_T_TUPLE2(
                                C_DVAR_T_TUPLE7(
                                        C_DVAR_T_y,
                                        C_DVAR_T_y,
                                        C_DVAR_T_y,
                                        C_DVAR_T_y,
                                        C_DVAR_T_u,
                                        C_DVAR_T_u,
                                        C_DVAR_T_ARRAY(
                                                C_DVAR_T_TUPLE2(C_DVAR_T_y, C_DVAR_T_v)
                                        )
                                ),
                                C_DVAR_T_TUPLE0
                        )
                )
        };
        _c_cleanup_(c_dvar_deinit) CDVar var = C_DVAR_INIT;
        Message *message;
        void *data;
        size_t n_data;
        int r;

        c_dvar_begin_write(&var, (__BYTE_ORDER == __BIG_ENDIAN), type, 1);
        c_dvar_write(&var, "((yyyyuu[(y<o>)(y<s>)(y<s>)(y<s>)])())",
                     c_dvar_is_big_endian(&var) ? 'B' : 'l',
                     DBUS_MESSAGE_TYPE_METHOD_CALL, 0, 1, 0, 1,
                     DBUS_MESSAGE_FIELD_PATH, &c_dvar_type_o, "/",
                     DBUS_MESSAGE_FIELD_INTERFACE, &c_dvar_type_s, "com.example.Service",
                     DBUS_MESSAGE_FIELD_MEMBER, &c_dvar_type_s, "Ping",
                     DBUS_MESSAGE_FIELD_DESTINATION, &c_dvar_type_s, "com.example.Service");
        r = c_dvar_end_write(&var, &data, &n_data);
        c_assert(!r);

        r = message_new_outgoing(&message, data, n_data);
        c_assert(!r);
        r = message_parse_metadata(message);
        c_assert(!r);

        return message;
}

static void test_controller_quota(bool automatic, uid_t service_uid) {
        Broker broker = {
                .dispatcher = DISPATCH_CONTEXT_NULL(broker.dispatcher),
        };
        UserCharge pressure = USER_CHARGE_INIT;
        ControllerName *name;
        PolicyRegistry *registry;
        PolicySnapshot *policy;
        NameOwner sender_names;
        Message *message;
        uint64_t pending;
        unsigned int n_bytes, n_bytes_after, n_in_bytes, n_in_fds, n_out_fds;
        int pair[2], r;

        r = bus_init(&broker.bus, NULL, "0123456789abcdef0123456789abcdef", 65536, 64, 64, 64);
        c_assert(!r);
        r = user_registry_ref_user(&broker.bus.users, &broker.bus.user, 0);
        c_assert(!r);
        r = dispatch_context_init(&broker.dispatcher);
        c_assert(!r);
        r = socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair);
        c_assert(r >= 0);
        r = controller_init(&broker.controller, &broker, pair[0]);
        c_assert(!r);
        r = controller_add_name(&broker.controller, &name,
                                "/org/bus1/DBus/Name/test", "com.example.Service", service_uid);
        c_assert(!r);

        name_owner_init(&sender_names);
        r = policy_registry_new(&registry, NULL, "");
        c_assert(!r);
        r = policy_snapshot_new(&policy, registry, "", 0, NULL, 0);
        c_assert(!r);
        message = test_new_message();

        /* Exhaust the controller owner's quota, not necessarily the service's. */
        r = user_charge(broker.bus.user, &pressure, NULL, USER_SLOT_BYTES,
                        broker.bus.user->slots[USER_SLOT_BYTES].n);
        c_assert(!r);

        for (unsigned int i = 0; i < 4; ++i) {
                if (automatic)
                        r = activation_queue_message(&name->activation, broker.bus.user,
                                                     &sender_names, policy, message);
                else
                        r = activation_queue_request(&name->activation, broker.bus.user, 1, 1);
                c_assert(r == ACTIVATION_E_QUOTA);
                c_assert(!name->activation.pending);
                c_assert(c_list_is_empty(&name->activation.activation_messages));
                c_assert(c_list_is_empty(&name->activation.activation_requests));
                c_assert(c_list_is_empty(&broker.controller.connection.socket.out.queue));
                c_assert(c_list_is_empty(&broker.controller.connection.socket.out.pending));
                c_assert(connection_is_running(&broker.controller.connection));
        }

        user_charge_deinit(&pressure);

        /* Retrying after resources are released must send a fresh activation. */
        if (automatic)
                r = activation_queue_message(&name->activation, broker.bus.user,
                                             &sender_names, policy, message);
        else
                r = activation_queue_request(&name->activation, broker.bus.user, 1, 1);
        c_assert(!r);
        pending = name->activation.pending;
        c_assert(pending && pending == broker.bus.activation_ids);
        c_assert(automatic ? !c_list_is_empty(&name->activation.activation_messages)
                           : !c_list_is_empty(&name->activation.activation_requests));
        socket_get_stats(&broker.controller.connection.socket,
                         &n_in_bytes, &n_in_fds, &n_bytes, &n_out_fds);
        c_assert(n_bytes > 0);

        /* Once pending, further requests must not send duplicate activations. */
        if (automatic)
                r = activation_queue_message(&name->activation, broker.bus.user,
                                             &sender_names, policy, message);
        else
                r = activation_queue_request(&name->activation, broker.bus.user, 1, 2);
        c_assert(!r);
        c_assert(name->activation.pending == pending);
        c_assert(broker.bus.activation_ids == pending);
        socket_get_stats(&broker.controller.connection.socket,
                         &n_in_bytes, &n_in_fds, &n_bytes_after, &n_out_fds);
        c_assert(n_bytes_after == n_bytes);

        message_unref(message);
        policy_snapshot_free(policy);
        policy_registry_free(registry);
        name_owner_deinit(&sender_names);
        controller_deinit(&broker.controller);
        pair[1] = c_close(pair[1]);
        dispatch_context_deinit(&broker.dispatcher);
        bus_deinit(&broker.bus);
}

int main(int argc, char **argv) {
        test_controller_quota(false, 0);
        test_controller_quota(true, 0);
        test_controller_quota(false, 1);
        test_controller_quota(true, 1);
        return 0;
}
