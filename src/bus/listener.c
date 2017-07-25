/*
 * Socket Listener
 */

#include <c-list.h>
#include <c-macro.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include "bus/bus.h"
#include "bus/listener.h"
#include "bus/peer.h"
#include "bus/policy.h"
#include "launch/policy-parser.h" /* XXX: drop once we get the policy pre-parsed */
#include "util/dispatch.h"
#include "util/error.h"

static int listener_dispatch(DispatchFile *file, uint32_t events) {
        Listener *listener = c_container_of(file, Listener, socket_file);
        _c_cleanup_(peer_freep) Peer *peer = NULL;
        _c_cleanup_(c_closep) int fd = -1;
        int r;

        if (!(events & EPOLLIN))
                return 0;

        fd = accept4(listener->socket_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (fd < 0) {
                if (errno == EAGAIN) {
                        /*
                         * EAGAIN implies there are no pending incoming
                         * connections. Catch this, clear EPOLLIN and tell the
                         * caller about it.
                         */
                        dispatch_file_clear(&listener->socket_file, EPOLLIN);
                        return 0;
                } else {
                        /*
                         * The linux UDS layer does not return pending errors
                         * on the child socket (unlike the TCP layer). Hence,
                         * there are no known errors to check for.
                         */
                        return error_origin(-errno);
                }
        }

        r = peer_new_with_fd(&peer, listener->bus, &listener->policy, listener->guid, file->context, fd);
        if (r == PEER_E_QUOTA || r == PEER_E_CONNECTION_REFUSED)
                /*
                 * The user has too many open connections, or a policy disallows it to
                 * connect. Simply drop this.
                 */
                return 0;
        else if (r)
                return error_fold(r);
        fd = -1; /* consume fd */

        r = peer_spawn(peer);
        if (r)
                return error_fold(r);

        peer = NULL;
        return 0;
}

static int listener_instantiate_policy_registry(PolicyRegistry *registry, const char *policypath) {
        _c_cleanup_(policy_parser_registry_deinit) PolicyParserRegistry parser = POLICY_PARSER_REGISTRY_NULL(parser);
        Policy *source;
        int r;

        r = policy_parser_registry_init(&parser);
        if (r)
                return error_fold(r);

        r = policy_parser_registry_append_file(&parser, policypath, NULL);
        if (r)
                return error_fold(r);

        r = policy_registry_init(registry);
        if (r)
                return error_fold(r);

        r = policy_connect_instantiate(&registry->policy_connect, &parser.registry.policy_connect);
        if (r)
                return error_fold(r);

        r = policy_instantiate(registry->wildcard_uid_policy, &parser.default_policy);
        if (r)
                return error_fold(r);

        r = policy_instantiate(registry->wildcard_uid_policy, &parser.console_policy);
        if (r)
                return error_fold(r);

        r = policy_instantiate(registry->wildcard_uid_policy, &parser.mandatory_policy);
        if (r)
                return error_fold(r);

        c_rbtree_for_each_entry(source, &parser.registry.uid_policy_tree, registry_node) {
                Policy *target;

                r = policy_registry_get_policy_by_uid(registry, &target, source->uid);
                if (r)
                        return error_fold(r);

                r = policy_instantiate(target, &parser.default_policy);
                if (r)
                        return error_fold(r);

                r = policy_instantiate(target, source);
                if (r)
                        return error_fold(r);

                r = policy_instantiate(target, &parser.console_policy);
                if (r)
                        return error_fold(r);

                r = policy_instantiate(target, &parser.mandatory_policy);
                if (r)
                        return error_fold(r);
        }

        c_rbtree_for_each_entry(source, &parser.registry.gid_policy_tree, registry_node) {
                Policy *target;

                r = policy_registry_get_policy_by_gid(registry, &target, (gid_t)source->uid);
                if (r)
                        return error_fold(r);

                r = policy_instantiate(target, source);
                if (r)
                        return error_fold(r);
        }

        return 0;
}

/**
 * listener_init_with_fd() - XXX
 */
int listener_init_with_fd(Listener *l, Bus *bus, DispatchContext *dispatcher, int socket_fd, const char *policypath) {
        _c_cleanup_(listener_deinitp) Listener *listener = l;
        int r;

        *listener = (Listener)LISTENER_NULL(*listener);
        listener->bus = bus;

        /*
         * Every listener socket needs its own, unique UUID for clients to
         * identify it. We simply generate those UUIDs from the bus-uuid, by
         * XOR'ing a unique 64bit counter on the lower 64bit, leaving the upper
         * 64bit unchanged.
         */
        ++bus->listener_ids;
        for (size_t i = 0; i < sizeof(listener->guid); ++i) {
                listener->guid[i] = bus->guid[i];
                if (i < sizeof(uint64_t))
                        listener->guid[i] ^= (bus->listener_ids >> (8 * i)) & 0xff;
        }

        r = listener_instantiate_policy_registry(&listener->policy, policypath);
        if (r)
                return error_trace(r);

        r = dispatch_file_init(&listener->socket_file,
                               dispatcher,
                               listener_dispatch,
                               socket_fd,
                               EPOLLIN);
        if (r)
                return error_fold(r);

        dispatch_file_select(&listener->socket_file, EPOLLIN);

        listener->socket_fd = socket_fd;
        listener = NULL;
        return 0;
}

/**
 * listener_deinit() - XXX
 */
void listener_deinit(Listener *listener) {
        assert(c_list_is_empty(&listener->peer_list));

        policy_registry_deinit(&listener->policy);
        dispatch_file_deinit(&listener->socket_file);
        listener->socket_fd = c_close(listener->socket_fd);
        listener->bus = NULL;
}
