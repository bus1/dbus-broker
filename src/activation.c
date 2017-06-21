/*
 * Name Activation
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/types.h>
#include "activation.h"
#include "dbus/socket.h"
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

static int activation_compare(CRBTree *tree, void *k, CRBNode *rb) {
        Activation *activation = c_container_of(rb, Activation, registry_node);

        return strcmp(k, activation->path);
}

/**
 * activation_new() - XXX
 */
int activation_new(Activation **activationp, ActivationRegistry *registry, const char *path, Name *name, User *user) {
        _c_cleanup_(activation_freep) Activation *activation = NULL;
        CRBNode **slot, *parent;

        slot = c_rbtree_find_slot(&registry->activation_tree, activation_compare, path, &parent);
        if (!slot)
                return ACTIVATION_E_EXISTS;

        if (name->activation)
                return ACTIVATION_E_ALREADY_ACTIVATABLE;

        activation = calloc(1, sizeof(*activation) + strlen(path) + 1);
        if (!activation)
                return error_origin(-ENOMEM);

        activation->registry = registry;
        activation->name = name_ref(name);
        activation->user = user_ref(user);
        activation->socket_buffers = (CList)C_LIST_INIT(activation->socket_buffers);
        activation->activation_requests = (CList)C_LIST_INIT(activation->activation_requests);
        activation->registry_node = (CRBNode)C_RBNODE_INIT(activation->registry_node);
        memcpy((char*)activation->path, path, strlen(path) + 1);

        name->activation = activation;
        c_rbtree_add(&registry->activation_tree, parent, slot, &activation->registry_node);

        *activationp = activation;
        activation = NULL;
        return 0;
}

/**
 * activation_free() - XXX
 */
Activation *activation_free(Activation *activation) {
        if (!activation)
                return NULL;

        activation_flush(activation);

        assert(c_list_is_empty(&activation->socket_buffers));
        assert(c_list_is_empty(&activation->activation_requests));

        activation->user = user_unref(activation->user);
        activation->name->activation = NULL;
        activation->name = name_unref(activation->name);
        c_rbtree_remove_init(&activation->registry->activation_tree, &activation->registry_node);
        free(activation);

        return NULL;
}

int activation_flush(Activation *activation) {
        SocketBuffer *skb;
        ActivationRequest *request;

        /* XXX: send out error replies */

        while ((skb = c_list_first_entry(&activation->socket_buffers, SocketBuffer, link)))
                socket_buffer_free(skb);

        while ((request = c_list_first_entry(&activation->activation_requests, ActivationRequest, link)))
                activation_request_free(request);

        return 0;
}

int activation_queue_message(Activation *activation, Message *message) {
        SocketBuffer *skb;
        int r;

        r = socket_buffer_new(&skb, message);
        if (r)
                return error_fold(r);

        c_list_link_tail(&activation->socket_buffers, &skb->link);

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

void activation_registry_init(ActivationRegistry *registry) {
        *registry = (ActivationRegistry){};
}

void activation_registry_deinit(ActivationRegistry *registry) {
        assert(c_rbtree_is_empty(&registry->activation_tree));
}

Activation *activation_registry_find(ActivationRegistry *registry, const char *path) {
        return c_rbtree_find_entry(&registry->activation_tree, activation_compare, path, Activation, registry_node);
}

void activation_registry_flush(ActivationRegistry *registry) {
        Activation *activation, *safe;

        c_rbtree_for_each_entry_unlink(activation, safe, &registry->activation_tree, registry_node)
                activation_free(activation);
}
