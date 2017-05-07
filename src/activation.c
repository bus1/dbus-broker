/*
 * Name Activation
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/types.h>
#include "bus.h"
#include "activation.h"
#include "util/error.h"

static int activation_compare(CRBTree *tree, void *k, CRBNode *rb) {
        Activation *activation = c_container_of(rb, Activation, bus_node);
        const char *path = k;

        return strcmp(activation->path, path);
}

/**
 * activation_new() - XXX
 */
int activation_new(Activation **activationp, Bus *bus, const char *path, const char *name, uid_t uid) {
        _c_cleanup_(activation_freep) Activation *activation = NULL;
        _c_cleanup_(name_entry_unrefp) NameEntry *entry = NULL;
        _c_cleanup_(user_entry_unrefp) UserEntry *user = NULL;
        CRBNode **slot, *parent;
        int r;

        slot = c_rbtree_find_slot(&bus->activation_tree, activation_compare, path, &parent);
        if (!slot)
                return ACTIVATION_E_EXISTS;

        r = name_entry_get(&entry, &bus->names, name);
        if (r)
                return error_fold(r);

        if (entry->activation)
                return ACTIVATION_E_ALREADY_ACTIVATABLE;

        r = user_registry_ref_entry(&bus->users, &user, uid);
        if (r)
                return error_fold(r);

        activation = calloc(1, sizeof(*activation) + strlen(path) + 1);
        if (!activation)
                return error_origin(-ENOMEM);

        activation->bus = bus;
        activation->name = name_entry_ref(entry);
        activation->user = user_entry_ref(user);
        activation->socket_buffers = (CList)C_LIST_INIT(activation->socket_buffers);
        activation->bus_node = (CRBNode)C_RBNODE_INIT(activation->bus_node);
        memcpy((char*)activation->path, path, strlen(path) + 1);

        entry->activation = activation;
        c_rbtree_add(&bus->activation_tree, parent, slot, &activation->bus_node);

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

        assert(c_list_is_empty(&activation->socket_buffers));

        activation->user = user_entry_unref(activation->user);
        activation->name = name_entry_unref(activation->name);
        activation->name->activation = NULL;
        c_rbtree_remove_init(&activation->bus->activation_tree, &activation->bus_node);
        free(activation);

        return NULL;
}

Activation *activation_find(Bus *bus, const char *path) {
        return c_rbtree_find_entry(&bus->activation_tree, activation_compare, path, Activation, bus_node);
}

int activation_queue_message(Activation *activation, Message *message) {
        SocketBuffer *skb;
        int r;

        r = socket_buffer_new_message(&skb, message);
        if (r)
                return error_fold(r);

        c_list_link_tail(&activation->socket_buffers, &skb->link);

        return 0;
}
