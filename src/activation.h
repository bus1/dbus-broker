#pragma once

/*
 * Name Activation
 */

#include <c-list.h>
#include <c-macro.h>
#include <c-rbtree.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct Activation Activation;
typedef struct ActivationRegistry ActivationRegistry;
typedef struct Message Message;
typedef struct Name Name;
typedef struct UserEntry UserEntry;

enum {
        _ACTIVATION_E_SUCCESS,

        ACTIVATION_E_EXISTS,
        ACTIVATION_E_ALREADY_ACTIVATABLE,
};

struct Activation {
        ActivationRegistry *registry;
        Name *name;

        UserEntry *user;
        CList socket_buffers;
        bool requested : 1;

        CRBNode registry_node;
        const char path[];
};

struct ActivationRegistry {
        CRBTree activation_tree;
};

int activation_new(Activation **activationp, ActivationRegistry *registry, const char *path, Name *name, UserEntry *user);
Activation *activation_free(Activation *free);

int activation_queue_message(Activation *activation, Message *message);

void activation_registry_init(ActivationRegistry *registry);
void activation_registry_deinit(ActivationRegistry *registry);

Activation *activation_registry_find(ActivationRegistry *registry, const char *path);

C_DEFINE_CLEANUP(Activation *, activation_free);
