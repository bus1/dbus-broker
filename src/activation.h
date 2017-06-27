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
typedef struct ActivationMessage ActivationMessage;
typedef struct ActivationRegistry ActivationRegistry;
typedef struct ActivationRequest ActivationRequest;
typedef struct Message Message;
typedef struct Name Name;
typedef struct User User;

enum {
        _ACTIVATION_E_SUCCESS,

        ACTIVATION_E_EXISTS,
        ACTIVATION_E_ALREADY_ACTIVATABLE,
};

struct ActivationRequest {
        uint64_t sender_id;
        uint32_t serial;
        CList link;
};

struct ActivationMessage {
        CList link;
        Message *message;
};

struct Activation {
        ActivationRegistry *registry;
        Name *name;

        User *user;
        CList activation_messages;
        CList activation_requests;
        bool requested : 1;

        CRBNode registry_node;
        const char path[];
};

struct ActivationRegistry {
        CRBTree activation_tree;
};

ActivationRequest *activation_request_free(ActivationRequest *request);

ActivationMessage *activation_message_free(ActivationMessage *message);

int activation_new(Activation **activationp, ActivationRegistry *registry, const char *path, Name *name, User *user);
Activation *activation_free(Activation *free);

int activation_queue_message(Activation *activation, Message *m);
int activation_queue_request(Activation *activation, uint64_t sender_id, uint32_t serial);

int activation_flush(Activation *activation);

void activation_registry_init(ActivationRegistry *registry);
void activation_registry_deinit(ActivationRegistry *registry);

void activation_registry_flush(ActivationRegistry *registry);

Activation *activation_registry_find(ActivationRegistry *registry, const char *path);

C_DEFINE_CLEANUP(Activation *, activation_free);
