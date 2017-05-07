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
typedef struct Bus Bus;
typedef struct Message Message;
typedef struct NameEntry NameEntry;
typedef struct UserEntry UserEntry;

enum {
        _ACTIVATION_E_SUCCESS,

        ACTIVATION_E_EXISTS,
        ACTIVATION_E_ALREADY_ACTIVATABLE,
};

struct Activation {
        Bus *bus;
        NameEntry *name;

        UserEntry *user;
        CList socket_buffers;
        bool requested : 1;

        CRBNode bus_node;
        const char path[];
};

int activation_new(Activation **activationp, Bus *bus, const char *path, const char *name, uid_t uid);
Activation *activation_free(Activation *free);

int activation_queue_message(Activation *activation, Message *message);

C_DEFINE_CLEANUP(Activation *, activation_free);
