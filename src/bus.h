#pragma once

/*
 * Bus Context
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct Bus Bus;
typedef struct NameRegistry NameRegistry;
typedef struct UserRegistry UserRegistry;

struct Bus {
        NameRegistry *names;
        UserRegistry *users;
};

int bus_new(Bus **busp,
            unsigned int max_bytes,
            unsigned int max_fds,
            unsigned int max_names);
Bus *bus_free(Bus *bus);

C_DEFINE_CLEANUP(Bus *, bus_free);
