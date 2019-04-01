#pragma once

/*
 * D-Bus Service
 */

#include <c-macro.h>
#include <c-rbtree.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>
#include "launch/launcher.h"

typedef struct Service Service;

typedef enum {
        SERVICE_STATE_PENDING,
        SERVICE_STATE_CURRENT,
        SERVICE_STATE_DEFUNCT,
} ServiceState;

struct Service {
        Launcher *launcher;
        ServiceState state;
        bool not_found;
        sd_bus_slot *slot;
        CRBNode rb;
        CRBNode rb_by_name;
        char *path;
        char *name;
        char *unit;
        size_t argc;
        char **argv;
        char *user;
        uid_t uid;
        uint64_t instance;
        uint64_t n_missing_unit;
        char id[];
};

int service_new(Service **servicep,
                Launcher *launcher,
                const char *name,
                CRBNode **slot_by_name,
                CRBNode *parent_by_name,
                const char *path,
                const char *unit,
                size_t argc,
                char **argv,
                const char *user,
                uid_t uid);
Service *service_free(Service *service);

C_DEFINE_CLEANUP(Service *, service_free);

int service_update(Service *service, const char *path, const char *unit, size_t argc, char **argv, const char *user, uid_t uid);

int service_compare(CRBTree *t, void *k, CRBNode *n);
int service_compare_by_name(CRBTree *t, void *k, CRBNode *n);

int service_add(Service *service);
int service_activate(Service *service);
int service_remove(Service *service);
