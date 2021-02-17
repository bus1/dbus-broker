#pragma once

/*
 * D-Bus Service
 */

#include <c-rbtree.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>
#include "launch/launcher.h"

typedef struct Service Service;

struct Service {
        Launcher *launcher;
        bool not_found;
        bool running;
        bool reload_tag;
        sd_bus_slot *slot_watch_jobs;
        sd_bus_slot *slot_watch_unit;
        sd_bus_slot *slot_start_unit;
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
        uint64_t n_masked_unit;
        uint64_t last_serial;
        char *job;
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
int service_activate(Service *service, uint64_t serial);
int service_remove(Service *service);
