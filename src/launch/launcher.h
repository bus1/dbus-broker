#pragma once

/*
 * Launcher
 */

#include <c-rbtree.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>
#include "util/dirwatch.h"
#include "util/log.h"
#include "util/misc.h"

typedef struct Launcher Launcher;

enum {
        _LAUNCHER_E_SUCCESS,

        LAUNCHER_E_INVALID_CONFIG,
        LAUNCHER_E_INVALID_SERVICE_FILE,
};

struct Launcher {
        sd_event *event;
        sd_bus *bus_controller;
        sd_bus *bus_regular;
        Log log;
        int fd_listen;
        int fd_metrics;
        bool audit;
        bool user_scope;
        char *configfile;
        Dirwatch *dirwatch;
        sd_event_source *dirwatch_src;
        CRBTree services;
        CRBTree services_by_name;
        uint64_t service_ids;
        uint32_t uid;
        uint32_t gid;
        uint64_t max_bytes;
        uint64_t max_fds;
        uint64_t max_matches;
        bool at_console;
};

int launcher_new(
        Launcher **launcherp,
        int listen_fd,
        int metrics_fd,
        bool audit,
        const char *configfile,
        bool user_scope
);
Launcher *launcher_free(Launcher *launcher);

C_DEFINE_CLEANUP(Launcher *, launcher_free);

int launcher_listen_inherit(Launcher *launcher);
int launcher_run(Launcher *launcher);
