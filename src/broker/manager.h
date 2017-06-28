#pragma once

/*
 * Bus Manager
 */

#include <c-macro.h>
#include <stdlib.h>
#include "broker/controller.h"
#include "bus.h"
#include "dbus/connection.h"
#include "util/dispatch.h"

typedef struct Manager Manager;

struct Manager {
        Bus bus;
        DispatchContext dispatcher;

        int signals_fd;
        DispatchFile signals_file;

        Connection controller;
        Controller ctrl;
};

int manager_new(Manager **managerp, int controller_fd);
Manager *manager_free(Manager *manager);

int manager_run(Manager *manager);

C_DEFINE_CLEANUP(Manager *, manager_free);
