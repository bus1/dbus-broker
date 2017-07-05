#pragma once

/*
 * Broker
 */

#include <c-macro.h>
#include <stdlib.h>
#include "broker/controller.h"
#include "bus/bus.h"
#include "util/dispatch.h"

typedef struct Broker Broker;

struct Broker {
        Bus bus;
        DispatchContext dispatcher;

        int signals_fd;
        DispatchFile signals_file;

        Controller controller;
};

int broker_new(Broker **brokerp, int controller_fd);
Broker *broker_free(Broker *broker);

int broker_run(Broker *broker);

C_DEFINE_CLEANUP(Broker *, broker_free);
