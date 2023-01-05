#pragma once

/*
 * Broker
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include <systemd/sd-event.h>
#include "broker/controller.h"
#include "bus/bus.h"
#include "util/dispatch.h"
#include "util/log.h"

#define OPTION_NUM_MAX 20

enum {
        _BROKER_E_SUCCESS,

        BROKER_E_FORWARD_FAILED,
};

typedef struct Broker Broker;
typedef struct BrokerArg BrokerArg;
typedef struct User User;

struct BrokerArg {
        const char *bin_path;
        const char *machine_id;
        bool arg_audit;
        int log_fd;
        int controller_fd;
        int mem_fd;
        uint64_t max_bytes;
        uint64_t max_fds;
        uint64_t max_matches;
        uint64_t max_objects;
};

struct Broker {
        sd_event *event;
        Log log;
        Bus bus;
        DispatchContext dispatcher;

        int signals_fd;
        int reexec_serial;
        bool arg_audit;
        bool do_reexec;
        const char *bin_path;
        const char *machine_id;
        int log_fd;
        int controller_fd;
        int mem_fd;
        uint64_t max_bytes;
        uint64_t max_fds;
        uint64_t max_matches;
        uint64_t max_objects;
        pid_t launcher_pid;
        DispatchFile signals_file;

        Controller controller;
};

/* broker */

int broker_new(Broker **brokerp, BrokerArg *broker_arg);
Broker *broker_free(Broker *broker);

int broker_run(Broker *broker);
int broker_update_environment(Broker *broker, const char * const *env, size_t n_env);
int broker_reload_config(Broker *broker, User *sender_user, uint64_t sender_id, uint32_t sender_serial);

C_DEFINE_CLEANUP(Broker *, broker_free);

/* inline helpers */

static inline Broker *BROKER(Bus *bus) {
        /*
         * This function up-casts a Bus to its parent class Broker. In our code
         * base we pretend a Bus is an abstract class with several virtual
         * methods. However, we only do this to clearly separate our code
         * bases. We never intended this to be modular. Hence, instead of
         * providing real vtables with userdata pointers, we instead allow
         * explicit up-casts to the parent type.
         *
         * This function performs the up-cast, relying on the fact that all our
         * Bus objects are always owned by a Broker object.
         */
        return c_container_of(bus, Broker, bus);
}
int deserialize_broker(Broker *broker, int mem_fd);
