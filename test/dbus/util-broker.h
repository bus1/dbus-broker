#pragma once

/*
 * Test Infrastructure around dbus-broker
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>

typedef struct Broker Broker;

struct Broker {
        pthread_t thread;
        struct sockaddr_un address;
        socklen_t n_address;
        int listener_fd;
        int pipe_fds[2];
        pid_t pid;
        pid_t child_pid;
};

#define BROKER_NULL {                                                           \
                .address.sun_family = AF_UNIX,                                  \
                .n_address = sizeof(struct sockaddr_un),                        \
                .listener_fd = -1,                                              \
                .pipe_fds[0] = -1,                                              \
                .pipe_fds[1] = -1,                                              \
        }

/* misc */

bool util_is_reference(void);
void util_event_new(sd_event **eventp);
void util_fork_broker(sd_bus **busp, sd_event *event, int listener_fd, pid_t *pidp);
void util_fork_daemon(sd_event *event, int pipe_fd, pid_t *pidp);

/* broker */

void util_broker_new(Broker **brokerp);
Broker *util_broker_free(Broker *broker);
void util_broker_spawn(Broker *broker);
void util_broker_terminate(Broker *broker);
void util_broker_settle(Broker *broker);

void util_broker_connect_fd(Broker *broker, int *fdp);
void util_broker_connect_raw(Broker *broker, sd_bus **busp);
void util_broker_connect(Broker *broker, sd_bus **busp);
void util_broker_connect_monitor(Broker *broker, sd_bus **busp);
void util_broker_disconnect(sd_bus *bus);

void util_broker_consume_method_call(sd_bus *bus, const char *interface, const char *member);
void util_broker_consume_method_return(sd_bus *bus);
void util_broker_consume_method_error(sd_bus *bus, const char *name);
void util_broker_consume_signal(sd_bus *bus, const char *interface, const char *member);

C_DEFINE_CLEANUP(Broker *, util_broker_free);
