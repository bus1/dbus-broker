/*
 * Broker
 */

#include <c-list.h>
#include <c-macro.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "broker/broker.h"
#include "broker/controller.h"
#include "broker/main.h"
#include "bus/bus.h"
#include "dbus/connection.h"
#include "dbus/message.h"
#include "util/dispatch.h"
#include "util/error.h"
#include "util/log.h"
#include "util/proc.h"
#include "util/user.h"

static int broker_dispatch_signals(DispatchFile *file) {
        Broker *broker = c_container_of(file, Broker, signals_file);
        struct signalfd_siginfo si;
        ssize_t l;

        assert(dispatch_file_events(file) == EPOLLIN);

        l = read(broker->signals_fd, &si, sizeof(si));
        if (l < 0)
                return error_origin(-errno);

        assert(l == sizeof(si));

        if (main_arg_verbose)
                fprintf(stderr,
                        "Caught %s, exiting\n",
                        (si.ssi_signo == SIGTERM ? "SIGTERM" :
                         si.ssi_signo == SIGINT ? "SIGINT" :
                         "SIG?"));

        return DISPATCH_E_EXIT;
}

int broker_new(Broker **brokerp, int log_fd, int controller_fd, uint64_t max_bytes, uint64_t max_fds, uint64_t max_matches, uint64_t max_objects) {
        _c_cleanup_(broker_freep) Broker *broker = NULL;
        struct ucred ucred;
        socklen_t z;
        sigset_t sigmask;
        int r, log_type;

        if (log_fd >= 0) {
                z = sizeof(log_type);
                r = getsockopt(log_fd, SOL_SOCKET, SO_TYPE, &log_type, &z);
                if (r < 0)
                        return error_origin(-errno);
        }

        z = sizeof(ucred);
        r = getsockopt(controller_fd, SOL_SOCKET, SO_PEERCRED, &ucred, &z);
        if (r < 0)
                return error_origin(-errno);

        broker = calloc(1, sizeof(*broker));
        if (!broker)
                return error_origin(-ENOMEM);

        broker->log = (Log)LOG_NULL;
        broker->bus = (Bus)BUS_NULL(broker->bus);
        broker->dispatcher = (DispatchContext)DISPATCH_CONTEXT_NULL(broker->dispatcher);
        broker->signals_fd = -1;
        broker->signals_file = (DispatchFile)DISPATCH_FILE_NULL(broker->signals_file);
        broker->controller = (Controller)CONTROLLER_NULL(broker->controller);

        if (log_fd < 0)
                log_init(&broker->log);
        else if (log_type == SOCK_STREAM)
                log_init_stderr(&broker->log, log_fd);
        else if (log_type == SOCK_DGRAM)
                log_init_journal(&broker->log, log_fd);
        else
                return error_origin(-ENOTRECOVERABLE);

        /* XXX: make this run-time optional */
        log_set_lossy(&broker->log, true);

        r = bus_init(&broker->bus, &broker->log, max_bytes, max_fds, max_matches, max_objects);
        if (r)
                return error_fold(r);

        r = proc_get_seclabel(&broker->bus.seclabel, &broker->bus.n_seclabel);
        if (r)
                return error_fold(r);

        broker->bus.pid = ucred.pid;
        r = user_registry_ref_user(&broker->bus.users, &broker->bus.user, ucred.uid);
        if (r)
                return error_fold(r);

        r = dispatch_context_init(&broker->dispatcher);
        if (r)
                return error_fold(r);

        sigemptyset(&sigmask);
        sigaddset(&sigmask, SIGTERM);
        sigaddset(&sigmask, SIGINT);

        broker->signals_fd = signalfd(-1, &sigmask, SFD_CLOEXEC | SFD_NONBLOCK);
        if (broker->signals_fd < 0)
                return error_origin(-errno);

        r = dispatch_file_init(&broker->signals_file,
                               &broker->dispatcher,
                               broker_dispatch_signals,
                               broker->signals_fd,
                               EPOLLIN,
                               0);
        if (r)
                return error_fold(r);

        dispatch_file_select(&broker->signals_file, EPOLLIN);

        r = controller_init(&broker->controller, broker, controller_fd);
        if (r)
                return error_fold(r);

        *brokerp = broker;
        broker = NULL;
        return 0;
}

Broker *broker_free(Broker *broker) {
        if (!broker)
                return NULL;

        controller_deinit(&broker->controller);
        dispatch_file_deinit(&broker->signals_file);
        c_close(broker->signals_fd);
        dispatch_context_deinit(&broker->dispatcher);
        bus_deinit(&broker->bus);
        log_deinit(&broker->log);
        free(broker);

        return NULL;
}

int broker_run(Broker *broker) {
        sigset_t signew, sigold;
        int r;

        sigemptyset(&signew);
        sigaddset(&signew, SIGTERM);
        sigaddset(&signew, SIGINT);

        sigprocmask(SIG_BLOCK, &signew, &sigold);

        r = connection_open(&broker->controller.connection);
        if (r == CONNECTION_E_EOF)
                return MAIN_EXIT;
        else if (r)
                return error_fold(r);

        do {
                r = dispatch_context_dispatch(&broker->dispatcher);
                if (r == DISPATCH_E_EXIT)
                        r = MAIN_EXIT;
                else if (r == DISPATCH_E_FAILURE)
                        r = MAIN_FAILED;
                else
                        r = error_fold(r);
        } while (!r);

        peer_registry_flush(&broker->bus.peers);

        sigprocmask(SIG_SETMASK, &sigold, NULL);

        return r;
}

int broker_update_environment(Broker *broker, const char * const *env, size_t n_env) {
        return error_fold(controller_dbus_send_environment(&broker->controller, env, n_env));
}

int broker_reload_config(Broker *broker, User *sender_user, uint64_t sender_id, uint32_t sender_serial) {
        int r;

        r = controller_request_reload(&broker->controller, sender_user, sender_id, sender_serial);
        if (r) {
                if (r == CONTROLLER_E_SERIAL_EXHAUSTED ||
                    r == CONTROLLER_E_QUOTA)
                        return BROKER_E_FORWARD_FAILED;

                return error_fold(r);
        }

        return 0;
}
