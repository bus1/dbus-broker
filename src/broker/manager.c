/*
 * Bus Manager
 */

#include <c-list.h>
#include <c-macro.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "dbus/connection.h"
#include "dbus/message.h"
#include "bus.h"
#include "controller.h"
#include "main.h"
#include "manager.h"
#include "util/dispatch.h"
#include "util/error.h"
#include "util/user.h"

static int manager_dispatch_signals(DispatchFile *file, uint32_t events) {
        Manager *manager = c_container_of(file, Manager, signals_file);
        struct signalfd_siginfo si;
        ssize_t l;

        assert(events == EPOLLIN);

        l = read(manager->signals_fd, &si, sizeof(si));
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

int manager_new(Manager **managerp, int controller_fd) {
        _c_cleanup_(manager_freep) Manager *manager = NULL;
        struct ucred ucred;
        socklen_t z_ucred = sizeof(ucred);
        sigset_t sigmask;
        int r;

        r = getsockopt(controller_fd, SOL_SOCKET, SO_PEERCRED, &ucred, &z_ucred);
        if (r < 0)
                return error_origin(-errno);

        manager = calloc(1, sizeof(*manager));
        if (!manager)
                return error_origin(-ENOMEM);

        manager->bus = (Bus)BUS_NULL(manager->bus);
        manager->dispatcher = (DispatchContext)DISPATCH_CONTEXT_NULL(manager->dispatcher);
        manager->signals_fd = -1;
        manager->signals_file = (DispatchFile)DISPATCH_FILE_NULL(manager->signals_file);
        manager->controller = (Controller)CONTROLLER_NULL(manager->controller);

        r = bus_init(&manager->bus, 16 * 1024 * 1024, 1024, 10 * 1024, 10 * 1024);
        if (r)
                return error_fold(r);

        manager->bus.controller = &manager->controller.connection;
        manager->bus.pid = ucred.pid;
        r = user_registry_ref_user(&manager->bus.users, &manager->bus.user, ucred.uid);
        if (r)
                return error_fold(r);

        r = dispatch_context_init(&manager->dispatcher);
        if (r)
                return error_fold(r);

        sigemptyset(&sigmask);
        sigaddset(&sigmask, SIGTERM);
        sigaddset(&sigmask, SIGINT);

        manager->signals_fd = signalfd(-1, &sigmask, SFD_CLOEXEC | SFD_NONBLOCK);
        if (manager->signals_fd < 0)
                return error_origin(-errno);

        r = dispatch_file_init(&manager->signals_file,
                               &manager->dispatcher,
                               manager_dispatch_signals,
                               manager->signals_fd,
                               EPOLLIN);
        if (r)
                return error_fold(r);

        dispatch_file_select(&manager->signals_file, EPOLLIN);

        r = controller_init(&manager->controller, manager, controller_fd);
        if (r)
                return error_fold(r);

        *managerp = manager;
        manager = NULL;
        return 0;
}

Manager *manager_free(Manager *manager) {
        if (!manager)
                return NULL;

        controller_deinit(&manager->controller);
        dispatch_file_deinit(&manager->signals_file);
        c_close(manager->signals_fd);
        dispatch_context_deinit(&manager->dispatcher);
        bus_deinit(&manager->bus);
        free(manager);

        return NULL;
}

int manager_run(Manager *manager) {
        sigset_t signew, sigold;
        int r;

        sigemptyset(&signew);
        sigaddset(&signew, SIGTERM);
        sigaddset(&signew, SIGINT);

        sigprocmask(SIG_BLOCK, &signew, &sigold);

        r = connection_open(&manager->controller.connection);
        if (r == CONNECTION_E_EOF)
                return MAIN_EXIT;
        else if (r)
                return error_fold(r);

        do {
                r = dispatch_context_dispatch(&manager->dispatcher);
                if (r == DISPATCH_E_EXIT)
                        r = MAIN_EXIT;
                else if (r == DISPATCH_E_FAILURE)
                        r = MAIN_FAILED;
                else
                        r = error_fold(r);
        } while (!r);

        peer_registry_flush(&manager->bus.peers);

        sigprocmask(SIG_SETMASK, &sigold, NULL);

        return r;
}
