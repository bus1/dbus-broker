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
#include "main.h"
#include "manager.h"
#include "user.h"
#include "util/dispatch.h"
#include "util/error.h"

struct Manager {
        UserRegistry users;
        DispatchContext dispatcher;

        int signals_fd;
        DispatchFile signals_file;

        Connection controller;
};

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

static int manager_dispatch_controller_message(Manager *manager, Message *m) {
        return 0;
}

static int manager_dispatch_controller(DispatchFile *file, uint32_t events) {
        Manager *manager = c_container_of(file, Manager, controller.socket_file);
        int r;

        if (dispatch_file_is_ready(file, EPOLLIN)) {
                r = connection_dispatch(&manager->controller, EPOLLIN);
                if (r)
                        return error_fold(r);
        }

        if (dispatch_file_is_ready(file, EPOLLHUP)) {
                r = connection_dispatch(&manager->controller, EPOLLHUP);
                if (r)
                        return error_fold(r);
        }

        for (;;) {
                _c_cleanup_(message_unrefp) Message *m = NULL;

                r = connection_dequeue(&manager->controller, &m);
                if (r == CONNECTION_E_EOF) {
                        connection_shutdown(&manager->controller);
                        break;
                } else if (r == CONNECTION_E_RESET) {
                        connection_close(&manager->controller);
                        return DISPATCH_E_EXIT;
                } else if (r) {
                        return error_fold(r);
                }

                if (!m)
                        break;

                r = manager_dispatch_controller_message(manager, m);
                if (r)
                        return error_trace(r);
        }

        if (dispatch_file_is_ready(file, EPOLLOUT)) {
                r = connection_dispatch(&manager->controller, EPOLLOUT);
                if (r)
                        return error_fold(r);
        }

        return 0;
}

int manager_new(Manager **managerp, int controller_fd) {
        _c_cleanup_(manager_freep) Manager *manager = NULL;
        _c_cleanup_(user_entry_unrefp) UserEntry *user = NULL;
        struct ucred ucred;
        socklen_t z_ucred;
        sigset_t sigmask;
        int r;

        r = getsockopt(controller_fd, SOL_SOCKET, SO_PEERCRED, &ucred, &z_ucred);
        if (r < 0)
                return error_origin(-errno);

        manager = calloc(1, sizeof(*manager));
        if (!manager)
                return error_origin(-ENOMEM);

        user_registry_init(&manager->users, 16 * 1024 * 1024, 128, 128, 128, 128);
        manager->dispatcher = (DispatchContext)DISPATCH_CONTEXT_NULL(manager->dispatcher);
        manager->signals_fd = -1;
        manager->signals_file = (DispatchFile)DISPATCH_FILE_NULL(manager->signals_file);
        manager->controller = (Connection)CONNECTION_NULL(manager->controller);

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
                               &manager->dispatcher.ready_list,
                               manager_dispatch_signals,
                               manager->signals_fd,
                               EPOLLIN);
        if (r)
                return error_fold(r);

        r = user_registry_ref_entry(&manager->users, &user, ucred.uid);
        if (r)
                return error_fold(r);

        r = connection_init_server(&manager->controller,
                                   &manager->dispatcher,
                                   &manager->dispatcher.ready_list,
                                   manager_dispatch_controller,
                                   user,
                                   "0123456789abcdef",
                                   controller_fd);
        if (r)
                return error_fold(r);

        dispatch_file_select(&manager->signals_file, EPOLLIN);

        *managerp = manager;
        manager = NULL;
        return 0;
}

Manager *manager_free(Manager *manager) {
        if (!manager)
                return NULL;

        connection_deinit(&manager->controller);
        dispatch_file_deinit(&manager->signals_file);
        c_close(manager->signals_fd);
        dispatch_context_deinit(&manager->dispatcher);
        user_registry_deinit(&manager->users);
        free(manager);

        return NULL;
}

static int manager_dispatch(Manager *manager) {
        CList processed = (CList)C_LIST_INIT(processed);
        DispatchFile *file;
        int r;

        r = dispatch_context_poll(&manager->dispatcher, c_list_is_empty(&manager->dispatcher.ready_list) ? -1 : 0);
        if (r)
                return error_fold(r);

        do {
                while (!r && (file = c_list_first_entry(&manager->dispatcher.ready_list, DispatchFile, ready_link))) {

                        /*
                         * Whenever we dispatch an entry, we first move it into
                         * a separate list, so if it modifies itself or others,
                         * it will not corrupt our list iterator.
                         *
                         * Then we call into is dispatcher, so it can handle
                         * the I/O events. The dispatchers can use DISPATCH_E_EXIT
                         * or DISPATCH_E_FAILURE to exit the main-loop. Everything
                         * else is treated as fatal.
                         */

                        c_list_unlink(&file->ready_link);
                        c_list_link_tail(&processed, &file->ready_link);

                        r = dispatch_file_call(file);
                        if (r == DISPATCH_E_EXIT)
                                r = MAIN_EXIT;
                        else if (r == DISPATCH_E_FAILURE)
                                r = MAIN_FAILED;
                        else
                                r = error_fold(r);
                }
        } while (!r);

        c_list_splice(&manager->dispatcher.ready_list, &processed);
        return r;
}

int manager_run(Manager *manager) {
        sigset_t signew, sigold;
        int r;

        sigemptyset(&signew);
        sigaddset(&signew, SIGTERM);
        sigaddset(&signew, SIGINT);

        sigprocmask(SIG_BLOCK, &signew, &sigold);

        do {
                r = manager_dispatch(manager);
        } while (!r);

        sigprocmask(SIG_SETMASK, &sigold, NULL);

        return error_trace(r);
}
