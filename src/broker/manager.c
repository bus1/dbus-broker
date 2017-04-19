/*
 * Bus Manager
 */

#include <c-list.h>
#include <c-macro.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include "main.h"
#include "manager.h"
#include "util/dispatch.h"
#include "util/error.h"

struct Manager {
        DispatchContext dispatcher;
        CList dispatcher_list;

        int signals_fd;
        DispatchFile signals_file;
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

int manager_new(Manager **managerp) {
        _c_cleanup_(manager_freep) Manager *manager = NULL;
        sigset_t sigmask;
        int r;

        manager = calloc(1, sizeof(*manager));
        if (!manager)
                return error_origin(-ENOMEM);

        manager->dispatcher = (DispatchContext)DISPATCH_CONTEXT_NULL;
        manager->dispatcher_list = (CList)C_LIST_INIT(manager->dispatcher_list);
        manager->signals_fd = -1;
        manager->signals_file = (DispatchFile)DISPATCH_FILE_NULL(manager->signals_file);

        r = dispatch_context_init(&manager->dispatcher);
        if (r)
                return error_fold(r);

        sigemptyset(&sigmask);
        sigaddset(&sigmask, SIGTERM);
        sigaddset(&sigmask, SIGINT);
        sigprocmask(SIG_BLOCK, &sigmask, NULL);

        manager->signals_fd = signalfd(-1, &sigmask, SFD_CLOEXEC | SFD_NONBLOCK);
        if (manager->signals_fd < 0)
                return error_origin(-errno);

        r = dispatch_file_init(&manager->signals_file,
                               &manager->dispatcher,
                               &manager->dispatcher_list,
                               manager_dispatch_signals,
                               manager->signals_fd,
                               EPOLLIN);
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

        dispatch_file_deinit(&manager->signals_file);
        c_close(manager->signals_fd);
        assert(c_list_is_empty(&manager->dispatcher_list));
        dispatch_context_deinit(&manager->dispatcher);
        free(manager);

        return NULL;
}

static int manager_dispatch(Manager *manager) {
        CList processed = (CList)C_LIST_INIT(processed);
        DispatchFile *file;
        int r;

        r = dispatch_context_poll(&manager->dispatcher, c_list_is_empty(&manager->dispatcher_list) ? -1 : 0);
        if (r)
                return error_fold(r);

        while (!r && (file = c_list_first_entry(&manager->dispatcher_list, DispatchFile, ready_link))) {
                c_list_unlink(&file->ready_link);
                c_list_link_tail(&processed, &file->ready_link);

                r = dispatch_file_call(file);
                if (r == DISPATCH_E_EXIT)
                        r = MAIN_EXIT;
                else if (r == DISPATCH_E_FAILURE)
                        r = MAIN_FAILED;
                else if (r != 0)
                        r = error_fold(r);
        }

        c_list_splice(&manager->dispatcher_list, &processed);
        return r;
}

int manager_run(Manager *manager) {
        int r;

        do {
                r = manager_dispatch(manager);
        } while (!r);

        return r;
}
