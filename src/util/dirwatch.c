/*
 * Directory Watch
 *
 * The Dirwatch object implements a simple notification mechanism based on
 * file-system monitoring. It allows to get notified whenever a file inside of
 * a list of directories is modified.
 *
 * Since file-system monitoring is frowned upon, we only implement what is
 * necessary to be compatible to dbus-daemon. This means, only very basic
 * direct watches without detailed reporting are supported.
 */

#include <c-macro.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include "util/dirwatch.h"
#include "util/error.h"

/**
 * dirwatch_new() - initialize directory watch
 * @dwp:                output variable for directory watch
 *
 * This initializes a new directory watch.
 *
 * Return: 0 on success, negative error code on failure.
 */
int dirwatch_new(Dirwatch **dwp) {
        _c_cleanup_(dirwatch_freep) Dirwatch *dw = NULL;

        dw = malloc(sizeof(*dw));
        if (!dw)
                return error_origin(-ENOMEM);

        *dw = (Dirwatch)DIRWATCH_NULL(*dw);

        dw->inotify_fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
        if (dw->inotify_fd < 0)
                return error_origin(-errno);

        *dwp = dw;
        dw = NULL;
        return 0;
}

/**
 * dirwatch_free() - deinitialize directory watch
 * @dw:                 directory watch to operate on, or NULL
 *
 * This deinitializes @dw.
 *
 * Return: NULL is returned.
 */
Dirwatch *dirwatch_free(Dirwatch *dw) {
        if (dw) {
                c_close(dw->inotify_fd);
                free(dw);
        }
        return NULL;
}

/**
 * dirwatch_get_fd() - return context FD
 * @dw:                 directory watch to operate on
 *
 * Return the inotify context file-descriptor. The caller is supposed to
 * monitor it for read-events and call dirwatch_dispatch() when ready.
 *
 * Return: File-descriptor is returned.
 */
int dirwatch_get_fd(Dirwatch *dw) {
        return dw->inotify_fd;
}

/**
 * dirwatch_dispatch() - dispatch the directory watch
 * @dw:                 directory watch to operate on
 *
 * This dispatches all active events on the dirwatch. If a file-system
 * modification was detected, DIRWATCH_E_TRIGGERED is signalled to the caller.
 *
 * Return: 0 is returned on success, DIRWATCH_E_TRIGGERED if a file-system
 *         modification was detected, a negative error code on failure.
 */
int dirwatch_dispatch(Dirwatch *dw) {
        uint8_t buffer[16 * (sizeof(struct inotify_event) + NAME_MAX + 1)];
        bool triggered = false;
        ssize_t l;

        do {
                l = read(dw->inotify_fd, buffer, sizeof(buffer));
                if (l > 0) {
                        triggered = true;
                } else if (!l) {
                        return error_origin(-EINVAL);
                } else if (errno != EAGAIN) {
                        return error_origin(-errno);
                }
        } while (l > 0);

        return triggered ? DIRWATCH_E_TRIGGERED : 0;
}

/**
 * dirwatch_add() - add path to watch-list
 * @dw:                 directory watch to operate on
 * @path:               path to watch
 */
int dirwatch_add(Dirwatch *dw, const char *path) {
        int r;

        r = inotify_add_watch(dw->inotify_fd,
                              path,
                              IN_CLOSE_WRITE | IN_DELETE
                                             | IN_MOVED_TO
                                             | IN_MOVED_FROM);
        if (r < 0) {
                /* non-existant dirs are silently ignored by dbus-daemon */
                if (errno == ENOENT || errno == ENOTDIR)
                        return 0;

                return error_origin(-errno);
        }

        return 0;
}
