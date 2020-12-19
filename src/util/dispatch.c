/*
 * Event Dispatcher
 *
 * This event dispatcher provides a simple wrapper around edge-triggered epoll.
 * It consists of a DispatchContext to represent the epoll-set, and a
 * DispatchFile for each file-descriptor added to that epoll-set. All events
 * are delivered in edge-triggered mode and cached in the DispatchFile. By
 * default, this means that we will get woken up for each event once, and cache
 * it. Since we don't use level-triggered mode, a continuous unhandled event
 * will not cause any further wakeups, unless the event is triggered by the
 * kernel again.
 *
 * On top of this edge-triggered mirror of the kernel space, we provide a
 * level-triggered callback mechanism. That is, on each dispatch-file you can
 * `select` and `deselect` events you're interested in. As long as an event is
 * selected, you will get notified of it in level-triggered mode (that is,
 * until you handled it). Since our cache is distinct from the kernel data, we
 * need explicit notification of when an event is handled. Therefore, you must
 * clear any event when you handled it. This usually means catching EAGAIN
 * and then clearing the event.
 *
 * Every DispatchFile has 3 event masks:
 *
 *     * kernel_mask: This mask is constant and must be provided at
 *                    initialization time. It describes the events that we
 *                    asked the kernel to report via epoll_ctl(2). For
 *                    performance reasons we never modify this mask. If there
 *                    ever arises a need to update this mask according to our
 *                    user-mask, this can be added later on.
 *
 *     * user_mask: This mask reflects the events that the user selected and
 *                  thus is interested in. It must always be a subset of
 *                  @kernel_mask. As long as an event is set in the event-mask
 *                  and in @user_mask, its callback will be invoked in a
 *                  level-triggered manner.
 *
 *     * events: This mask reflects the events the kernel signalled. That is,
 *               those events are always a subset of @kernel_mask and cached as
 *               soon as the kernel signalled them.
 *               You must explicitly clear events once you handled them. The
 *               kernel never tells us about falling edges, so we must detect
 *               them manually (usually via EAGAIN).
 */

#include <c-list.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include "util/dispatch.h"
#include "util/error.h"

/**
 * dispatch_file_init() - initialize dispatch file
 * @file:               dispatch file
 * @ctx:                dispatch context
 * @fn:                 callback function
 * @fd:                 file descriptor
 * @mask:               EPOLL* event mask
 * @events:             initial EPOLL* event mask before calling into the kernel
 *
 * This initializes a new dispatch-file and registers it with the given
 * dispatch-context. The file-descriptor @fd is added to the epoll-set of @ctx
 * with the event mask @mask.
 *
 * Note that all event handling is always edge-triggered. Hence, EPOLLET must
 * not be passed in @mask, but is added automatically. Furthermore, the event
 * mask in @mask is used to select kernel events for edge-triggered mode. To
 * actually get notified via your callback, you must select the user-mask via
 * dispatch_file_select().
 *
 * The file-descriptor @fd is *NOT* consumed by this function. That is, the
 * caller still owns it, and is responsible to close it when done. However, the
 * caller must make sure to call dispatch_file_deinit() *BEFORE* closing the
 * FD.
 *
 * Return: 0 on success, negative error code on failure.
 */
int dispatch_file_init(DispatchFile *file,
                       DispatchContext *ctx,
                       DispatchFn fn,
                       int fd,
                       uint32_t mask,
                       uint32_t events) {
        int r;

        c_assert(!(mask & EPOLLET));
        c_assert(!(events & ~mask));

        r = epoll_ctl(ctx->epoll_fd,
                      EPOLL_CTL_ADD,
                      fd,
                      &(struct epoll_event) {
                                .events = mask | EPOLLET,
                                .data.ptr = file,
                      });
        if (r < 0)
                return error_origin(-errno);

        file->context = ctx;
        file->ready_link = (CList)C_LIST_INIT(file->ready_link);
        file->fn = fn;
        file->fd = fd;
        file->user_mask = 0;
        file->kernel_mask = mask;
        file->events = events;

        ++file->context->n_files;

        return 0;
}

/**
 * dispatch_file_deinit() - deinitialize dispatch file
 * @file:               dispatch file
 *
 * This deinitialized the dispatch-file @file and unregisters it from its
 * context. The file is put into a deinitialized state, hence, it is safe to
 * call this function multiple times.
 *
 * The file-descriptor provided via dispatch_file_init() is *NOT* closed, but
 * left unchanged. However, the caller must make sure to call
 * dispatch_file_deinit() *BEFORE* closing the FD.
 */
void dispatch_file_deinit(DispatchFile *file) {
        int r;

        if (file->context) {
                /*
                 * There is no excuse to ever skip EPOLL_CTL_DEL. Epoll
                 * descriptors are not tied to FDs, but rather combinations of
                 * file+fd. Only if the file-description (sic) is destroyed, an
                 * epoll description is removed from the epoll set. Hence, we
                 * have no way to know whether this FD is the only FD for the
                 * given file-description. Nor do we know whether the caller
                 * intends to continue using the FD.
                 *
                 * Therefore, we always unconditionally remove FDs from the
                 * epoll-set, and require it to succeed. If the removal fails,
                 * you did something wrong and better fix it.
                 */
                r = epoll_ctl(file->context->epoll_fd, EPOLL_CTL_DEL, file->fd, NULL);
                c_assert(r >= 0);

                --file->context->n_files;
                c_list_unlink(&file->ready_link);
        }

        file->fd = -1;
        file->fn = NULL;
        file->context = NULL;
}

/**
 * dispatch_file_select() - select notification mask
 * @file:               dispatch file
 * @mask:               event mask
 *
 * This selects the events specified in @mask for notification. That is, if
 * those events are signalled by the kernel, the callback of @file will be
 * invoked for those events.
 *
 * Once you lost interest in a given event, you must deselect it via
 * dispatch_file_deselect(). Otherwise, you will keep being notified of the
 * event.
 *
 * Once you handled an event fully, you must clear it via dispatch_file_clear()
 * to tell the dispatcher that you should only be invoked for the event
 * when the kernel signals it again.
 */
void dispatch_file_select(DispatchFile *file, uint32_t mask) {
        c_assert(!(mask & ~file->kernel_mask));

        file->user_mask |= mask;
        if ((file->user_mask & file->events) && !c_list_is_linked(&file->ready_link))
                c_list_link_tail(&file->context->ready_list, &file->ready_link);
}

/**
 * dispatch_file_deselect() - deselect notification mask
 * @file:               dispatch file
 * @mask:               event mask
 *
 * This is the inverse of dispatch_file_select() and removes a given event mask
 * from the user-mask. The callback will no longer be invoked for those events.
 */
void dispatch_file_deselect(DispatchFile *file, uint32_t mask) {
        c_assert(!(mask & ~file->kernel_mask));

        file->user_mask &= ~mask;
        if (!(file->events & file->user_mask))
                c_list_unlink(&file->ready_link);
}

/**
 * dispatch_file_clear() - clear kernel event mask
 * @file:               dispatch file
 * @mask:               event mask
 *
 * This clears the events in @mask from the pending kernel event mask. That is,
 * those events are now considered as 'handled'. The kernel must notify us of
 * them again to reconsider them.
 */
void dispatch_file_clear(DispatchFile *file, uint32_t mask) {
        c_assert(!(mask & ~file->kernel_mask));

        file->events &= ~mask;
        if (!(file->events & file->user_mask))
                c_list_unlink(&file->ready_link);
}

/**
 * dispatch_context_init() - initialize dispatch context
 * @ctx:                dispatch context
 *
 * This initializes a new dispatch context.
 *
 * Return: 0 on success, negative error code on failure.
 */
int dispatch_context_init(DispatchContext *ctx) {
        *ctx = (DispatchContext)DISPATCH_CONTEXT_NULL(*ctx);

        ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (ctx->epoll_fd < 0)
                return error_origin(-errno);

        return 0;
}

/**
 * dispatch_context_deinit() - deinitialize dispatch context
 * @ctx:                dispatch context
 *
 * This deinitializes a dispatch context. The caller must make sure no
 * dispatch-file is registered on it.
 *
 * The context will be set into an deinitialized state afterwards. Hence, it is
 * safe to call this function multiple times.
 */
void dispatch_context_deinit(DispatchContext *ctx) {
        c_assert(!ctx->n_files);
        c_assert(c_list_is_empty(&ctx->ready_list));

        ctx->epoll_fd = c_close(ctx->epoll_fd);
}

/**
 * dispatch_context_poll() - fetch events from kernel
 * @ctx:                dispatch context
 * @timeout:            poll timeout
 *
 * This calls into epoll_wait(2) to fetch events on all registered
 * dispatch-files from the kernel. @timeout is passed unmodified to
 * epoll_wait().
 *
 * The events fetched from the kernel are merged into our list of
 * dispatch-files. Nothing is dispatched! The data is merely fetched from the
 * kernel.
 *
 * Return: 0 on success, negative error code on failure.
 */
int dispatch_context_poll(DispatchContext *ctx, int timeout) {
        _c_cleanup_(c_freep) void *buffer = NULL;
        struct epoll_event *events, *e;
        DispatchFile *f;
        size_t n;
        int r;

        n = ctx->n_files * sizeof(*events);
        if (n > 128UL * 1024UL) {
                buffer = malloc(n);
                if (!buffer)
                        return error_origin(-ENOMEM);

                events = buffer;
        } else {
                events = alloca(n);
        }

        r = epoll_wait(ctx->epoll_fd, events, ctx->n_files, timeout);
        if (r < 0) {
                if (errno == EINTR)
                        return 0;

                return error_origin(-errno);
        }

        while (r > 0) {
                e = &events[--r];
                f = e->data.ptr;

                c_assert(f->context == ctx);

                f->events |= e->events & f->kernel_mask;
                if ((f->events & f->user_mask) && !c_list_is_linked(&f->ready_link))
                        c_list_link_tail(&f->context->ready_list, &f->ready_link);
        }

        return 0;
}

/**
 * dispatch_context_dispatch() - dispatch pending events
 * @ctx:                dispatch context
 *
 * This runs one dispatch round on the given dispatch context. That is, it
 * dispatches all pending events and calls into the callbacks of the respective
 * dispatch-file.
 *
 * The first non-zero return code of any dispatch-file callback will break the
 * loop and cause a propagation of that error code to the caller.
 *
 * Return: 0 on success, otherwise the first non-zero return code of any
 *         dispatched file stops dispatching and is returned unmodified.
 */
int dispatch_context_dispatch(DispatchContext *ctx) {
        CList todo = (CList)C_LIST_INIT(todo);
        DispatchFile *file;
        int r;

        r = dispatch_context_poll(ctx, c_list_is_empty(&ctx->ready_list) ? -1 : 0);
        if (r)
                return error_fold(r);

        /*
         * We want to dispatch @ctx->ready_list exactly once here. The trivial
         * approach would be to iterate it via c_list_for_each(). However, we
         * want to allow callbacks to modify their event masks, so we must
         * allow them to add and remove files arbitrarily. At the same time, we
         * want to prevent dispatching a single file twice, so we must make
         * sure to detect detach+reattach cycles to avoid starvation.
         *
         * Therefore, we simply fetch the entire ready-list into @todo and
         * handle it one-by-one, moving them back onto the ready-list. This is
         * safe against entry-removal in the callbacks, and it has a clearly
         * determined runtime.
         */
        c_list_swap(&todo, &ctx->ready_list);

        while ((file = c_list_first_entry(&todo, DispatchFile, ready_link))) {
                c_list_unlink(&file->ready_link);
                c_list_link_tail(&ctx->ready_list, &file->ready_link);

                r = file->fn(file);
                if (error_trace(r)) {
                        c_list_splice(&ctx->ready_list, &todo);
                        break;
                }
        }

        c_assert(c_list_is_empty(&todo));
        return r;
}
