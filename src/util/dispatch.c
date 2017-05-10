/*
 * Event Dispatcher
 */

#include <c-list.h>
#include <c-macro.h>
#include <c-ref.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include "dispatch.h"
#include "error.h"

/**
 * dispatch_file_init() - XXX
 */
int dispatch_file_init(DispatchFile *file,
                       DispatchContext *ctx,
                       DispatchFn fn,
                       int fd,
                       uint32_t mask) {
        int r;

        assert(!(mask & (EPOLLET | EPOLLRDHUP)));

        if (mask & EPOLLIN)
                mask |= EPOLLRDHUP;

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
        file->events = 0;

        ++file->context->n_files;

        return 0;
}

/**
 * dispatch_file_deinit() - XXX
 */
void dispatch_file_deinit(DispatchFile *file) {
        int r;

        if (file->context) {
                r = epoll_ctl(file->context->epoll_fd, EPOLL_CTL_DEL, file->fd, NULL);
                assert(r >= 0);

                --file->context->n_files;
                c_list_unlink_init(&file->ready_link);
        }

        file->fd = -1;
        file->fn = NULL;
        file->context = NULL;
}

/**
 * dispatch_file_select() - XXX
 */
void dispatch_file_select(DispatchFile *file, uint32_t mask) {
        assert(!(mask & ~file->kernel_mask));

        file->user_mask |= mask;
        if ((file->user_mask & file->events) &&
            !c_list_is_linked(&file->ready_link))
                c_list_link_tail(&file->context->ready_list, &file->ready_link);
}

/**
 * dispatch_file_deselect() - XXX
 */
void dispatch_file_deselect(DispatchFile *file, uint32_t mask) {
        assert(!(mask & ~file->kernel_mask));

        file->user_mask &= ~mask;
        if (!(file->events & file->user_mask))
                c_list_unlink_init(&file->ready_link);
}

/**
 * dispatch_file_clear() - XXX
 */
void dispatch_file_clear(DispatchFile *file, uint32_t mask) {
        assert(!(mask & ~file->kernel_mask));

        if (_c_unlikely_((file->events & EPOLLRDHUP) && (mask & EPOLLIN) && (file->events & EPOLLIN))) {
                mask &= ~EPOLLIN;
                mask |= EPOLLRDHUP;
        }

        file->events &= ~mask;
        if (!(file->events & file->user_mask))
                c_list_unlink_init(&file->ready_link);
}

/**
 * dispatch_context_init() - XXX
 */
int dispatch_context_init(DispatchContext *ctxp) {
        int fd;

        fd = epoll_create1(EPOLL_CLOEXEC);
        if (fd < 0)
                return error_origin(-errno);

        *ctxp = (DispatchContext)DISPATCH_CONTEXT_NULL(*ctxp);
        ctxp->epoll_fd = fd;

        return 0;
}

/**
 * dispatch_context_deinit() - XXX
 */
void dispatch_context_deinit(DispatchContext *ctx) {
        assert(!ctx->n_files);
        assert(c_list_is_empty(&ctx->ready_list));

        ctx->epoll_fd = c_close(ctx->epoll_fd);
}

/**
 * dispatch_context_poll() - XXX
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

                f->events |= e->events & f->kernel_mask;
                if ((f->events & f->user_mask) &&
                    !c_list_is_linked(&f->ready_link))
                        c_list_link_tail(&f->context->ready_list, &f->ready_link);
        }

        return 0;
}

int dispatch_context_dispatch(DispatchContext *ctx) {
        CList processed = (CList)C_LIST_INIT(processed);
        DispatchFile *file;
        int r;

        r = dispatch_context_poll(ctx, c_list_is_empty(&ctx->ready_list) ? -1 : 0);
        if (r)
                return error_fold(r);

        while ((file = c_list_first_entry(&ctx->ready_list, DispatchFile, ready_link))) {

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

                r = file->fn(file, file->events & file->user_mask);
                if (error_trace(r))
                        break;
        }

        c_list_splice(&ctx->ready_list, &processed);
        return r;
}
