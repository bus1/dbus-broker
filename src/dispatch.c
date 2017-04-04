/*
 * Event Dispatcher
 */

#include <c-list.h>
#include <c-macro.h>
#include <c-ref.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include "dispatch.h"

/**
 * dispatch_file_init() - XXX
 */
int dispatch_file_init(DispatchFile *file,
                       DispatchContext *ctx,
                       CList *ready_list,
                       DispatchFn fn,
                       int fd,
                       uint32_t mask) {
        int r;

        r = epoll_ctl(ctx->epoll_fd,
                      EPOLL_CTL_ADD,
                      fd,
                      &(struct epoll_event) {
                                .events = mask | EPOLLET,
                                .data.ptr = file,
                      });
        if (r < 0)
                return r;

        file->context = ctx;
        file->fn = fn;
        file->ready_list = ready_list;
        file->ready_link = (CList)C_LIST_INIT(file->ready_link);
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
        file->ready_list = NULL;
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
                c_list_link_tail(file->ready_list, &file->ready_link);
}

/**
 * dispatch_file_deselect() - XXX
 */
void dispatch_file_deselect(DispatchFile *file, uint32_t mask) {
        assert(!(mask & ~file->user_mask));

        file->user_mask &= ~mask;
        if (!(file->events & file->user_mask))
                c_list_unlink_init(&file->ready_link);
}

/**
 * dispatch_file_clear() - XXX
 */
void dispatch_file_clear(DispatchFile *file, uint32_t mask) {
        assert(!(mask & ~file->kernel_mask));

        file->events &= ~mask;
        if (!(file->events & file->user_mask))
                c_list_unlink_init(&file->ready_link);
}

/**
 * dispatch_context_init() - XXX
 */
int dispatch_context_init(DispatchContext *ctxp) {
        DispatchContext ctx = {};

        ctx.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (ctx.epoll_fd < 0)
                return -errno;

        *ctxp = ctx;
        return 0;
}

/**
 * dispatch_context_deinit() - XXX
 */
void dispatch_context_deinit(DispatchContext *ctx) {
        assert(!ctx->n_files);

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
                        return -ENOMEM;

                events = buffer;
        } else {
                events = alloca(n);
        }

        r = epoll_wait(ctx->epoll_fd, events, ctx->n_files, timeout);
        if (r < 0)
                return -errno;

        while (r > 0) {
                e = &events[--r];
                f = e->data.ptr;

                f->events |= e->events;
                if ((f->events & f->user_mask) &&
                    !c_list_is_linked(&f->ready_link))
                        c_list_link_tail(f->ready_list, &f->ready_link);
        }

        return 0;
}
