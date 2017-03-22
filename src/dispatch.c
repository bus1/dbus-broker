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
void dispatch_file_init(DispatchFile *file,
                        DispatchFn fn,
                        DispatchContext *ctx,
                        CList *ready_list) {
        file->context = ctx;
        file->fn = fn;
        file->ready_list = ready_list;
        file->ready_link = (CList)C_LIST_INIT(file->ready_link);
        file->fd = -1;
        file->mask = 0;
        file->events = 0;

        ++file->context->n_files;
}

/**
 * dispatch_file_deinit() - XXX
 */
void dispatch_file_deinit(DispatchFile *file) {
        dispatch_file_drop(file);

        if (file->context)
                --file->context->n_files;

        c_list_unlink_init(&file->ready_link);
        file->ready_list = NULL;
        file->fn = NULL;
        file->context = NULL;
}

/**
 * dispatch_file_select() - XXX
 */
int dispatch_file_select(DispatchFile *file, int fd, uint32_t mask) {
        int r;

        if (fd != file->fd) {
                r = epoll_ctl(file->context->epoll_fd,
                              EPOLL_CTL_ADD,
                              fd,
                              &(struct epoll_event){
                                      .events = mask,
                                      .data.ptr = file,
                              });
                if (r < 0)
                        return -errno;

                dispatch_file_drop(file);
                file->fd = fd;
                file->mask = mask;
        } else if (mask != file->mask) {
                r = epoll_ctl(file->context->epoll_fd,
                              EPOLL_CTL_MOD,
                              file->fd,
                              &(struct epoll_event){
                                      .events = mask,
                                      .data.ptr = file,
                              });
                if (r < 0)
                        return -errno;

                file->mask = mask;
                file->events &= ~mask;
                if (!file->events)
                        c_list_unlink_init(&file->ready_link);
        }

        return 0;
}

/**
 * dispatch_file_clear() - XXX
 */
void dispatch_file_clear(DispatchFile *file, uint32_t mask) {
        file->events &= ~mask;
        if (!file->events)
                c_list_unlink_init(&file->ready_link);
}

/**
 * dispatch_file_drop() - XXX
 */
void dispatch_file_drop(DispatchFile *file) {
        int r;

        if (file->fd < 0)
                return;

        r = epoll_ctl(file->context->epoll_fd, EPOLL_CTL_DEL, file->fd, NULL);
        assert(r >= 0);

        c_list_unlink_init(&file->ready_link);
        file->fd = -1;
        file->events = 0;
        file->mask = 0;
}

/**
 * dispatch_context_new() - XXX
 */
int dispatch_context_new(DispatchContext **ctxp) {
        _c_cleanup_(dispatch_context_freep) DispatchContext *ctx = NULL;

        ctx = calloc(1, sizeof(*ctx));
        if (!ctx)
                return -ENOMEM;

        ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (ctx->epoll_fd < 0)
                return -errno;

        *ctxp = ctx;
        ctx = NULL;
        return 0;
}

/**
 * dispatch_context_free() - XXX
 */
DispatchContext *dispatch_context_free(DispatchContext *ctx) {
        if (!ctx)
                return NULL;

        assert(!ctx->n_files);

        c_close(ctx->epoll_fd);
        free(ctx);

        return NULL;
}

/**
 * dispatch_context_poll() - XXX
 */
int dispatch_context_poll(DispatchContext *ctx, int timeout, const sigset_t *sigset) {
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

        r = epoll_pwait(ctx->epoll_fd, events, ctx->n_files, timeout, sigset);
        if (r < 0)
                return -errno;

        while (r > 0) {
                e = &events[--r];
                f = e->data.ptr;

                f->events |= e->events;
                if ((f->events & f->mask) &&
                    !c_list_is_linked(&f->ready_link))
                        c_list_link_tail(f->ready_list, &f->ready_link);
        }

        return 0;
}
