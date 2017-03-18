#pragma once

/*
 * Event Dispatcher
 */

#include <c-list.h>
#include <c-macro.h>
#include <c-ref.h>
#include <stdlib.h>

typedef struct DispatchContext DispatchContext;
typedef struct DispatchFile DispatchFile;
typedef int (*DispatchFn) (DispatchFile *file, uint32_t events);

/* files */

struct DispatchFile {
        DispatchContext *context;
        DispatchFn fn;
        CList *ready_list;
        CList ready_link;

        int fd;
        uint32_t mask;
        uint32_t events;
};

void dispatch_file_init(DispatchFile *file,
                        DispatchFn fn,
                        DispatchContext *ctx,
                        CList *ready_list);
void dispatch_file_deinit(DispatchFile *file);

int dispatch_file_select(DispatchFile *file, int fd, uint32_t mask);
void dispatch_file_clear(DispatchFile *file, uint32_t mask);
void dispatch_file_drop(DispatchFile *file);

/* contexts */

struct DispatchContext {
        _Atomic unsigned long n_refs;
        int epoll_fd;
        size_t n_files;
};

int dispatch_context_new(DispatchContext **ctxp);
void dispatch_context_free(_Atomic unsigned long *n_refs, void *userdata);

int dispatch_context_poll(DispatchContext *ctx, int timeout, const sigset_t *sigset);

/**
 * dispatch_context_ref() - XXX
 */
static inline DispatchContext *dispatch_context_ref(DispatchContext *ctx) {
        if (ctx)
                c_ref_inc(&ctx->n_refs);
        return ctx;
}

/**
 * dispatch_context_unref() - XXX
 */
static inline DispatchContext *dispatch_context_unref(DispatchContext *ctx) {
        if (ctx)
                c_ref_dec(&ctx->n_refs, dispatch_context_free, NULL);
        return NULL;
}

C_DEFINE_CLEANUP(DispatchContext *, dispatch_context_unref);
