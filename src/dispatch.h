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
        int epoll_fd;
        size_t n_files;
};

int dispatch_context_new(DispatchContext **ctxp);
DispatchContext *dispatch_context_free(DispatchContext *ctx);

int dispatch_context_poll(DispatchContext *ctx, int timeout);

C_DEFINE_CLEANUP(DispatchContext *, dispatch_context_free);
