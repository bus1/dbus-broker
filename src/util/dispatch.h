#pragma once

/*
 * Event Dispatcher
 */

#include <c-list.h>
#include <c-macro.h>
#include <c-ref.h>
#include <stdlib.h>

enum {
        _DISPATCH_E_SUCCESS,

        DISPATCH_E_EXIT,
        DISPATCH_E_FAILURE,
};

typedef struct DispatchContext DispatchContext;
typedef struct DispatchFile DispatchFile;
typedef int (*DispatchFn) (DispatchFile *file, uint32_t events);

/* files */

struct DispatchFile {
        DispatchContext *context;
        CList *ready_list;
        CList ready_link;
        DispatchFn fn;

        int fd;
        uint32_t user_mask;
        uint32_t kernel_mask;
        uint32_t events;
};

#define DISPATCH_FILE_NULL(_x) {                                \
                .ready_link = C_LIST_INIT((_x).ready_link),     \
                .fd = -1,                                       \
        }

int dispatch_file_init(DispatchFile *file,
                       DispatchContext *ctx,
                       CList *ready_list,
                       DispatchFn fn,
                       int fd,
                       uint32_t mask);
void dispatch_file_deinit(DispatchFile *file);

void dispatch_file_select(DispatchFile *file, uint32_t mask);
void dispatch_file_deselect(DispatchFile *file, uint32_t mask);
void dispatch_file_clear(DispatchFile *file, uint32_t mask);

/* contexts */

struct DispatchContext {
        int epoll_fd;
        size_t n_files;
};

#define DISPATCH_CONTEXT_NULL { .epoll_fd = -1 }

int dispatch_context_init(DispatchContext *ctxp);
void dispatch_context_deinit(DispatchContext *ctx);

int dispatch_context_poll(DispatchContext *ctx, int timeout);

/* inline helpers */

static inline int dispatch_file_call(DispatchFile *file) {
        return file->fn(file, file->events & file->user_mask);
}
