#pragma once

/*
 * D-Bus Input/Output Queues
 */

#include <c-list.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include "util/fdlist.h"
#include "util/user.h"

typedef struct IQueue IQueue;

#define IQUEUE_LINE_MAX (16UL * 1024UL) /* taken from dbus-daemon(1) */
#define IQUEUE_RECV_MAX (2UL * 1024UL) /* based on average message size */

enum {
        _IQUEUE_E_SUCCESS,

        IQUEUE_E_PENDING,
        IQUEUE_E_QUOTA,
        IQUEUE_E_VIOLATION,
};

struct IQueue {
        User *user;

        UserCharge charge_data;
        UserCharge charge_fds;
        char *data;
        size_t data_size;
        size_t data_start;
        size_t data_end;
        size_t data_cursor;
        FDList *fds;

        struct {
                UserCharge charge_data;
                UserCharge charge_fds;
                void *data;
                size_t n_data;
                size_t n_copied;
                FDList *fds;
        } pending;

        char buffer[IQUEUE_RECV_MAX];
};

#define IQUEUE_NULL(_x) {                                                       \
                .charge_data = USER_CHARGE_INIT,                                \
                .charge_fds = USER_CHARGE_INIT,                                 \
                .data = (_x).buffer,                                            \
                .data_size = sizeof((_x).buffer),                               \
                .pending.charge_data = USER_CHARGE_INIT,                        \
                .pending.charge_fds = USER_CHARGE_INIT,                         \
        }

struct OQueue {
        User *user;
        CList list_buffers;
        CList list_inflight;
};

#define OQUEUE_NULL(_x) {                                                       \
                .list_buffers = C_LIST_INIT((_x).list_buffers),                 \
                .list_inflight = C_LIST_INIT((_x).list_inflight),               \
        }

/* input queue */

void iqueue_init(IQueue *iq, User *user);
void iqueue_deinit(IQueue *iq);

void iqueue_flush(IQueue *iq);
int iqueue_set_target(IQueue *iq, void *data, size_t n_data);
int iqueue_get_cursor(IQueue *iq,
                      void **bufferp,
                      size_t **fromp,
                      size_t *top,
                      FDList ***fdsp,
                      UserCharge **charge_fdsp);

int iqueue_pop_line(IQueue *iq, const char **linep, size_t *np);
int iqueue_pop_data(IQueue *iq, FDList **fds);

/* inline helpers */

static inline void *iqueue_get_target(IQueue *iq) {
        return iq->pending.data;
}

static inline bool iqueue_is_eof(IQueue *iq) {
        return iq->data_cursor >= iq->data_end &&
               (!iq->pending.data || iq->pending.n_copied < iq->pending.n_data);
}
