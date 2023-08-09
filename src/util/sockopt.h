#pragma once

/*
 * Socket Options Helpers
 */

#include <c-stdaux.h>
#include <stdlib.h>

enum {
        _SOCKOPT_E_SUCCESS,

        SOCKOPT_E_UNSUPPORTED,
        SOCKOPT_E_UNAVAILABLE,
        SOCKOPT_E_REAPED,
};

typedef struct Log Log;

int sockopt_get_peersec(int fd, char **labelp, size_t *lenp);
int sockopt_get_peergroups(int fd, Log *log, uid_t uid, gid_t primary_gid, gid_t **gidsp, size_t *n_gidsp);
int sockopt_get_peerpidfd(int fd, int *ret_pidfd);
