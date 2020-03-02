#pragma once

/*
 * Socket Options Helpers
 */

#include <c-stdaux.h>
#include <stdlib.h>

typedef struct Log Log;

int sockopt_get_peersec(int fd, char **labelp, size_t *lenp);
int sockopt_get_peergroups(int fd, Log *log, uid_t uid, gid_t primary_gid, gid_t **gidsp, size_t *n_gidsp);
