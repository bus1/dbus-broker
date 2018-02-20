#pragma once

/*
 * Socket Options Helpers
 */

#include <c-macro.h>
#include <stdlib.h>

struct Log;

int sockopt_get_peersec(int fd, char **labelp, size_t *lenp);
int sockopt_get_peergroups(int fd, Log *log, uid_t uid, gid_t gid, gid_t **gidsp, size_t *n_gidsp);
