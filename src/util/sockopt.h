#pragma once

/*
 * Socket Options Helpers
 */

#include <c-macro.h>
#include <stdlib.h>

int sockopt_get_peersec(int fd, char **labelp, size_t *lenp);
int sockopt_get_peergroups(int fd, uid_t uid, gid_t gid, gid_t **gidsp, size_t *n_gidsp);
