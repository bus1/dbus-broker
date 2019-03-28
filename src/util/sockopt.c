/*
 * Socket Options Helpers
 */

#include <c-macro.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "catalog/catalog-ids.h"
#include "util/error.h"
#include "util/log.h"
#include "util/sockopt.h"

int sockopt_get_peersec(int fd, char **labelp, size_t *lenp) {
        _c_cleanup_(c_freep) char *label = NULL;
        socklen_t len = 1023;
        char *l;
        int r;

        /*
         * There is no way to know how big a result SO_PEERSEC returns. Hence,
         * we simply keep re-allocating the buffer to the size returned by
         * SO_PEERSEC on failure. Note that this is racy. The seclabel can
         * change between calls. Hence, we must retry in a loop.
         */

        label = malloc(len + 1);
        if (!label)
                return error_origin(-ENOMEM);

        for (;;) {
                r = getsockopt(fd, SOL_SOCKET, SO_PEERSEC, label, &len);
                if (r >= 0) {
                        label[len] = '\0';
                        break;
                } else if (errno == ENOPROTOOPT) {
                        *label = 0;
                        break;
                } else if (errno != ERANGE) {
                        return error_origin(-errno);
                }

                l = realloc(label, len + 1);
                if (!l)
                        return error_origin(-ENOMEM);

                label = l;
        }

        /* dup label to throw away the unnecessary padding bytes */
        l = strdup(label);
        if (!l)
                return error_origin(-ENOMEM);

        *labelp = l;
        *lenp = strlen(l);
        return 0;
}

int sockopt_get_peergroups(int fd, Log *log, uid_t uid, gid_t gid, gid_t **gidsp, size_t *n_gidsp) {
        _c_cleanup_(c_freep) gid_t *gids = NULL;
        int r, n_gids = 64;
        void *tmp;

        /*
         * For compatibility to dbus-daemon(1), we need to know the auxiliary
         * groups a peer is in. Otherwise, we would be unable to apply group
         * policies. We use the SO_PEERGROUPS socket option to retrieve this
         * data alongside the uid+gid we got via SO_PEERCREDS.
         * SO_PEERGROUPS support was added in:
         *
         *     commit 28b5ba2aa0f55d80adb2624564ed2b170c19519e
         *     Author: David Herrmann <dh.herrmann@gmail.com>
         *     Commit: David S. Miller <davem@davemloft.net>
         *     Date:   Wed Jun 21 10:47:15 2017 +0200
         *
         *         net: introduce SO_PEERGROUPS getsockopt
         *
         * You are highly recommended to run >=linux-4.13.
         */
        {
                socklen_t socklen = n_gids * sizeof(*gids);

                gids = malloc(sizeof(gid) + socklen);
                if (!gids)
                        return error_origin(-ENOMEM);
                gids[0] = gid;

                r = getsockopt(fd, SOL_SOCKET, SO_PEERGROUPS, gids + 1, &socklen);
                if (r < 0 && errno == ERANGE) {
                        tmp = realloc(gids, sizeof(gid) + socklen);
                        if (!tmp)
                                return error_origin(-ENOMEM);
                        gids = tmp;
                        gids[0] = gid;

                        r = getsockopt(fd, SOL_SOCKET, SO_PEERGROUPS, gids + 1, &socklen);
                }
                if (r < 0 && errno != ENOPROTOOPT) {
                        return error_origin(-errno);
                } else if (r >= 0) {
                        if (gidsp) {
                                *gidsp = gids;
                                gids = NULL;
                        }
                        if (n_gidsp)
                                *n_gidsp = 1 + socklen / sizeof(*gids);
                        return 0;
                }

                /* fallthrough */
        }

        /*
         * If we end up here, then SO_PEERGROUPS did not work. This is not safe
         * and you really better update your kernel to support SO_PEERGROUPS.
         * Warn loudly before continuing with the fallback.
         */
        {
                static bool warned;

                if (!warned) {
                        warned = true;
                        log_append_here(log, LOG_ERR, 0, DBUS_BROKER_CATALOG_NO_SOPEERGROUP);
                        log_commitf(log, "Falling back to racy auxiliary groups"
                                         "resolution using nss.\n");
                }
        }

        /*
         * If SO_PEERGROUPS is not available, we fall back to getgrouplist(3),
         * which queries the user database. This is racy, incomplete, and in no
         * way consistent with the credentials associated with the used
         * resources. However, it is what was historically used, so we will
         * keep it for some more time.
         *
         * XXX: At what point can we drop this? We keep it for now, but we
         *      should at some point make a specific kernel version a
         *      hard-requirement.
         */
        {
                struct passwd *passwd;
                int n_gids_previous;

                passwd = getpwuid(uid);
                if (!passwd)
                        return error_origin(-errno);

                do {
                        n_gids_previous = n_gids;
                        tmp = realloc(gids, sizeof(*gids) * n_gids);
                        if (!tmp)
                                return error_origin(-ENOMEM);

                        gids = tmp;
                        r = getgrouplist(passwd->pw_name, passwd->pw_gid, gids, &n_gids);
                        if (r == -1 && n_gids <= n_gids_previous)
                                return error_origin(-ENOTRECOVERABLE);
                } while (r == -1);

                if (gidsp) {
                        *gidsp = gids;
                        gids = NULL;
                }
                if (n_gidsp)
                        *n_gidsp = n_gids;
        }

        return 0;
}
