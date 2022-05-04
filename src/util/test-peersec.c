/*
 * Verify SO_PEERSEC on SELinux
 *
 * This test queries SO_PEERSEC on AF_UNIX+SOCK_STREAM sockets. It first runs
 * socketpair(2) and queries it, then runs an emulated socketpair(2) and
 * queries it.
 *
 * XXX: For now, the test simply prints the data. However, ultimately, we want
 *      to use this as verification that the kernel is fixed to return the same
 *      data on both. This is still open for discussion, though.
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/auxv.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include "util/sockopt.h"

static int socketpair_fallback(int domain, int type, int protocol, int sv[2]) {
        _c_cleanup_(c_closep) int listener = -1, client_a = -1, client_b = -1;
        uint64_t magic = UINT64_C(0x6ff780fe02a8a310); /* pseudo-random seed */
        struct sockaddr_un address;
        int type_flags;
        int r;

        type_flags = type & (SOCK_NONBLOCK | SOCK_CLOEXEC);
        type &= ~type_flags;

        if (domain != AF_UNIX)
                return -EAFNOSUPPORT;
        if (type != SOCK_STREAM && type != SOCK_SEQPACKET)
                return -EOPNOTSUPP;

        /* create listener and connecting client */
        {
                listener = socket(AF_UNIX, type | SOCK_CLOEXEC, protocol);
                if (listener < 0)
                        return -errno;

                client_a = socket(AF_UNIX, type | type_flags, protocol);
                if (client_a < 0)
                        return -errno;
        }

        /* get some random data */
        {
                const uint8_t *at_random;
                struct timespec ts;

                /* if no other random source works, use our stack address */
                magic ^= (unsigned long)&magic;

                /* AT_RANDOM contains 128bits of randomness from kernel */
                at_random = (const uint8_t *)getauxval(AT_RANDOM);
                if (at_random) {
                        magic ^= at_random[0];
                        magic ^= at_random[1];
                        magic ^= at_random[2];
                        magic ^= at_random[3];
                }

                /* merge in the current time */
                r = clock_gettime(CLOCK_MONOTONIC, &ts);
                if (!r) {
                        magic ^= ts.tv_sec;
                        magic ^= ts.tv_nsec;
                }
        }

        /* bind our listener to a random address */
        {
                address = (struct sockaddr_un){
                        .sun_family = AF_UNIX,
                        .sun_path = { },
                };

                sprintf(address.sun_path + 1, "%"PRIx64, magic);

                r = bind(listener, (struct sockaddr *)&address, sizeof(address));
                if (r)
                        return -errno;

                r = listen(listener, 1);
                if (r)
                        return -errno;
        }

        /* connect @client_a to @listener */
        {
                r = connect(client_a, (struct sockaddr *)&address, sizeof(address));
                if (r)
                        return -errno;

                client_b = accept4(listener, NULL, NULL, type_flags);
                if (client_b < 0)
                        return -errno;
        }

        sv[0] = client_a;
        sv[1] = client_b;
        client_a = -1;
        client_b = -1;
        return 0;
}

static void test_peersec(void) {
        char buffer[4096];
        int r, sv[2];

        /* test socketpair(2) */
        {
                _c_cleanup_(c_closep) int a = -1, b = -1;
                _c_cleanup_(c_freep) char *label_a = NULL, *label_b = NULL;
                size_t n_label_a, n_label_b;

                r = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv);
                c_assert(!r);

                a = sv[0];
                b = sv[1];

                r = write(a, "foobar", 6);
                c_assert(r == 6);

                r = read(b, buffer, sizeof(buffer));
                c_assert(r == 6);
                c_assert(!memcmp(buffer, "foobar", 6));

                r = sockopt_get_peersec(a, &label_a, &n_label_a);
                c_assert(!r);

                r = sockopt_get_peersec(b, &label_b, &n_label_b);
                c_assert(!r);

                fprintf(stdout, "A:          socketpair(2): %zu '%s'\n", n_label_a, label_a);
                fprintf(stdout, "B:          socketpair(2): %zu '%s'\n", n_label_b, label_b);
        }

        /* test socketpair_fallback(2) */
        {
                _c_cleanup_(c_closep) int a = -1, b = -1;
                _c_cleanup_(c_freep) char *label_a = NULL, *label_b = NULL;
                size_t n_label_a, n_label_b;

                r = socketpair_fallback(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv);
                c_assert(!r);

                a = sv[0];
                b = sv[1];

                r = write(a, "foobar", 6);
                c_assert(r == 6);

                r = read(b, buffer, sizeof(buffer));
                c_assert(r == 6);
                c_assert(!memcmp(buffer, "foobar", 6));

                r = sockopt_get_peersec(a, &label_a, &n_label_a);
                c_assert(!r);

                r = sockopt_get_peersec(b, &label_b, &n_label_b);
                c_assert(!r);

                fprintf(stdout, "A: socketpair_fallback(2): %zu '%s'\n", n_label_a, label_a);
                fprintf(stdout, "B: socketpair_fallback(2): %zu '%s'\n", n_label_b, label_b);
        }
}

int main(int argc, char **argv) {
        test_peersec();
        return 0;
}
