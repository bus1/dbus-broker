/*
 * Test Peer
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include "bus.h"
#include "dbus/socket.h"
#include "peer.h"

static void test_setup(void) {
        _c_cleanup_(bus_freep) Bus *bus = NULL;
        _c_cleanup_(peer_freep) Peer *peer = NULL;
        int pair[2], r;

        r = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
        assert(r >= 0);

        r = bus_new(&bus, 0, 1024, 1024, 1024, 1024, 1024);
        assert(r >= 0);

        r = peer_new(&peer, bus, pair[0]);
        assert(r >= 0);

        close(pair[1]);
}

static void test_sasl_exchange(Bus *bus, char *sasl_client, char *sasl_server) {
        _c_cleanup_(peer_freep) Peer *peer = NULL;
        char buffer[strlen(sasl_server) + 1];
        int pair[2], r;

        r = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
        assert(r >= 0);

        r = peer_new(&peer, bus, pair[0]);
        assert(r >= 0);

        r = peer_start(peer);
        assert(!r);

        r = send(pair[1], "\0", 1, 0);
        assert(r >= 0);

        r = send(pair[1], sasl_client, strlen(sasl_client), 0);
        assert(r == (ssize_t)strlen(sasl_client));

        r = dispatch_context_poll(&bus->dispatcher, 0);
        assert(!r);

        r = peer_dispatch(&peer->connection.socket_file, EPOLLIN | EPOLLOUT);
        assert(r >= 0);

        r = recv(pair[1], buffer, sizeof(buffer), 0);
        assert(r == (ssize_t)strlen(sasl_server));
        assert(memcmp(buffer, sasl_server, r) == 0);
}

static void test_sasl(void) {
        _c_cleanup_(bus_freep) Bus *bus = NULL;
        int r;

        r = bus_new(&bus, 0, 1024, 1024, 1024, 1024, 1024);
        assert(r >= 0);

        test_sasl_exchange(bus,
                           "AUTH EXTERNAL\r\nDATA\r\nBEGIN\r\n",
                           "DATA\r\nOK 00000000000000000000000000000000\r\n");

        test_sasl_exchange(bus,
            "AUTH EXTERNAL\r\nDATA\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n",
            "DATA\r\nOK 00000000000000000000000000000000\r\nAGREE_UNIX_FD\r\n");
/* XXX: need to insert real UID
        test_sasl_exchange(bus,
                           "AUTH EXTERNAL 31\r\nBEGIN\r\n",
                           "OK 00000000000000000000000000000000\r\n");

        test_sasl_exchange(bus,
            "AUTH EXTERNAL 31\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n",
            "OK 00000000000000000000000000000000\r\nAGREE_UNIX_FD\r\n");
*/
}

int main(int argc, char **argv) {
        test_setup();
        test_sasl();
        return 0;
}
