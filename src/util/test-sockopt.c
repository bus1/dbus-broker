/*
 * Test Socket Options
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include "util/proc.h"
#include "util/sockopt.h"

static void wait_and_verify(pid_t pid_expected) {
        pid_t pid;
        int status;

        pid = wait(&status);
        c_assert(pid >= 0);
        c_assert(pid != 0);
        c_assert(pid == pid_expected);
        c_assert(WIFEXITED(status));
        c_assert(WEXITSTATUS(status) == 0);
}

static void create_server(int fd) {
        struct sockaddr_un address = { .sun_family = AF_UNIX };
        int r;

        r = bind(fd, &address, offsetof(struct sockaddr_un, sun_path));
        c_assert(r >= 0);

        r = listen(fd, 256);
        c_assert(r >= 0);
}

static void create_client(
        int *fdp,
        struct sockaddr_un *address,
        socklen_t n_address
) {
        _c_cleanup_(c_closep) int fd = -1;
        int r;

        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        c_assert(fd >= 0);

        r = connect(fd, address, n_address);
        c_assert(r >= 0);

        *fdp = fd;
        fd = -1;
}

static void test_peerpidfd_client(
        struct sockaddr_un *address,
        socklen_t n_address,
        pid_t pid_server,
        bool stale
) {
        _c_cleanup_(c_closep) int fd = -1, pidfd = -1;
        struct ucred ucred;
        socklen_t n_ucred;
        pid_t pid_socket;
        int r;

        create_client(&fd, address, n_address);

        /* Verify that SO_PEERCRED returns the PID even if stale. */

        n_ucred = sizeof(ucred);
        r = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &n_ucred);
        c_assert(r >= 0);

        c_assert(ucred.pid >= 0);
        c_assert(ucred.pid != 0);
        c_assert(ucred.pid == pid_server);

        /* Verify that SO_PEERPIDFD resolves only non-stale PIDs. */

        r = sockopt_get_peerpidfd(fd, &pidfd);
        if (r != SOCKOPT_E_UNSUPPORTED) {
                if (r == SOCKOPT_E_REAPED) {
                        /*
                         * Old kernels refused to return stale pidfds. Hence,
                         * in that case verify that we expected a stale pidfd.
                         */
                        c_assert(stale);
                } else {
                        c_assert(!r);
                        c_assert(pidfd >= 0);

                        r = proc_resolve_pidfd(pidfd, &pid_socket);
                        c_assert(!r);

                        if (stale) {
                                c_assert(pid_socket == -1);
                        } else {
                                c_assert(pid_socket > 0);
                                c_assert(pid_socket == pid_server);
                        }
                }
        }
}

static void test_peerpidfd(void) {
        _c_cleanup_(c_closep) int fd_server = -1;
        _c_cleanup_(c_closep) int rpipe_down = -1, wpipe_down = -1;
        _c_cleanup_(c_closep) int rpipe_up = -1, wpipe_up = -1;
        pid_t pid_server, pid_client;
        struct sockaddr_un address;
        socklen_t n_address;
        ssize_t l;
        char c;
        int r, pipes[2];

        /* Create 2 pipes for communicating with the server process. */

        r = pipe2(pipes, O_CLOEXEC | O_DIRECT);
        c_assert(r >= 0);
        rpipe_down = pipes[0];
        wpipe_down = pipes[1];

        r = pipe2(pipes, O_CLOEXEC | O_DIRECT);
        c_assert(r >= 0);
        rpipe_up = pipes[0];
        wpipe_up = pipes[1];

        /* Create the unbound server socket in the controller. */

        fd_server = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        c_assert(fd_server >= 0);

        /*
         * Fork the server process, which then binds the server socket. This
         * will pin the credentials of the server on the server socket.
         *
         * The server process notifies the controller once the socket is
         * configured, and then waits for notification from the controller
         * before it exits.
         */

        pid_server = fork();
        c_assert(pid_server >= 0);
        if (!pid_server) {
                rpipe_up = c_close(rpipe_up);
                wpipe_down = c_close(wpipe_down);

                create_server(fd_server);

                /* signal parent that the server is up */
                l = write(wpipe_up, "!", 1);
                c_assert(l == 1);

                /* wait with exit until told */
                l = read(rpipe_down, &c, 1);
                c_assert(l == 1 && c == '!');

                _exit(0);
        }

        wpipe_up = c_close(wpipe_up);
        rpipe_down = c_close(rpipe_down);

        /* Wait for server process to configure the server socket. */

        l = read(rpipe_up, &c, 1);
        c_assert(l == 1 && c == '!');

        n_address = sizeof(address);
        r = getsockname(fd_server, &address, &n_address);
        c_assert(r >= 0);

        /*
         * Create a client process that connects to the server socket and
         * tries to fetch the peer credentials and verify them.
         */

        pid_client = fork();
        c_assert(pid_client >= 0);
        if (!pid_client) {
                rpipe_up = c_close(rpipe_up);
                wpipe_down = c_close(wpipe_down);
                fd_server = c_close(fd_server);

                test_peerpidfd_client(&address, n_address, pid_server, false);
                _exit(0);
        }

        wait_and_verify(pid_client);

        /* Notify server process to exit and wait for it. */

        l = write(wpipe_down, "!", 1);
        c_assert(l == 1);

        wait_and_verify(pid_server);

        /*
         * Create another client process, but this time the pinned credentials
         * of the server socket refer to a non-existing process.
         */

        pid_client = fork();
        c_assert(pid_client >= 0);
        if (!pid_client) {
                rpipe_up = c_close(rpipe_up);
                wpipe_down = c_close(wpipe_down);
                fd_server = c_close(fd_server);

                test_peerpidfd_client(&address, n_address, pid_server, true);
                _exit(0);
        }

        wait_and_verify(pid_client);
}

int main(int argc, char **argv) {
        test_peerpidfd();
        return 0;
}
