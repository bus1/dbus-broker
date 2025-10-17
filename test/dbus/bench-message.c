/*
 * Message Passing Benchmarks
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <math.h>
#include <stdlib.h>
#include "util/sampler.h"
#include "util-broker.h"
#include "util-message.h"
#include "dbus/protocol.h"

#define TEST_N_ITERATIONS 500

static void test_connect_blocking_fd(Broker *broker, int *fdp) {
        _c_cleanup_(c_closep) int fd = -1;
        _c_cleanup_(c_freep) void *hello = NULL;
        size_t n_hello = 0;
        uint8_t reply[316];
        ssize_t len;
        int r;

        test_message_append_sasl(&hello, &n_hello);
        test_message_append_hello(&hello, &n_hello);

        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        c_assert(fd >= 0);

        r = connect(fd, (struct sockaddr *)&broker->address, broker->n_address);
        c_assert(r >= 0);

        len = write(fd, hello, n_hello);
        c_assert(len == (ssize_t)n_hello);

        len = recv(fd, reply, sizeof(reply), MSG_WAITALL);
        c_assert(len == (ssize_t)sizeof(reply));

        *fdp = fd;
        fd = -1;
}

static void test_message_transaction(Sampler *sampler, size_t n_matches, size_t n_replies, void *input, ssize_t n_input, ssize_t n_output) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        _c_cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        _c_cleanup_(c_closep) int fd1 = -1;
        _c_cleanup_(c_closep) int fd2 = -1;
        uint8_t output[n_output];
        ssize_t len;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);
        util_broker_settle(broker);

        test_connect_blocking_fd(broker, &fd1);

        if (n_matches > 0) {
                util_broker_connect(broker, &bus);

                for (unsigned int i = 0; i < n_matches; ++i) {
                        _c_cleanup_(c_freep) char *match = NULL;

                        r = asprintf(&match, "path=/org/example/Foo%u", i);
                        c_assert(r >= 0);

                        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                               "AddMatch", NULL, NULL,
                                               "s", match);
                        c_assert(r >= 0);
                }
        }

        if (n_replies > 0) {
                uint32_t serial = 0;;

                test_connect_blocking_fd(broker, &fd2);

                for (unsigned int i = 0; i < n_replies; ++i) {
                        _c_cleanup_(c_freep) void *ping = NULL;
                        size_t n_ping = 0;
                        uint8_t reply[136];

                        test_message_append_ping(&ping, &n_ping, ++serial, 2, 2);

                        len = write(fd2, ping, n_ping);
                        c_assert(len == (ssize_t)n_ping);

                        r = recv(fd2, reply, sizeof(reply), MSG_WAITALL);
                        c_assert(r == sizeof(reply));
                }
        }

        for (unsigned int i = 0; i < TEST_N_ITERATIONS; ++i) {
                sampler_sample_start(sampler);

                len = write(fd1, input, n_input);
                c_assert(len == (ssize_t)n_input);

                len = recv(fd1, output, sizeof(output), MSG_WAITALL);
                c_assert(len == (ssize_t)sizeof(output));

                sampler_sample_end(sampler);
        }

        util_broker_terminate(broker);
}

static void test_broadcast(void) {
        for (unsigned int j = 0; j <= 18; ++j) {
                _c_cleanup_(sampler_deinit) Sampler sampler = SAMPLER_INIT(CLOCK_MONOTONIC_RAW);
                _c_cleanup_(c_freep) void *buf = NULL;
                size_t n_buf = 0;

                test_message_append_broadcast(&buf, &n_buf, 1);
                test_message_append_signal(&buf, &n_buf, 1, 1);

                test_message_transaction(&sampler, 1 << j, 0, buf, n_buf, 120);

                fprintf(stderr, "Broadcast emmission to %u failing matches + message transaction completed in %"PRIu64" (+/- %.0f) us\n",
                        1 << j, sampler.average / 1000, sampler_read_standard_deviation(&sampler) / 1000);
        }
}

static void test_replies(void) {
        for (unsigned int j = 0; j <= 18; ++j) {
                _c_cleanup_(sampler_deinit) Sampler sampler = SAMPLER_INIT(CLOCK_MONOTONIC_RAW);
                _c_cleanup_(c_freep) void *buf = NULL;
                size_t n_buf = 0;

                test_message_append_ping(&buf, &n_buf, 1, 1, 1);
                test_message_append_pong(&buf, &n_buf, 2, 1, 1, 1);

                test_message_transaction(&sampler, 0, 1 << j, buf, n_buf, n_buf);

                fprintf(stderr, "Message transaction with %u outstanding replies on the bus completed in %"PRIu64" (+/- %.0f) us\n",
                        1 << j, sampler.average / 1000, sampler_read_standard_deviation(&sampler) / 1000);
        }
}

static void test_pipelining(void) {
        for (unsigned int j = 0; j <= 8; ++j) {
                _c_cleanup_(sampler_deinit) Sampler sampler = SAMPLER_INIT(CLOCK_MONOTONIC_RAW);
                _c_cleanup_(c_freep) void *buf = NULL;
                size_t n_buf = 0;
                uint32_t serial = 0;

                for (unsigned int i = 0; i <= (1U << j); ++i) {
                        test_message_append_ping(&buf, &n_buf, ++serial, 1, 1);
                }

                test_message_transaction(&sampler, 0, 0, buf, n_buf, n_buf);

                fprintf(stderr, "%u pipelined message transaction completed in %"PRIu64" (+/- %.0f) us\n",
                        (1 << j), sampler.average / 1000 / (1 << j), sampler_read_standard_deviation(&sampler) / 1000);
        }
}

int main(int argc, char **argv) {
        test_broadcast();
        test_replies();
        test_pipelining();
}
