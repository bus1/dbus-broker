/*
 * Connection Benchmarks
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include "util/metrics.h"
#include "util-broker.h"
#include "util-message.h"

#define TEST_N_ITERATIONS 500

static void test_connect_blocking_fd(Broker *broker, int *fdp) {
        _c_cleanup_(c_closep) int fd = -1;
        int r;

        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        c_assert(fd >= 0);

        r = connect(fd, (struct sockaddr *)&broker->address, broker->n_address);
        c_assert(r >= 0);

        *fdp = fd;
        fd = -1;
}

static void test_connect_one(Metrics *metrics, void *input, ssize_t n_input, ssize_t n_output) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        char output[n_output];
        ssize_t len;
        int fd;

        util_broker_new(&broker);
        util_broker_spawn(broker);
        util_broker_settle(broker);

        metrics_sample_start(metrics);

        test_connect_blocking_fd(broker, &fd);

        len = write(fd, input, n_input);
        c_assert(len == (ssize_t)n_input);

        len = recv(fd, output, sizeof(output), MSG_WAITALL);
        c_assert(len == (ssize_t)n_output);

        metrics_sample_end(metrics);

        fd = c_close(fd);

        util_broker_terminate(broker);
}

static void test_sasl(void) {
        _c_cleanup_(metrics_deinit) Metrics metrics = METRICS_INIT(CLOCK_MONOTONIC_RAW);
        _c_cleanup_(c_freep) void *buf = NULL;
        size_t n_buf = 0;

        test_message_append_sasl(&buf, &n_buf);

        for (unsigned int i = 0; i < TEST_N_ITERATIONS; ++i)
                test_connect_one(&metrics, buf, n_buf, 58);

        fprintf(stderr, "SASL transaction completed in %"PRIu64" (+/- %.0f) us\n",
                metrics.average / 1000, metrics_read_standard_deviation(&metrics) / 1000);
}

static void test_hello(void) {
        _c_cleanup_(metrics_deinit) Metrics metrics = METRICS_INIT(CLOCK_MONOTONIC_RAW);
        _c_cleanup_(c_freep) void *buf = NULL;
        size_t n_buf = 0;

        test_message_append_sasl(&buf, &n_buf);
        test_message_append_hello(&buf, &n_buf);

        for (unsigned int i = 0; i < TEST_N_ITERATIONS; ++i)
                test_connect_one(&metrics, buf, n_buf, 316);

        fprintf(stderr, "SASL + Hello transaction completed in %"PRIu64" (+/- %.0f) us\n",
                metrics.average / 1000, metrics_read_standard_deviation(&metrics) / 1000);
}

static void test_transaction(void) {
        _c_cleanup_(metrics_deinit) Metrics metrics = METRICS_INIT(CLOCK_MONOTONIC_RAW);
        _c_cleanup_(c_freep) void *buf = NULL;
        size_t n_buf = 0;

        test_message_append_sasl(&buf, &n_buf);
        test_message_append_hello(&buf, &n_buf);
        test_message_append_signal(&buf, &n_buf, 1, 1);

        for (unsigned int i = 0; i < TEST_N_ITERATIONS; ++i)
                test_connect_one(&metrics, buf, n_buf, 436);

        fprintf(stderr, "SASL + Hello + message transaction completed in %"PRIu64" (+/- %.0f) us\n",
                metrics.average / 1000, metrics_read_standard_deviation(&metrics) / 1000);
}

int main(int argc, char **argv) {
        test_sasl();
        test_hello();
        test_transaction();
}
