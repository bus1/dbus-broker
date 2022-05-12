/*
 * Test D-Bus Input/Output Queues
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include "dbus/queue.h"
#include "util/fdlist.h"
#include "util/user.h"

#define TEST_8 "01234567"
#define TEST_64 TEST_8 TEST_8 TEST_8 TEST_8 TEST_8 TEST_8 TEST_8 TEST_8
#define TEST_512 TEST_64 TEST_64 TEST_64 TEST_64 TEST_64 TEST_64 TEST_64 TEST_64
#define TEST_2k TEST_512 TEST_512 TEST_512 TEST_512
#define TEST_8k TEST_2k TEST_2k TEST_2k TEST_2k
#define TEST_32k TEST_8k TEST_8k TEST_8k TEST_8k

static void test_in_setup(void) {
        _c_cleanup_(iqueue_deinit) IQueue iq = IQUEUE_NULL(iq);

        iqueue_init(&iq, NULL);
        iqueue_deinit(&iq);
}

static void test_in_special(void) {
        _c_cleanup_(iqueue_deinit) IQueue iq = IQUEUE_NULL(iq);
        int r;

        iqueue_init(&iq, NULL);

        /*
         * Push as much data into the iqueue as possible. Make sure none of it
         * includes \r\n, hence, it is treated as a single line. Then verify
         * that after more than 16k it bails out with a protocol violation.
         */
        {
                static const char blob[] = TEST_32k;
                UserCharge *charge_fds;
                size_t n, total, *from, to;
                const char *l;
                void *buffer;
                FDList **fds;

                total = 0;
                for (;;) {
                        r = iqueue_get_cursor(&iq,
                                              &buffer,
                                              &from,
                                              &to,
                                              &fds,
                                              &charge_fds);
                        if (r == IQUEUE_E_VIOLATION)
                                break;

                        c_assert(!r);

                        n = c_min(to - *from, sizeof(blob));
                        if (!n)
                                break;

                        c_memcpy(buffer + *from, blob, n);
                        *from += n;
                        total += n;

                        r = iqueue_pop_line(&iq, &l, &n);
                        c_assert(r == IQUEUE_E_PENDING);
                }

                c_assert(total == IQUEUE_LINE_MAX);
        }

        iqueue_deinit(&iq);
        iqueue_init(&iq, NULL);

        /*
         * Verify `NULL' is correctly handled when fetching FDs. That is, the
         * FDs stay accounted and pinned in the queue and are handed over to
         * the next buffer.
         *
         * We push in this sequence:
         *
         *     * 1 byte + 1 FD
         *     * 2 bytes + 1 FD
         *
         * We dequeue them as:
         *
         *     * 1 byte + NULL
         *     * 1 byte + FD
         *     * 1 byte + FD
         *
         * That is, we pretend the first read byte wants to delay FD receiption
         * to the next buffer, so we pass NULL. We then verify that the iqueue
         * does the right thing.
         */
        {
                char data[128];
                UserCharge *charge_fds;
                size_t *from, to;
                void *buffer;
                FDList **fds, *f;

                /* push in 1 byte with 1 fd */
                r = iqueue_get_cursor(&iq,
                                      &buffer,
                                      &from,
                                      &to,
                                      &fds,
                                      &charge_fds);
                c_assert(!r);
                c_assert(to - *from >= 128);

                c_memcpy(buffer + *from, (char [1]){}, 1);
                *from += 1;
                r = fdlist_new_with_fds(fds, (int [1]){}, 1);
                c_assert(!r);

                /* verify further pushes are rejected until it is parsed */
                r = iqueue_get_cursor(&iq,
                                      &buffer,
                                      &from,
                                      &to,
                                      &fds,
                                      &charge_fds);
                c_assert(r == IQUEUE_E_PENDING);

                /* set 1 byte target and retrieve without fds */
                r = iqueue_set_target(&iq, data, 1);
                c_assert(!r);

                r = iqueue_pop_data(&iq, NULL);
                c_assert(!r);
                c_assert(!*data);

                /* set next 1 byte target and verify nothing is pending */
                r = iqueue_set_target(&iq, data, 1);
                c_assert(!r);

                r = iqueue_pop_data(&iq, NULL);
                c_assert(r == IQUEUE_E_PENDING);

                /* push in 2 more bytes with FDs */
                r = iqueue_get_cursor(&iq,
                                      &buffer,
                                      &from,
                                      &to,
                                      &fds,
                                      &charge_fds);
                c_assert(!r);
                c_assert(to - *from >= 128);

                c_memcpy(buffer + *from, (char [2]){}, 2);
                *from += 2;
                r = fdlist_new_with_fds(fds, (int [1]){ 1 }, 1);
                c_assert(!r);

                /* fetch 1 byte target and verify it got the *OLD* fd */
                r = iqueue_pop_data(&iq, &f);
                c_assert(!r);
                c_assert(!*data);
                c_assert(fdlist_count(f) == 1);
                c_assert(fdlist_get(f, 0) == 0);
                fdlist_free(f);

                /* fetch 1 byte target and verify it got the *NEW* fd */
                r = iqueue_set_target(&iq, data, 1);
                c_assert(!r);

                r = iqueue_pop_data(&iq, &f);
                c_assert(!r);
                c_assert(!*data);
                c_assert(fdlist_count(f) == 1);
                c_assert(fdlist_get(f, 0) == 1);
                fdlist_free(f);
        }

        iqueue_deinit(&iq);
        iqueue_init(&iq, NULL);

        /*
         * Test receival of empty blobs. Here we send 1 byte blob with FDs. We
         * retrieve the byte WITHOUT FD, followed by a request target of 0
         * bytes *WITH* FDs.
         */
        {
                char data[128];
                UserCharge *charge_fds;
                size_t *from, to;
                void *buffer;
                FDList **fds, *f;

                /* push in 1 byte with 1 fd */
                r = iqueue_get_cursor(&iq,
                                      &buffer,
                                      &from,
                                      &to,
                                      &fds,
                                      &charge_fds);
                c_assert(!r);
                c_assert(to - *from >= 128);

                c_memcpy(buffer + *from, (char [1]){}, 1);
                *from += 1;
                r = fdlist_new_with_fds(fds, (int [1]){}, 1);
                c_assert(!r);

                /* set 1 byte target and retrieve without fds */
                r = iqueue_set_target(&iq, data, 1);
                c_assert(!r);

                r = iqueue_pop_data(&iq, NULL);
                c_assert(!r);
                c_assert(!*data);

                /* set next 0 byte target and retieve FD */
                r = iqueue_set_target(&iq, data, 0);
                c_assert(!r);

                r = iqueue_pop_data(&iq, &f);
                c_assert(!r);
                c_assert(fdlist_count(f) == 1);
                c_assert(fdlist_get(f, 0) == 0);
                fdlist_free(f);
        }
}

static void test_in_lines(void) {
        static const char *send = {
                "foo\r\n"

                "\r\n"

                "bar\r\n"

                "\r \n\r\r\n"

                "foo bar foo bar foo bar\r\n"

                /* 512 + 2 */
                TEST_512 "\r\n"

                "random\r\n"

                /* 8k + 2 */
                TEST_8k "\r\n"

                "foobar\r\n"
        };
        static const char *expect[] = {
                "foo",

                "",

                "bar",

                "\r \n\r",

                "foo bar foo bar foo bar",

                TEST_512,

                "random",

                TEST_8k,

                "foobar",
        };
        _c_cleanup_(iqueue_deinit) IQueue iq = IQUEUE_NULL(iq);
        size_t i, n, i_send, i_expect;
        int r;

        iqueue_init(&iq, NULL);

        /*
         * Test Line Tokenizer
         *
         * Randomly chunk the data in @send and push it into @iq. Verify that
         * the tokenizer ends up with @expect.
         *
         * This verifies that regardless how the data is chunked, we correctly
         * tokenize the lines via iqueue. This also verifies that large lines
         * are correctly handled and end up in the resized line buffer.
         */

        for (i = 0; i < 0x1fff; ++i) {
                i_send = 0;
                i_expect = 0;

                do {
                        /* push random chunk from @send into @iq */
                        {
                                UserCharge *charge_fds;
                                size_t *from, to;
                                void *buffer;
                                FDList **fds;

                                r = iqueue_get_cursor(&iq,
                                                      &buffer,
                                                      &from,
                                                      &to,
                                                      &fds,
                                                      &charge_fds);
                                c_assert(!r);
                                c_assert(to > *from);

                                n = to - *from;
                                n = rand() % c_min(n, strlen(send) - i_send);
                                ++n;

                                c_memcpy(buffer + *from, send + i_send, n);
                                i_send += n;
                                *from += n;
                        }

                        /* dequeue as many lines from @iq as possible */
                        for (;;) {
                                const char *l;

                                r = iqueue_pop_line(&iq, &l, &n);
                                if (r == IQUEUE_E_PENDING)
                                        break;

                                c_assert(!r);
                                c_assert(n == strlen(expect[i_expect]));
                                c_assert(!memcmp(l, expect[i_expect], n));
                                ++i_expect;
                        }
                } while (i_send < strlen(send));

                c_assert(i_expect == C_ARRAY_SIZE(expect));
        }
}

int main(int argc, char **argv) {
        srand(0xabcdef);

        test_in_setup();
        test_in_special();
        test_in_lines();

        return 0;
}
