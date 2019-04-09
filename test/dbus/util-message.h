#pragma once

/*
 * Raw message helpers
 */

#include <c-stdaux.h>
#include <stdlib.h>

void test_message_append_sasl(void **buf, size_t *n_buf);
void test_message_append_hello(void **buf, size_t *n_buf);
void test_message_append_broadcast(void **buf,
                                   size_t *n_buf,
                                   uint64_t sender_id);
void test_message_append_signal(void **buf,
                                size_t *n_buf,
                                uint64_t sender_id,
                                uint64_t destination_id);
void test_message_append_ping(void **buf,
                              size_t *n_buf,
                              uint32_t serial,
                              uint64_t sender_id,
                              uint64_t destination_id);
void test_message_append_ping2(void **buf,
                               size_t *n_buf,
                               uint32_t serial,
                               const char *sender,
                               const char *destination);
void test_message_append_pong(void **buf,
                              size_t *n_buf,
                              uint32_t serial,
                              uint32_t reply_serial,
                              uint64_t sender_id,
                              uint64_t destination_id);
