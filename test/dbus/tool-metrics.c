/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: D-Bus Broker Developers */

/*
 * Dump the OpenMetrics document of a freshly exercised broker
 *
 * This spawns a broker, puts a bit of load on it (a few peers, a name, a match
 * rule and a broadcast), and then scrapes the metrics listener so the emitted
 * document can be eyeballed.
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdio.h>
#include <stdlib.h>
#include "util-broker.h"

int main(int argc, char **argv) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *sender = NULL;
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *receiver = NULL;
        _c_cleanup_(c_freep) char *metrics = NULL;
        size_t i;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        util_broker_connect(broker, &sender);
        util_broker_connect(broker, &receiver);

        /* claim a well-known name, so the name gauge is non-zero */
        r = sd_bus_request_name(sender, "com.example.Metrics", 0);
        c_assert(r >= 0);

        /*
         * Subscribe without a sender filter. This is the shape of match rule
         * that forces the broker to evaluate every broadcast against this peer.
         */
        r = sd_bus_add_match(receiver, NULL, "type='signal',interface='com.example.Loud'", NULL, NULL);
        c_assert(r >= 0);

        /* emit a few broadcasts so the fan-out counter moves */
        for (i = 0; i < 16; ++i) {
                r = sd_bus_emit_signal(sender,
                                       "/com/example/Metrics",
                                       "com.example.Loud",
                                       "Noise",
                                       "u",
                                       (uint32_t)i);
                c_assert(r >= 0);
        }

        util_broker_settle(broker);

        util_broker_scrape_metrics(broker, &metrics);
        fputs(metrics, stdout);

        util_broker_terminate(broker);
        return 0;
}
