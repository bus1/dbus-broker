/*
* Serialize Helpers
*/

#include <c-rbtree.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "bus/peer.h"
#include "util/error.h"
#include "util/proc.h"
#include "util/serialize.h"
#include "util/syscall.h"

int state_file_init(FILE **ret) {
        int mem_fd;
        FILE *f = NULL;
        mem_fd = syscall_memfd_create("launcher-state", 0);
        if (mem_fd < 0)
                return mem_fd;

        errno = 0;
        f = fdopen(mem_fd, "w+");
        if (!f) {
                return error_trace(-errno);
        }
        *ret = f;
        return mem_fd;
}

int serialize_basic(FILE *f, char *key, const char *format, ...) {
        va_list args;
        _c_cleanup_(c_freep) char *buf = malloc(LINE_LENGTH_MAX);
        int r;

        va_start(args, format);
        r = vsnprintf(buf, LINE_LENGTH_MAX, format, args);
        va_end(args);

        if (r < 0 || strlen(key) + r + 2 > LINE_LENGTH_MAX) {
                return -EINVAL;
        }

        fputs(key, f);
        fputc('=', f);
        fputs(buf, f);
        fputc('\n', f);

        return 0;
}

int serialize_peers(FILE *f, Broker *broker) {
        Peer *peeri;
        int r = 0;

        _c_cleanup_(c_freep) char *fd_str = malloc(FD_LENGTH_MAX), *id_str = malloc(ID_LENGTH_MAX);
        _c_cleanup_(c_freep) char *pid_str = malloc(PID_LENGTH_MAX), *uid_str = malloc(UID_LENGTH_MAX);
        _c_cleanup_(c_freep) char *rule_str = malloc(MATCH_RULE_LENGTH_MAX), *sasl_str = malloc(SASL_ELEMENT_LENGTH_MAX);
        _c_cleanup_(c_freep) char *rule_str_list = malloc(LINE_LENGTH_MAX), *sasl_str_list = malloc(SASL_LENGTH_MAX);

        c_rbtree_for_each_entry(peeri, &broker->bus.peers.peer_tree, registry_node) {
                _c_cleanup_(c_freep) char *nameowner_ship_str = malloc(NAME_LENGTH_MAX);
                memset(nameowner_ship_str, 0, NAME_LENGTH_MAX);
                char *rule_str_list_cur = rule_str_list, *sasl_str_list_cur = sasl_str_list;
                int left_length = LINE_LENGTH_MAX;
                bool skip_this_peer = false;

                /* Skip dbus-broker-launch */
                if (peeri->pid == broker->launcher_pid) {
                        close(peeri->connection.socket.fd);
                        continue;
                }

                /* Serialize fd, id, pid and uid. */
                (void) snprintf(fd_str, FD_LENGTH_MAX, "%d", peeri->connection.socket.fd);
                (void) snprintf(id_str, ID_LENGTH_MAX, "%lu", peeri->id);
                (void) snprintf(pid_str, PID_LENGTH_MAX, "%d", peeri->pid);
                (void) snprintf(uid_str, UID_LENGTH_MAX, "%u", peeri->user->uid);
                /* 1 * strlen('peer=') + 4 * strlen(';') + 1 * strlen('\0') = 10 */
                left_length -= strlen(fd_str) + strlen(id_str) + strlen(pid_str) + strlen(uid_str) + 10;

                /* Serialize requested names. */
                NameOwnership *nameowner_shipi = NULL;
                c_rbtree_for_each_entry(nameowner_shipi, &peeri->owned_names.ownership_tree, owner_node) {
                        if (name_ownership_is_primary(nameowner_shipi) && nameowner_shipi->name->name){
                                (void) snprintf(nameowner_ship_str, NAME_LENGTH_MAX, "%s", nameowner_shipi->name->name);
                                left_length -= strlen(nameowner_ship_str) + strlen(";");
                        }
                }
                /* Generate a owner name for peers which doesn't have one */
                if (strlen(nameowner_ship_str) == 0) {
                        snprintf(nameowner_ship_str, NAME_LENGTH_MAX, "local.client.%d", peeri->connection.socket.fd);
                }

                /* Serialize match rule strings. */
                rule_str_list_cur = stpcpy(rule_str_list_cur, "[");
                left_length -= 1;
                RuleString *rsi;
                c_list_for_each_entry(rsi, &peeri->rule_string_list, rule_string_link) {
                        (void) snprintf(rule_str, MATCH_RULE_LENGTH_MAX, "{%s}", rsi->rule_string);
                        char *arg0 = strstr(rule_str, "arg0");
                        if (arg0 && !strncmp(arg0 + strlen("arg0"), "=':1", strlen("=':1"))) {
                                continue;
                        }
                        rule_str_list_cur = stpcpy(rule_str_list_cur, rule_str);
                        left_length -= strlen(rule_str);
                        /* Besides the next rule_str, we should also keep MATCH_RULE_LENGTH_MAX
                         * bytes for sasl_str. sasl_str usually doesn't need that much space,
                         * just be sure. */
                        if (left_length <= 2 * MATCH_RULE_LENGTH_MAX) {
                                skip_this_peer = true;
                                break;
                        }
                }

                if (skip_this_peer) {
                        log_append_here(&broker->log, LOG_WARNING, 0, NULL);
                        r = log_commitf(&broker->log, "Failed to serialize perr: %s, skipping.\n",
                                        nameowner_ship_str);
                        if (r < 0)
                                return error_fold(r);
                        close(peeri->connection.socket.fd);
                        continue;
                }

                rule_str_list_cur = stpcpy(rule_str_list_cur, "]");

                /* Serialize SASL state and fds_allowed. */
                sasl_str_list_cur = stpcpy(sasl_str_list_cur, "[");
                (void) snprintf(sasl_str, SASL_ELEMENT_LENGTH_MAX, "{%d}", peeri->connection.sasl_server.state);
                sasl_str_list_cur = stpcpy(sasl_str_list_cur, sasl_str);
                (void) snprintf(sasl_str, SASL_ELEMENT_LENGTH_MAX, "{%d}", peeri->connection.sasl_server.fds_allowed);
                sasl_str_list_cur = stpcpy(sasl_str_list_cur, sasl_str);
                (void) snprintf(sasl_str, SASL_ELEMENT_LENGTH_MAX, "{%d}", peeri->connection.sasl_client.state);
                sasl_str_list_cur = stpcpy(sasl_str_list_cur, sasl_str);
                sasl_str_list_cur = stpcpy(sasl_str_list_cur, "]");

                /* Write all. */
                (void) serialize_basic(f, "peer", "%s;%s;%s;%s;%s;%s;%s",
                                                  fd_str,
                                                  id_str,
                                                  pid_str,
                                                  uid_str,
                                                  nameowner_ship_str,
                                                  rule_str_list,
                                                  sasl_str_list);
        }
        return 0;
}
