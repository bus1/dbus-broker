/*
 * Broker
 */

#include <c-list.h>
#include <c-stdaux.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "broker/broker.h"
#include "broker/controller.h"
#include "broker/main.h"
#include "bus/bus.h"
#include "catalog/catalog-ids.h"
#include "dbus/connection.h"
#include "dbus/message.h"
#include "util/dispatch.h"
#include "util/error.h"
#include "util/log.h"
#include "util/proc.h"
#include "util/serialize.h"
#include "util/sockopt.h"
#include "util/string.h"
#include "util/user.h"

static int broker_dispatch_signals(DispatchFile *file) {
        Broker *broker = c_container_of(file, Broker, signals_file);
        struct signalfd_siginfo si;
        ssize_t l;

        c_assert(dispatch_file_events(file) == EPOLLIN);

        l = read(broker->signals_fd, &si, sizeof(si));
        if (l < 0)
                return error_origin(-errno);

        c_assert(l == sizeof(si));

        return DISPATCH_E_EXIT;
}

static int serialize_broker(Broker *broker) {
        FILE *f = NULL;
        int mem_fd;
        mem_fd = state_file_init(&f);
        if (mem_fd < 0)
                return error_fold(mem_fd);

        (void) serialize_basic(f, "max_ids", "%d", broker->bus.peers.ids);
        (void) serialize_peers(f, broker);
        fseeko(f, 0, SEEK_SET);

        return mem_fd;
}

static int broker_execv_with_args(Broker *broker, int mem_fd) {
        _c_cleanup_(c_freep) char *str_mem_fd = NULL, *str_log = NULL, *str_controller = NULL;
        _c_cleanup_(c_freep) char *str_max_bytes = NULL, *str_max_fds = NULL, *str_max_matches = NULL;
        int r;
        /* Generating args */
        r = asprintf(&str_mem_fd, "%d", mem_fd);
        if (r < 0)
                return error_fold(r);
        r = asprintf(&str_log, "%d", broker->log_fd);
        if (r < 0)
                return error_fold(r);
        r = asprintf(&str_controller, "%d", broker->controller_fd);
        if (r < 0)
                return error_fold(r);
        r = asprintf(&str_max_bytes, "%lu", broker->max_bytes);
        if (r < 0)
                return error_fold(r);
        r = asprintf(&str_max_fds, "%lu", broker->max_fds + 1);
        if (r < 0)
                return error_fold(r);
        r = asprintf(&str_max_matches, "%lu", broker->max_matches);
        if (r < 0)
                return error_fold(r);

        /* execv */
        char *args[OPTION_NUM_MAX];
        int i = 0;
        args[i++] = broker->bin_path;
        generate_args_string(broker->log_fd > 0, args, OPTION_NUM_MAX, &i, "--log", str_log);
        generate_args_string(true, args, OPTION_NUM_MAX, &i, "--controller", str_controller);
        generate_args_string(true, args, OPTION_NUM_MAX, &i, "--machine-id", broker->machine_id);
        generate_args_string(true, args, OPTION_NUM_MAX, &i, "--max-bytes", str_max_bytes);
        generate_args_string(true, args, OPTION_NUM_MAX, &i, "--max-fds", str_max_fds);
        generate_args_string(true, args, OPTION_NUM_MAX, &i, "--max-matches", str_max_matches);
        generate_args_string(true, args, OPTION_NUM_MAX, &i, "--reexec", str_mem_fd);
        if (broker->arg_audit && i + 2 < OPTION_NUM_MAX)
                args[i++] = "--audit";
        args[i++] = NULL;

        log_append_here(&broker->log, LOG_INFO, 0, NULL);
        r = log_commitf(&broker->log, "Broker now reexecuting...");
        if (r)
                return error_fold(r);

        execv(broker->bin_path, args);
        return 0;
}

static void set_broker_from_arg(Broker *broker, BrokerArg *broker_arg) {
        broker->arg_audit = broker_arg->arg_audit;
        broker->bin_path = broker_arg->bin_path;
        broker->machine_id = broker_arg->machine_id;
        broker->log_fd = broker_arg->log_fd;
        broker->controller_fd = broker_arg->controller_fd;
        broker->mem_fd = broker_arg->mem_fd;
        broker->max_bytes = broker_arg->max_bytes;
        broker->max_fds = broker_arg->max_fds;
        broker->max_matches = broker_arg->max_matches;
        broker->max_objects = broker_arg->max_objects;
}

static int broker_reexecute(Broker *broker) {
        int mem_fd;
        int r;

        log_append_here(&broker->log, LOG_INFO, 0, NULL);
        r = log_commitf(&broker->log, "Serializing broker.\n");
        if (r)
                return error_fold(r);

        /* serialize */
        mem_fd = serialize_broker(broker);
        if (mem_fd < 0) {
                log_append_here(&broker->log, LOG_INFO, errno, DBUS_BROKER_CATALOG_BROKER_EXITED);
                r = log_commitf(&broker->log, "Failed to serialize broker.\n");
                if (r < 0)
                        return error_fold(r);
        }

        kill(broker->launcher_pid, SIGCHLD);
        return broker_execv_with_args(broker, mem_fd);
}

int broker_new(Broker **brokerp, BrokerArg *broker_arg) {
        _c_cleanup_(broker_freep) Broker *broker = NULL;
        struct ucred ucred;
        socklen_t z;
        sigset_t sigmask;
        int r, log_type;
        int log_fd = broker_arg->log_fd, controller_fd = broker_arg->controller_fd;
        const char* machine_id = broker_arg->machine_id;
        uint64_t max_bytes = broker_arg->max_bytes, max_fds = broker_arg->max_fds;
        uint64_t max_matches = broker_arg->max_matches, max_objects = broker_arg->max_objects;

        if (log_fd >= 0) {
                z = sizeof(log_type);
                r = getsockopt(log_fd, SOL_SOCKET, SO_TYPE, &log_type, &z);
                if (r < 0)
                        return error_origin(-errno);
        }

        z = sizeof(ucred);
        r = getsockopt(controller_fd, SOL_SOCKET, SO_PEERCRED, &ucred, &z);
        if (r < 0)
                return error_origin(-errno);

        broker = calloc(1, sizeof(*broker));
        if (!broker)
                return error_origin(-ENOMEM);

        broker->log = (Log)LOG_NULL;
        broker->bus = (Bus)BUS_NULL(broker->bus);
        broker->dispatcher = (DispatchContext)DISPATCH_CONTEXT_NULL(broker->dispatcher);
        broker->signals_fd = -1;
        broker->reexec_serial = -1;
        broker->do_reexec = false;
        broker->launcher_pid = getppid();
        set_broker_from_arg(broker, broker_arg);
        broker->signals_file = (DispatchFile)DISPATCH_FILE_NULL(broker->signals_file);
        broker->controller = (Controller)CONTROLLER_NULL(broker->controller);

        if (log_fd < 0)
                log_init(&broker->log);
        else if (log_type == SOCK_STREAM)
                log_init_stderr(&broker->log, log_fd);
        else if (log_type == SOCK_DGRAM)
                log_init_journal(&broker->log, log_fd);
        else
                return error_origin(-ENOTRECOVERABLE);

        /* XXX: make this run-time optional */
        log_set_lossy(&broker->log, true);

        r = bus_init(&broker->bus, &broker->log, machine_id, max_bytes, max_fds, max_matches, max_objects);
        if (r)
                return error_fold(r);

        /*
         * We need the seclabel to run the broker for 2 reasons: First, if
         * 'org.freedesktop.DBus' is queried for the seclabel, we need to
         * return some value. Second, all unlabeled names get this label
         * assigned by default. Due to the latter, this seclabel is actually
         * referenced in selinux rules, to allow peers to own names.
         * We use SO_PEERSEC on the controller socket to get this label.
         * However, note that this used to return the 'unlabeled_t' entry for
         * socketpairs until kernel v4.17. From v4.17 onwards it now returns
         * the correct label. There is no way to detect this at runtime,
         * though. We hard-require 4.17. If you use older kernels, you will get
         * selinux denials.
         */
        r = sockopt_get_peersec(controller_fd, &broker->bus.seclabel, &broker->bus.n_seclabel);
        if (r)
                return error_fold(r);

        r = sockopt_get_peergroups(controller_fd,
                                   &broker->log,
                                   ucred.uid,
                                   ucred.gid,
                                   &broker->bus.gids,
                                   &broker->bus.n_gids);
        if (r)
                return error_fold(r);

        broker->bus.pid = ucred.pid;
        r = user_registry_ref_user(&broker->bus.users, &broker->bus.user, ucred.uid);
        if (r)
                return error_fold(r);

        r = dispatch_context_init(&broker->dispatcher);
        if (r)
                return error_fold(r);

        sigemptyset(&sigmask);
        sigaddset(&sigmask, SIGTERM);
        sigaddset(&sigmask, SIGINT);

        broker->signals_fd = signalfd(-1, &sigmask, SFD_CLOEXEC | SFD_NONBLOCK);
        if (broker->signals_fd < 0)
                return error_origin(-errno);

        r = dispatch_file_init(&broker->signals_file,
                               &broker->dispatcher,
                               broker_dispatch_signals,
                               broker->signals_fd,
                               EPOLLIN,
                               0);
        if (r)
                return error_fold(r);

        dispatch_file_select(&broker->signals_file, EPOLLIN);

        r = controller_init(&broker->controller, broker, controller_fd);
        if (r)
                return error_fold(r);

        *brokerp = broker;
        broker = NULL;
        return 0;
}

Broker *broker_free(Broker *broker) {
        if (!broker)
                return NULL;

        controller_deinit(&broker->controller);
        dispatch_file_deinit(&broker->signals_file);
        c_close(broker->signals_fd);
        dispatch_context_deinit(&broker->dispatcher);
        bus_deinit(&broker->bus);
        log_deinit(&broker->log);
        free(broker);

        return NULL;
}

static int broker_log_metrics(Broker *broker) {
        Metrics *metrics = &broker->bus.metrics;
        double stddev;
        int r;

        stddev = metrics_read_standard_deviation(metrics);
        log_appendf(broker->bus.log,
                    "DBUS_BROKER_METRICS_DISPATCH_COUNT=%"PRIu64"\n"
                    "DBUS_BROKER_METRICS_DISPATCH_MIN=%"PRIu64"\n"
                    "DBUS_BROKER_METRICS_DISPATCH_MAX=%"PRIu64"\n"
                    "DBUS_BROKER_METRICS_DISPATCH_AVG=%"PRIu64"\n"
                    "DBUS_BROKER_METRICS_DISPATCH_STDDEV=%.0f\n",
                    metrics->count,
                    metrics->minimum,
                    metrics->maximum,
                    metrics->average,
                    stddev);
        log_append_here(broker->bus.log, LOG_INFO, 0, DBUS_BROKER_CATALOG_DISPATCH_STATS);
        r = log_commitf(broker->bus.log,
                       "Dispatched %"PRIu64" messages @ %"PRIu64"(±%.0f)μs / message.",
                       metrics->count,
                       metrics->average / 1000,
                       stddev / 1000);
        if (r)
                return error_fold(r);

        return 0;
}

int broker_run(Broker *broker) {
        sigset_t signew, sigold;
        int r, k;

        sigemptyset(&signew);
        sigaddset(&signew, SIGTERM);
        sigaddset(&signew, SIGINT);

        sigprocmask(SIG_BLOCK, &signew, &sigold);

        r = connection_open(&broker->controller.connection);
        if (r == CONNECTION_E_EOF)
                return MAIN_EXIT;
        else if (r)
                return error_fold(r);

        if (broker->mem_fd) {
                r = deserialize_broker(broker, broker->mem_fd);
                if (r)
                        return error_trace(r);
        }

        do {
                r = dispatch_context_dispatch(&broker->dispatcher);
                if (r == DISPATCH_E_EXIT)
                        r = MAIN_EXIT;
                else if (r == DISPATCH_E_FAILURE)
                        r = MAIN_FAILED;
                else
                        r = error_fold(r);

                if (broker->do_reexec)
                        r = MAIN_REEXEC;

        } while (!r);

        Peer *peeri;
        c_rbtree_for_each_entry(peeri, &broker->bus.peers.peer_tree, registry_node) {
                socket_dispatch_write(&peeri->connection.socket);
        }

        if (r == MAIN_REEXEC)
                (void) broker_reexecute(broker);

        peer_registry_flush(&broker->bus.peers);

        k = broker_log_metrics(broker);
        if (k)
                r = error_fold(k);

        sigprocmask(SIG_SETMASK, &sigold, NULL);

        return r;
}

int broker_update_environment(Broker *broker, const char * const *env, size_t n_env) {
        return error_fold(controller_dbus_send_environment(&broker->controller, env, n_env));
}

int broker_reload_config(Broker *broker, User *sender_user, uint64_t sender_id, uint32_t sender_serial) {
        int r;

        r = controller_request_reload(&broker->controller, sender_user, sender_id, sender_serial);
        if (r) {
                if (r == CONTROLLER_E_SERIAL_EXHAUSTED ||
                    r == CONTROLLER_E_QUOTA)
                        return BROKER_E_FORWARD_FAILED;

                return error_fold(r);
        }

        return 0;
}

int deserialize_broker(Broker *broker, int mem_fd) {
        FILE *f = NULL;
        int max_ids_length = ID_LENGTH_MAX + strlen("max_ids=");
        _c_cleanup_(c_freep) char *buf = malloc(max_ids_length);

        errno = 0;
        f = fdopen(mem_fd, "r");
        if (!f)
                return error_trace(-errno);

        while (fgets(buf, max_ids_length, f) != NULL) {
                char *max_ids = string_prefix(buf, "max_ids=");
                if (max_ids) {
                        broker->bus.peers.ids = atoi(max_ids);
                        break;
                }
        }

        return 0;
}
