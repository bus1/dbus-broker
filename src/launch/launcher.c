/*
 * Launcher
 */

#include <c-ini.h>
#include <c-rbtree.h>
#include <c-shquote.h>
#include <c-stdaux.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>
#include <systemd/sd-id128.h>
#include "catalog/catalog-ids.h"
#include "dbus/protocol.h"
#include "launch/config.h"
#include "launch/launcher.h"
#include "launch/nss-cache.h"
#include "launch/policy.h"
#include "launch/service.h"
#include "util/apparmor.h"
#include "util/audit.h"
#include "util/dirwatch.h"
#include "util/error.h"
#include "util/fs.h"
#include "util/log.h"
#include "util/misc.h"
#include "util/nsec.h"
#include "util/string.h"

/*
 * These are the default limits used when spawning dbus-broker. They are
 * similar to the limits used by dbus-daemon(1) (specified here in parentheses)
 * but slightly lowered to avoid DoS. We should be fine, since dbus-broker
 * employs a dynamically adjusted quota-based share distribution of resources.
 */
static const uint64_t main_max_outgoing_bytes = 8 * 1024 * 1024; /* 127MiB */
static const uint64_t main_max_outgoing_unix_fds = 64;
static const uint64_t main_max_connections_per_user = 64; /* 256 */
static const uint64_t main_max_match_rules_per_connection = 256;

static const char *     main_arg_broker = BINDIR "/dbus-broker";

static sd_bus *bus_close_unref(sd_bus *bus) {
        /*
         * It is not sufficient to simply call sd_bus_unref(), as messages
         * in the bus' queues may pin the bus itself. Also,
         * sd_bus_flush_close_unref() is not always appropriate as it would
         * block in poll waiting for messages to be flushed to the socket.
         *
         * In some cases all we really want to do is close the socket and
         * release all the memory, ignoring whether or not it has been
         * flushed to the kernel (typically in error paths).
         */
        if (!bus)
                return NULL;

        sd_bus_close(bus);

        return sd_bus_unref(bus);
}

static void log_append_bus_error(Log *log, const sd_bus_error *error) {
        log_appendf(log, "DBUS_BROKER_LAUNCH_BUS_ERROR_NAME=%s\n", error->name);
        log_appendf(log, "DBUS_BROKER_LAUNCH_BUS_ERROR_MESSAGE=%s\n", error->message);
}

static void log_append_siginfo(Log *log, const siginfo_t *si) {
        log_appendf(log, "DBUS_BROKER_LAUNCH_SIGNAL_SIGNO=%d\n", si->si_signo);
        log_appendf(log, "DBUS_BROKER_LAUNCH_SIGNAL_CODE=%d\n", si->si_code);
        log_appendf(log, "DBUS_BROKER_LAUNCH_SIGNAL_PID=%"PRIu32"\n", si->si_pid);
        log_appendf(log, "DBUS_BROKER_LAUNCH_SIGNAL_UID=%"PRIu32"\n", si->si_uid);
}

static void log_append_signalfd_siginfo(Log *log, const struct signalfd_siginfo *ssi) {
        siginfo_t si = {
                .si_signo = ssi->ssi_signo,
                .si_code = ssi->ssi_code,
                .si_pid = ssi->ssi_pid,
                .si_uid = ssi->ssi_uid,
        };
        log_append_siginfo(log, &si);
}

static void log_append_service_path(Log *log, const char *path) {
        if (path)
                log_appendf(log, "DBUS_BROKER_LAUNCH_SERVICE_PATH=%s\n", path);
}

static void log_append_service_name(Log *log, const char *name) {
        if (name)
                log_appendf(log, "DBUS_BROKER_LAUNCH_SERVICE_NAME=%s\n", name);
}

static void log_append_service_user(Log *log, const char *user) {
        if (user)
                log_appendf(log, "DBUS_BROKER_LAUNCH_SERVICE_USER=%s\n", user);
}

static int launcher_reload_config(Launcher *launcher);

static int launcher_on_sighup(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Launcher *launcher = userdata;
        int r;

        log_append_here(&launcher->log, LOG_INFO, si->ssi_errno, DBUS_BROKER_CATALOG_SIGHUP);
        log_append_signalfd_siginfo(&launcher->log, si);

        r = log_commitf(&launcher->log, "Caught SIGHUP, trigger reload.\n");
        if (r)
                return error_fold(r);

        r = launcher_reload_config(launcher);
        if (r) {
                if (r == LAUNCHER_E_INVALID_CONFIG) {
                        log_append_here(&launcher->log, LOG_WARNING, 0, NULL);

                        r = log_commitf(&launcher->log, "Invalid configuration, ignored.\n");
                        if (r)
                                return error_fold(r);
                } else {
                        return error_fold(r);
                }
        }

        return 1;
}

static int launcher_on_dirwatch(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Launcher *launcher = userdata;
        int r;

        r = dirwatch_dispatch(launcher->dirwatch);
        if (r != DIRWATCH_E_TRIGGERED)
                return error_fold(r);

        log_append_here(&launcher->log, LOG_INFO, 0, DBUS_BROKER_CATALOG_DIRWATCH);

        r = log_commitf(&launcher->log, "Noticed file-system modification, trigger reload.\n");
        if (r)
                return error_fold(r);

        r = launcher_reload_config(launcher);
        if (r) {
                if (r == LAUNCHER_E_INVALID_CONFIG) {
                        log_append_here(&launcher->log, LOG_WARNING, 0, NULL);

                        r = log_commitf(&launcher->log, "Invalid configuration, ignored.\n");
                        if (r)
                                return error_fold(r);
                } else {
                        return error_fold(r);
                }
        }

        return 1;
}

static int launcher_open_journal(int *fdp) {
        _c_cleanup_(c_closep) int fd = -1;
        struct sockaddr_un address = {
                .sun_family = AF_UNIX,
                .sun_path = "/run/systemd/journal/socket",
        };
        int r;

        fd = socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
                return error_origin(-errno);

        r = connect(fd,
                    (struct sockaddr *)&address,
                    offsetof(struct sockaddr_un, sun_path) + strlen(address.sun_path));
        if (r < 0)
                return error_origin(-errno);

        *fdp = fd;
        fd = -1;
        return 0;
}

static int launcher_open_log(Launcher *launcher) {
        int r, fd;

        c_assert(log_get_fd(&launcher->log) < 0);

        r = launcher_open_journal(&fd);
        if (r)
                return error_fold(r);

        log_init_journal_consume(&launcher->log, fd);

        /* XXX: make this run-time optional */
        log_set_lossy(&launcher->log, true);

        return 0;
}

int launcher_new(
        Launcher **launcherp,
        int fd_listen,
        int fd_metrics,
        bool audit,
        const char *configfile,
        bool user_scope
) {
        _c_cleanup_(launcher_freep) Launcher *launcher = NULL;
        int r;

        launcher = calloc(1, sizeof(*launcher));
        if (!launcher)
                return error_origin(-ENOMEM);

        launcher->log = (Log)LOG_NULL;
        launcher->fd_listen = fd_listen;
        launcher->fd_metrics = fd_metrics;
        launcher->uid = -1;
        launcher->gid = -1;
        launcher->audit = audit;
        launcher->user_scope = user_scope;

        if (configfile)
                launcher->configfile = strdup(configfile);

        r = launcher_open_log(launcher);
        if (r)
                return error_trace(r);

        r = sd_event_default(&launcher->event);
        if (r < 0)
                return error_origin(r);

        r = sd_event_add_signal(launcher->event, NULL, SIGTERM, NULL, NULL);
        if (r < 0)
                return error_origin(r);

        r = sd_event_add_signal(launcher->event, NULL, SIGINT, NULL, NULL);
        if (r < 0)
                return error_origin(r);

        r = sd_event_add_signal(launcher->event, NULL, SIGHUP, launcher_on_sighup, launcher);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_new(&launcher->bus_controller);
        if (r < 0)
                return error_origin(r);

        *launcherp = launcher;
        launcher = NULL;
        return 0;
}

Launcher *launcher_free(Launcher *launcher) {
        Service *service, *safe;

        if (!launcher)
                return NULL;

        c_rbtree_for_each_entry_safe_postorder_unlink(service, safe, &launcher->services, rb)
                service_free(service);
        c_assert(c_rbtree_is_empty(&launcher->services_by_name));

        sd_event_source_unref(launcher->dirwatch_src);
        dirwatch_free(launcher->dirwatch);
        c_close(launcher->fd_metrics);
        c_close(launcher->fd_listen);
        free(launcher->configfile);
        log_deinit(&launcher->log);
        bus_close_unref(launcher->bus_regular);
        bus_close_unref(launcher->bus_controller);
        sd_event_unref(launcher->event);
        free(launcher);

        return NULL;
}

static noreturn void launcher_run_child(Launcher *launcher, int fd_controller) {
        sd_id128_t machine_id;
        char str_log[C_DECIMAL_MAX(int) + 1],
             str_controller[C_DECIMAL_MAX(int) + 1],
             str_machine_id[33],
             str_max_bytes[C_DECIMAL_MAX(uint64_t)],
             str_max_fds[C_DECIMAL_MAX(uint64_t)],
             str_max_matches[C_DECIMAL_MAX(uint64_t)];
        const char * const argv[] = {
                "dbus-broker",
                "--log",
                str_log,
                "--controller",
                str_controller,
                "--machine-id",
                str_machine_id,
                "--max-bytes",
                str_max_bytes,
                "--max-fds",
                str_max_fds,
                "--max-matches",
                str_max_matches,
                launcher->audit ? "--audit" : NULL, /* note that this needs to be the last argument to work */
                NULL,
        };
        int r, fd_journal;

        if (launcher->uid != (uint32_t)-1) {
                r = util_audit_drop_permissions(launcher->uid, launcher->gid);
                if (r)
                        goto exit;
        }

        r = prctl(PR_SET_PDEATHSIG, SIGTERM);
        if (r) {
                r = error_origin(-errno);
                goto exit;
        }

        r = launcher_open_journal(&fd_journal);
        if (r) {
                r = error_trace(r);
                goto exit;
        }

        r = fcntl(fd_journal, F_GETFD);
        if (r < 0) {
                r = error_origin(-errno);
                goto exit;
        }

        r = fcntl(fd_journal, F_SETFD, r & ~FD_CLOEXEC);
        if (r < 0) {
                r = error_origin(-errno);
                goto exit;
        }

        r = fcntl(fd_controller, F_GETFD);
        if (r < 0) {
                r = error_origin(-errno);
                goto exit;
        }

        r = fcntl(fd_controller, F_SETFD, r & ~FD_CLOEXEC);
        if (r < 0) {
                r = error_origin(-errno);
                goto exit;
        }

        r = sd_id128_get_machine(&machine_id);
        if (r < 0) {
                r = error_origin(r);
                goto exit;
        }

        sd_id128_to_string(machine_id, str_machine_id);

        r = snprintf(str_log, sizeof(str_log), "%d", fd_journal);
        c_assert(r < (ssize_t)sizeof(str_log));

        r = snprintf(str_controller, sizeof(str_controller), "%d", fd_controller);
        c_assert(r < (ssize_t)sizeof(str_controller));

        r = snprintf(str_max_bytes, sizeof(str_max_bytes), "%"PRIu64, launcher->max_bytes);
        c_assert(r < (ssize_t)sizeof(str_max_bytes));

        r = snprintf(str_max_fds, sizeof(str_max_fds), "%"PRIu64, launcher->max_fds);
        c_assert(r < (ssize_t)sizeof(str_max_fds));

        r = snprintf(str_max_matches, sizeof(str_max_matches), "%"PRIu64, launcher->max_matches);
        c_assert(r < (ssize_t)sizeof(str_max_matches));

        r = execve(main_arg_broker, (char * const *)argv, environ);
        r = error_origin(-errno);

exit:
        _exit(1);
}

static int launcher_on_child_exit(sd_event_source *source, const siginfo_t *si, void *userdata) {
        Launcher *launcher = userdata;
        int r;

        log_append_here(&launcher->log, LOG_INFO, si->si_errno, DBUS_BROKER_CATALOG_BROKER_EXITED);
        log_append_siginfo(&launcher->log, si);

        r = log_commitf(&launcher->log, "Caught SIGCHLD of broker.\n");
        if (r)
                return error_fold(r);

        return sd_event_exit(sd_event_source_get_event(source),
                             (si->si_code == CLD_EXITED) ? si->si_status : EXIT_FAILURE);
}

static int launcher_fork(Launcher *launcher, int fd_controller) {
        pid_t pid;
        int r;

        pid = fork();
        if (pid < 0)
                return error_origin(-errno);

        if (!pid)
                launcher_run_child(launcher, fd_controller);

        r = sd_event_add_child(launcher->event, NULL, pid, WEXITED, launcher_on_child_exit, launcher);
        if (r < 0)
                return error_origin(-errno);

        close(fd_controller);
        return 0;
}

static int launcher_on_name_activate(Launcher *launcher, sd_bus_message *m, const char *id) {
        Service *service;
        uint64_t serial;
        int r;

        r = sd_bus_message_read(m, "t", &serial);
        if (r < 0)
                return error_origin(r);

        service = c_rbtree_find_entry(&launcher->services,
                                      service_compare,
                                      id,
                                      Service,
                                      rb);
        if (!service) {
                log_append_here(&launcher->log, LOG_ERR, 0, NULL);

                r = log_commitf(&launcher->log, "Activation request on unknown name '%s'.\n", id);
                if (r)
                        return error_fold(r);

                return 0;
        }

        r = service_activate(service, serial);
        if (r)
                return error_fold(r);

        return 0;
}

static int launcher_set_environment_handler(sd_bus_message *message, void *userdata, sd_bus_error *errorp) {
        Launcher *launcher = userdata;
        const sd_bus_error *error;
        int r;

        error = sd_bus_message_get_error(message);
        if (!error)
                /* environment set successfully */
                return 1;

        log_append_here(&launcher->log, LOG_ERR, 0, NULL);
        log_append_bus_error(&launcher->log, error);

        r = log_commitf(&launcher->log, "Updating activation environment failed.\n");
        if (r)
                return error_fold(r);

        return 1;
}

static int launcher_on_set_activation_environment(Launcher *launcher, sd_bus_message *m) {
        _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *method_call = NULL;
        int r;

        r = sd_bus_message_new_method_call(launcher->bus_regular, &method_call,
                                           "org.freedesktop.systemd1",
                                           "/org/freedesktop/systemd1",
                                           "org.freedesktop.systemd1.Manager",
                                           "SetEnvironment");
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_enter_container(m, 'a', "{ss}");
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_open_container(method_call, 'a', "s");
        if (r < 0)
                return error_origin(r);

        while (!sd_bus_message_at_end(m, false)) {
                _c_cleanup_(c_freep) char *entry = NULL;
                const char *key, *value;

                r = sd_bus_message_read(m, "{ss}", &key, &value);
                if (r < 0)
                        return error_origin(r);

                r = asprintf(&entry, "%s=%s", key, value);
                if (r < 0)
                        return error_origin(-errno);

                r = sd_bus_message_append(method_call, "s", entry);
                if (r < 0)
                        return error_origin(r);
        }

        r = sd_bus_message_close_container(method_call);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_call_async(launcher->bus_regular, NULL, method_call, launcher_set_environment_handler, launcher, -1);
        if (r < 0)
                return error_origin(r);

        return 0;
}

static int launcher_on_message(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Launcher *launcher = userdata;
        const char *path, *suffix;
        int r = 0;

        path = sd_bus_message_get_path(m);
        if (!path)
                return 0;

        suffix = string_prefix(path, "/org/bus1/DBus/Name/");
        if (suffix) {
                if (sd_bus_message_is_signal(m, "org.bus1.DBus.Name", "Activate"))
                        r = launcher_on_name_activate(launcher, m, suffix);
        } else if (strcmp(path, "/org/bus1/DBus/Broker") == 0) {
                if (sd_bus_message_is_signal(m, "org.bus1.DBus.Broker", "SetActivationEnvironment"))
                        r = launcher_on_set_activation_environment(launcher, m);
        }

        return error_trace(r);
}

static int launcher_ini_reader_parse_file(Launcher *launcher, CIniGroup **groupp, const char *path) {
        _c_cleanup_(c_closep) int fd = -1;
        _c_cleanup_(c_ini_reader_freep) CIniReader *reader = NULL;
        _c_cleanup_(c_ini_domain_unrefp) CIniDomain *domain = NULL;
        CIniGroup *group;
        ssize_t len;
        int r;

        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
                /*
                 * For compatibility reasons we have to accept any failure
                 * during open(2). dbus-daemon(1) simply ignores those errors
                 * and skips the service file in question.
                 *
                 * We would very much prefer to whitelist specific error codes
                 * here, but we would be playing whack-a-mole, so lets just
                 * treat it as soft-error.
                 */
                log_append_here(&launcher->log, LOG_ERR, errno, DBUS_BROKER_CATALOG_SERVICE_FAILED_OPEN);
                log_append_service_path(&launcher->log, path);
                if (errno == ENOENT) {
                        r = log_commitf(&launcher->log, "Original source was unlinked while parsing service file '%s'\n", path);
                        if (r)
                                return error_fold(r);
                } else if (errno == EACCES) {
                        r = log_commitf(&launcher->log, "Read access denied for service file '%s'\n", path);
                        if (r)
                                return error_fold(r);
                } else {
                        r = log_commitf(&launcher->log, "Unable to open service file '%s': %m\n", path);
                        if (r)
                                return error_fold(r);
                }

                return LAUNCHER_E_INVALID_SERVICE_FILE;
        }

        r = c_ini_reader_new(&reader);
        if (r)
                return error_origin(r);

        c_ini_reader_set_mode(reader,
                              C_INI_MODE_EXTENDED_WHITESPACE |
                              C_INI_MODE_MERGE_GROUPS |
                              C_INI_MODE_OVERRIDE_ENTRIES);

        for (;;) {
                uint8_t buf[1024];

                len = read(fd, buf, sizeof(buf));
                if (len < 0)
                        return error_origin(-errno);
                else if (len == 0)
                        break;

                r = c_ini_reader_feed(reader, buf, len);
                if (r)
                        return error_origin(r);
        }

        r = c_ini_reader_seal(reader, &domain);
        if (r)
                return error_origin(r);

        group = c_ini_domain_find(domain, "D-BUS Service", -1);
        if (!group) {
                log_append_here(&launcher->log, LOG_ERR, 0, DBUS_BROKER_CATALOG_SERVICE_INVALID);
                log_append_service_path(&launcher->log, path);

                r = log_commitf(&launcher->log, "Missing 'D-Bus Service' section in service file '%s'\n", path);
                if (r)
                        return error_fold(r);

                return LAUNCHER_E_INVALID_SERVICE_FILE;
        }

        *groupp = c_ini_group_ref(group);
        return 0;
}

static int launcher_load_service_file(Launcher *launcher, const char *path, const char *basename, size_t n_basename, NSSCache *nss_cache) {
        _c_cleanup_(c_ini_group_unrefp) CIniGroup *group = NULL;
        _c_cleanup_(c_freep) char **argv = NULL;
        _c_cleanup_(service_freep) Service *service = NULL;
        CIniEntry *name_entry = NULL, *unit_entry = NULL, *exec_entry = NULL, *user_entry = NULL;
        const char *name = NULL, *unit = NULL, *exec = NULL, *user = NULL;
        size_t argc = 0, n_exec, n_name;
        CRBNode **slot, *parent;
        uid_t uid;
        int r;

        r = launcher_ini_reader_parse_file(launcher, &group, path);
        if (r)
                return error_trace(r);

        name_entry = c_ini_group_find(group, "Name", -1);
        unit_entry = c_ini_group_find(group, "SystemdService", -1);
        exec_entry = c_ini_group_find(group, "Exec", -1);
        user_entry = c_ini_group_find(group, "User", -1);

        if (!name_entry) {
                log_append_here(&launcher->log, LOG_ERR, 0, DBUS_BROKER_CATALOG_SERVICE_INVALID);
                log_append_service_path(&launcher->log, path);

                r = log_commitf(&launcher->log, "Missing name in service file '%s'\n", path);
                if (r)
                        return error_fold(r);

                return LAUNCHER_E_INVALID_SERVICE_FILE;
        }

        name = c_ini_entry_get_value(name_entry, &n_name);
        if (!dbus_validate_name(name, n_name)) {
                log_append_here(&launcher->log, LOG_ERR, 0, DBUS_BROKER_CATALOG_SERVICE_INVALID);
                log_append_service_path(&launcher->log, path);
                log_append_service_name(&launcher->log, name);

                r = log_commitf(&launcher->log, "Invalid D-Bus name '%s' in service file '%s'\n", name, path);
                if (r)
                        return error_fold(r);

                return LAUNCHER_E_INVALID_SERVICE_FILE;
        } else if (n_name != n_basename || strncmp(name, basename, n_name) != 0) {
                if (launcher->user_scope) {
                        log_append_here(&launcher->log, LOG_WARNING, 0, DBUS_BROKER_CATALOG_SERVICE_INVALID);
                        log_append_service_path(&launcher->log, path);
                        log_append_service_name(&launcher->log, name);

                        r = log_commitf(&launcher->log, "Service file '%s' is not named after the D-Bus name '%s'.\n", path, name);
                        if (r)
                                return error_fold(r);

                        /* For backwards compatibilty, we do not fail in the user-scope. */
                } else {
                        log_append_here(&launcher->log, LOG_ERR, 0, DBUS_BROKER_CATALOG_SERVICE_INVALID);
                        log_append_service_path(&launcher->log, path);
                        log_append_service_name(&launcher->log, name);

                        r = log_commitf(&launcher->log, "Service file '%s' is not named after the D-Bus name '%s'.\n", path, name);
                        if (r)
                                return error_fold(r);

                        return LAUNCHER_E_INVALID_SERVICE_FILE;
                }
        }

        if (unit_entry)
                unit = c_ini_entry_get_value(unit_entry, NULL);

        if (exec_entry) {
                exec = c_ini_entry_get_value(exec_entry, &n_exec);

                r = c_shquote_parse_argv(&argv, &argc, exec, n_exec);
                if (r) {
                        if (r == C_SHQUOTE_E_BAD_QUOTING || r == C_SHQUOTE_E_CONTAINS_NULL) {
                                log_append_here(&launcher->log, LOG_ERR, 0, DBUS_BROKER_CATALOG_SERVICE_INVALID);
                                log_append_service_path(&launcher->log, path);

                                r = log_commitf(&launcher->log, "Invalid exec '%s' in service file '%s'\n", exec, path);
                                if (r)
                                        return error_fold(r);

                                return LAUNCHER_E_INVALID_SERVICE_FILE;
                        }

                        return error_origin(r);
                }
        }

        if (user_entry) {
                user = c_ini_entry_get_value(user_entry, NULL);

                r = nss_cache_get_uid(nss_cache, &uid, NULL, user);
                if (r) {
                        if (r == NSS_CACHE_E_INVALID_NAME) {
                                log_append_here(&launcher->log, LOG_ERR, 0, DBUS_BROKER_CATALOG_SERVICE_INVALID);
                                log_append_service_path(&launcher->log, path);
                                log_append_service_user(&launcher->log, user);

                                r = log_commitf(&launcher->log, "Invalid user name '%s' in service file '%s'\n", user, path);
                                if (r)
                                        return error_fold(r);

                                return LAUNCHER_E_INVALID_SERVICE_FILE;
                        }

                        return error_fold(r);
                }

        } else {
                uid = getuid();
        }

        slot = c_rbtree_find_slot(&launcher->services_by_name, service_compare_by_name, name, &parent);
        if (slot) {
                r = service_new(&service, launcher, name, slot, parent, path, unit, argc, argv, user, uid);
                if (r)
                        return error_trace(r);

                service->reload_tag = true;
        } else {
                Service *old_service = c_container_of(parent, Service, rb_by_name);

                if (!old_service->reload_tag) {
                        old_service->reload_tag = true;
                        r = service_update(old_service, path, unit, argc, argv, user, uid);
                        if (r)
                                return error_trace(r);
                } else {
                        log_append_here(&launcher->log, LOG_ERR, 0, DBUS_BROKER_CATALOG_SERVICE_INVALID);
                        log_append_service_path(&launcher->log, path);
                        log_append_service_name(&launcher->log, name);

                        r = log_commitf(&launcher->log, "Ignoring duplicate name '%s' in service file '%s'\n", name, path);
                        if (r)
                                return error_fold(r);

                        return LAUNCHER_E_INVALID_SERVICE_FILE;
                }
        }

        service = NULL;
        return 0;
}

static int launcher_load_service_dir(Launcher *launcher, const char *dirpath, NSSCache *nss_cache) {
        const char suffix[] = ".service";
        _c_cleanup_(fs_dirlist_freep) FsDirlist *list = NULL;
        _c_cleanup_(c_closedirp) DIR *dir = NULL;
        struct dirent *de;
        char *path;
        size_t i, n;
        int r;

        dir = opendir(dirpath);
        if (!dir) {
                if (errno == ENOENT || errno == ENOTDIR) {
                        return 0;
                } else if (errno == EACCES) {
                        log_append_here(&launcher->log, LOG_ERR, 0, NULL);
                        r = log_commitf(&launcher->log, "Access denied to service directory '%s'\n", dirpath);
                        if (r)
                                return error_fold(r);

                        return 0;
                } else {
                        log_append_here(&launcher->log, LOG_ERR, errno, NULL);
                        r = log_commitf(&launcher->log, "Unable to open service directory '%s': %m\n", dirpath);
                        if (r)
                                return error_fold(r);

                        return error_origin(-errno);
                }
        }

        r = dirwatch_add(launcher->dirwatch, dirpath);
        if (r)
                return error_fold(r);

        r = fs_dir_list(dir, &list, FS_DIR_FLAG_NO_HIDDEN);
        if (r)
                return error_fold(r);

        for (i = 0; i < list->n_entries; ++i) {
                de = list->entries[i];

                n = strlen(de->d_name);
                if (n <= strlen(suffix))
                        continue;
                if (strcmp(de->d_name + n - strlen(suffix), suffix))
                        continue;

                r = asprintf(&path, "%s/%s", dirpath, de->d_name);
                if (r < 0)
                        return error_origin(-ENOMEM);

                r = launcher_load_service_file(launcher, path, de->d_name, n - strlen(suffix), nss_cache);
                free(path);
                if (r && r != LAUNCHER_E_INVALID_SERVICE_FILE)
                        return error_trace(r);
        }

        return 0;
}

static int launcher_add_services(Launcher *launcher) {
        Service *service;
        int r;

        c_rbtree_for_each_entry(service, &launcher->services, rb) {
                r = service_add(service);
                if (r)
                        return error_fold(r);
        }

        return 0;
}

static int launcher_remove_services(Launcher *launcher) {
        Service *service, *service_safe;
        int r;

        c_rbtree_for_each_entry_safe(service, service_safe, &launcher->services, rb) {
                if (service->reload_tag)
                        continue;

                r = service_remove(service);
                if (r)
                        return error_fold(r);

                service_free(service);
        }

        return 0;
}

static int launcher_load_standard_session_services(Launcher *launcher, NSSCache *nss_cache) {
        const char *suffix = "dbus-1/services";
        int r;

        /*
         * $XDG_RUNTIME_DIR/dbus-1/services is used in user-scope to
         * load transient units. dbus-daemon(1) actually creates this
         * path, we don't. It is incompatible with socket-activation of
         * dbus-daemon(1), so you must already be able to deal with
         * creating the directory yourself. But if the directory is
         * there, we load units from it.
         */
        {
                _c_cleanup_(c_freep) char *dirpath = NULL;
                const char *runtime_dir;

                runtime_dir = getenv("XDG_RUNTIME_DIR");
                if (!runtime_dir) {
                        fprintf(stderr, "Cannot figure out service runtime directory\n");
                } else {
                        r = asprintf(&dirpath, "%s/%s", runtime_dir, suffix);
                        if (r < 0)
                                return error_origin(-ENOMEM);

                        r = launcher_load_service_dir(launcher, dirpath, nss_cache);
                        if (r)
                                return error_trace(r);
                }
        }

        /*
         * $HOME/.local/share/dbus-1/services is used for user buses
         * additionally to the above mentioned directories. Note that
         * it can be modified via the XDG_DATA_HOME env-variable.
         */
        {
                _c_cleanup_(c_freep) char *data_home_dir = NULL;
                struct passwd *passwd;
                const char *dir;

                dir = getenv("XDG_DATA_HOME");
                if (dir) {
                        r = asprintf(&data_home_dir, "%s/%s", dir, suffix);
                        if (r < 0)
                                return error_origin(-ENOMEM);
                } else {
                        passwd = getpwuid(getuid());
                        if (passwd && passwd->pw_dir) {
                                r = asprintf(&data_home_dir, "%s/.local/share/%s", passwd->pw_dir, suffix);
                                if (r < 0)
                                        return error_origin(-ENOMEM);
                        }
                }
                if (!data_home_dir) {
                        fprintf(stderr, "Cannot figure out service home directory\n");
                } else {
                        r = launcher_load_service_dir(launcher, data_home_dir, nss_cache);
                        if (r)
                                return error_trace(r);
                }
        }

        /*
         * As last step, XDG_DATA_DIRS (or its default) are searched for
         * service files. ./dbus-1/services/ is appended to each path found in
         * XDG_DATA_DIRS.
         */
        {
                const char *data_dirs, *sep;
                size_t n;

                data_dirs = getenv("XDG_DATA_DIRS") ?:
                            "/usr/local/share:/usr/share";

                while (*data_dirs) {
                        sep = strchr(data_dirs, ':');
                        n = sep ? (size_t)(sep - data_dirs) : strlen(data_dirs);

                        if (n) {
                                _c_cleanup_(c_freep) char *dirpath = NULL;

                                r = asprintf(&dirpath, "%.*s/%s", (int)n, data_dirs, suffix);
                                if (r < 0)
                                        return error_origin(-ENOMEM);

                                r = launcher_load_service_dir(launcher, dirpath, nss_cache);
                                if (r)
                                        return error_trace(r);
                        }

                        data_dirs += n + !!sep;
                }
        }

        return 0;
}

static int launcher_load_standard_system_services(Launcher *launcher, NSSCache *nss_cache) {
        static const char *default_data_dirs[] = {
                "/etc",
                "/run",
                "/usr/local/share",
                "/usr/share",
                "/lib",
                NULL,
        };
        const char *suffix = "dbus-1/system-services";
        size_t i;
        int r;

        /*
         * In system scope, the default data directories are used. They
         * cannot be modified via env-variables!
         *
         * dbus-daemon(1) also supports /lib, which we don't. If there
         * is need, add it later.
         *
         * The order in which the directories are parsed follows the order
         * of dbus-daemon(1).
         */

        for (i = 0; default_data_dirs[i]; ++i) {
                _c_cleanup_(c_freep) char *dirpath = NULL;

                r = asprintf(&dirpath, "%s/%s", default_data_dirs[i], suffix);
                if (r < 0)
                        return error_origin(-ENOMEM);

                r = launcher_load_service_dir(launcher, dirpath, nss_cache);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

static int launcher_load_services(Launcher *launcher, ConfigRoot *config, NSSCache *nss_cache) {
        ConfigNode *cnode;
        int r;

        c_list_for_each_entry(cnode, &config->node_list, root_link) {
                switch (cnode->type) {
                case CONFIG_NODE_STANDARD_SESSION_SERVICEDIRS:
                        r = launcher_load_standard_session_services(launcher, nss_cache);
                        if (r)
                                return error_trace(r);

                        break;
                case CONFIG_NODE_STANDARD_SYSTEM_SERVICEDIRS:
                        r = launcher_load_standard_system_services(launcher, nss_cache);
                        if (r)
                                return error_trace(r);

                        break;
                case CONFIG_NODE_SERVICEDIR:
                        r = launcher_load_service_dir(launcher, cnode->servicedir.path, nss_cache);
                        if (r)
                                return error_trace(r);

                        break;
                default:
                        /* ignored */
                        break;
                }

        }

        return 0;
}

static int launcher_parse_config(Launcher *launcher, ConfigRoot **rootp, NSSCache *nss_cache) {
        _c_cleanup_(config_parser_deinit) ConfigParser parser = CONFIG_PARSER_NULL(parser);
        _c_cleanup_(dirwatch_freep) Dirwatch *dirwatch = NULL;
        uint64_t max_match_rules_per_connection = main_max_match_rules_per_connection;
        uint64_t max_connections_per_user = main_max_connections_per_user;
        uint64_t max_outgoing_unix_fds = main_max_outgoing_unix_fds;
        uint64_t max_outgoing_bytes = main_max_outgoing_bytes;
        bool at_console = false;
        const char *configfile;
        ConfigNode *cnode;
        int r;

        r = dirwatch_new(&dirwatch);
        if (r)
                return error_fold(r);

        if (launcher->configfile)
                configfile = launcher->configfile;
        else if (launcher->user_scope)
                configfile = "/usr/share/dbus-1/session.conf";
        else
                configfile = "/usr/share/dbus-1/system.conf";

        config_parser_init(&parser);

        r = config_parser_read(&parser, rootp, configfile, nss_cache, dirwatch);
        if (r) {
                if (r == CONFIG_E_INVALID)
                        return LAUNCHER_E_INVALID_CONFIG;

                return error_fold(r);
        }

        launcher->dirwatch = dirwatch_free(launcher->dirwatch);
        launcher->dirwatch_src = sd_event_source_unref(launcher->dirwatch_src);

        launcher->dirwatch = dirwatch;
        dirwatch = NULL;

        r = sd_event_add_io(launcher->event,
                            &launcher->dirwatch_src,
                            dirwatch_get_fd(launcher->dirwatch),
                            EPOLLIN,
                            launcher_on_dirwatch,
                            launcher);
        if (r)
                return error_origin(r);

        c_list_for_each_entry(cnode, &(*rootp)->node_list, root_link) {
                switch (cnode->type) {
                case CONFIG_NODE_USER:
                        if (cnode->user.valid) {
                                launcher->uid = cnode->user.uid;
                                launcher->gid = cnode->user.gid;
                        }

                        break;
                case CONFIG_NODE_LIMIT:
                        switch (cnode->limit.name) {
                        case CONFIG_LIMIT_MAX_OUTGOING_BYTES:
                                max_outgoing_bytes = cnode->limit.value;
                                break;
                        case CONFIG_LIMIT_MAX_OUTGOING_UNIX_FDS:
                                max_outgoing_unix_fds = cnode->limit.value;
                                break;
                        case CONFIG_LIMIT_MAX_CONNECTIONS_PER_USER:
                                max_connections_per_user = cnode->limit.value;
                                break;
                        case CONFIG_LIMIT_MAX_MATCH_RULES_PER_CONNECTION:
                                max_match_rules_per_connection = cnode->limit.value;
                                break;
                        }

                        break;
                case CONFIG_NODE_POLICY:
                        if (cnode->policy.context == CONFIG_POLICY_AT_CONSOLE)
                                at_console = true;

                        break;
                default:
                        /* ignored */
                        break;
                }
        }

        /* Convert the per-connection limits into per-user limits. */
        launcher->max_bytes = util_umul64_saturating(max_connections_per_user, max_outgoing_bytes);
        launcher->max_fds = util_umul64_saturating(max_connections_per_user, max_outgoing_unix_fds);
        launcher->max_matches = util_umul64_saturating(max_connections_per_user, max_match_rules_per_connection);

        /* Remember if our at_console compat logic is needed */
        launcher->at_console = at_console;

        return 0;
}

static int launcher_load_policy(Launcher *launcher, ConfigRoot *root, Policy *policy) {
        int r;

        r = policy_import(policy, root);
        if (r)
                return error_fold(r);

        policy_optimize(policy);

        return 0;
}

static int launcher_add_listener(Launcher *launcher, Policy *policy, uint32_t *system_console_users, size_t n_system_console_users) {
        _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        r = sd_bus_message_new_method_call(launcher->bus_controller,
                                           &m,
                                           NULL,
                                           "/org/bus1/DBus/Broker",
                                           "org.bus1.DBus.Broker",
                                           "AddListener");
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_append(m, "oh",
                                  "/org/bus1/DBus/Listener/0",
                                  launcher->fd_listen);
        if (r < 0)
                return error_origin(r);

        r = policy_export(policy, m, system_console_users, n_system_console_users);
        if (r)
                return error_fold(r);

        r = sd_bus_call(launcher->bus_controller, m, 0, NULL, NULL);
        if (r < 0)
                return error_origin(r);

        return 0;
}

static int launcher_add_metrics(Launcher *launcher) {
        _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        if (launcher->fd_metrics < 0)
                return 0;

        r = sd_bus_message_new_method_call(launcher->bus_controller,
                                           &m,
                                           NULL,
                                           "/org/bus1/DBus/Broker",
                                           "org.bus1.DBus.Broker",
                                           "AddMetrics");
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_append(m, "oh",
                                  "/org/bus1/DBus/Metrics/0",
                                  launcher->fd_metrics);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_call(launcher->bus_controller, m, 0, NULL, NULL);
        if (r < 0)
                return error_origin(r);

        return 0;
}

static int launcher_set_policy(Launcher *launcher, Policy *policy, uint32_t *system_console_users, size_t n_system_console_users) {
        _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        r = sd_bus_message_new_method_call(launcher->bus_controller,
                                           &m,
                                           NULL,
                                           "/org/bus1/DBus/Listener/0",
                                           "org.bus1.DBus.Listener",
                                           "SetPolicy");
        if (r < 0)
                return error_origin(r);

        r = policy_export(policy, m, system_console_users, n_system_console_users);
        if (r)
                return error_fold(r);

        r = sd_bus_call(launcher->bus_controller, m, 0, NULL, NULL);
        if (r < 0)
                return error_origin(r);

        return 0;
}

static int launcher_apparmor_apply(unsigned int *apparmor_mode) {
        bool enabled, supported;
        int r;

        if (*apparmor_mode == CONFIG_APPARMOR_DISABLED)
                return 0;

        r = bus_apparmor_is_enabled(&enabled);
        if (r)
                return error_fold(r);

        r = bus_apparmor_dbus_supported(&supported);
        if (r)
                return error_fold(r);

        if (*apparmor_mode == CONFIG_APPARMOR_ENABLED) {
                if (enabled && !supported) {
                        fprintf(stderr, "Kernel is missing AppArmor DBus support.\n");
                        *apparmor_mode = CONFIG_APPARMOR_DISABLED;
                } else if (!enabled) {
                        *apparmor_mode = CONFIG_APPARMOR_DISABLED;
                }
        } else if (*apparmor_mode == CONFIG_APPARMOR_REQUIRED) {
                if (enabled && supported)
                        *apparmor_mode = CONFIG_APPARMOR_ENABLED;
                else
                        fprintf(stderr, "AppArmor required, but not supported. Exiting.\n");
        }

        return 0;
}


static int launcher_reload_config(Launcher *launcher) {
        _c_cleanup_(config_root_freep) ConfigRoot *root = NULL;
        _c_cleanup_(policy_deinit) Policy policy = POLICY_INIT(policy);
        _c_cleanup_(nss_cache_deinit) NSSCache nss_cache = NSS_CACHE_INIT;
        _c_cleanup_(c_freep) uint32_t *system_console_users = NULL;
        size_t n_system_console_users = 0;
        Service *service;
        int r, res;

        r = sd_notifyf(/* unset_environment = */ false,
                       "RELOADING=1\n"
                       "MONOTONIC_USEC=%" NSEC_PRI,
                       nsec_to_usec(nsec_now(CLOCK_MONOTONIC)));
        if (r < 0)
                return error_origin(r);

        c_rbtree_for_each_entry(service, &launcher->services, rb)
                service->reload_tag = false;

        r = nss_cache_populate(&nss_cache);
        if (r)
                goto out;

        r = launcher_parse_config(launcher, &root, &nss_cache);
        if (r)
                goto out;

        if (launcher->at_console) {
                r = nss_cache_resolve_system_console_users(&nss_cache,
                                                           &system_console_users,
                                                           &n_system_console_users);
                if (r)
                        return error_trace(r);
        }

        r = launcher_load_services(launcher, root, &nss_cache);
        if (r)
                goto out;

        r = launcher_load_policy(launcher, root, &policy);
        if (r)
                goto out;

        r = launcher_apparmor_apply(&policy.apparmor_mode);
        if (r < 0)
                return error_fold(r);
        if (policy.apparmor_mode == CONFIG_APPARMOR_REQUIRED) {
                r = sd_event_exit(launcher->event, 0);
                if (r < 0)
                        return error_fold(r);
                return 0;
        }

        r = launcher_remove_services(launcher);
        if (r)
                goto out;

        r = launcher_set_policy(launcher, &policy, system_console_users, n_system_console_users);
        if (r)
                goto out;

        r = launcher_add_services(launcher);
        if (r)
                goto out;

out:
        res = sd_notify(false, "READY=1");
        if (res < 0)
                return error_origin(res);

        return error_trace(r);
}

static int launcher_connect(Launcher *launcher) {
        int r;

        c_assert(!launcher->bus_regular);

        if (launcher->user_scope) {
                r = sd_bus_open_user(&launcher->bus_regular);
                if (r < 0)
                        return error_origin(r);
        } else {
                r = sd_bus_open_system(&launcher->bus_regular);
                if (r < 0)
                        return error_origin(r);
        }

        return 0;
}

static int launcher_subscribe(Launcher *launcher) {
        int r;

        /*
         * The systemd APIs only ever send signals if there is at least one
         * subscriber. On the system-bus, the systemd tools themselves already
         * subscribe, so the feature is a no-op. However, on the session bus
         * this is not always the case. Regardless, we just properly subscribe
         * in all circumstances, since we require unit state-change
         * notifications.
         */

        r = sd_bus_call_method_async(
                launcher->bus_regular,
                NULL,
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "Subscribe",
                NULL,
                NULL,
                ""
        );
        if (r < 0)
                return error_origin(r);

        return 0;
}

static int bus_method_reload_config(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Launcher *launcher = userdata;
        int r;

        r = launcher_reload_config(launcher);
        if (r) {
                if (r == LAUNCHER_E_INVALID_CONFIG)
                        return sd_bus_reply_method_errorf(message, "org.bus1.DBus.Controller.Error.InvalidConfig", "Invalid configuration. Reload ignored.");
                else
                        return error_fold(r);
        }

        return sd_bus_reply_method_return(message, NULL);
}

const sd_bus_vtable launcher_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_METHOD("ReloadConfig", NULL, NULL, bus_method_reload_config, 0),

        SD_BUS_VTABLE_END
};

int launcher_run(Launcher *launcher) {
        _c_cleanup_(config_root_freep) ConfigRoot *root = NULL;
        _c_cleanup_(policy_deinit) Policy policy = POLICY_INIT(policy);
        _c_cleanup_(nss_cache_deinit) NSSCache nss_cache = NSS_CACHE_INIT;
        _c_cleanup_(c_freep) uint32_t *system_console_users = NULL;
        size_t n_system_console_users = 0;
        int r, controller[2];

        r = nss_cache_populate(&nss_cache);
        if (r)
                return error_fold(r);

        r = launcher_parse_config(launcher, &root, &nss_cache);
        if (r)
                return error_trace(r);

        if (launcher->at_console) {
                r = nss_cache_resolve_system_console_users(&nss_cache,
                                                           &system_console_users,
                                                           &n_system_console_users);
                if (r)
                        return error_trace(r);
        }

        r = launcher_load_services(launcher, root, &nss_cache);
        if (r)
                return error_trace(r);

        r = sd_notify(false, "READY=1");
        if (r < 0)
                return error_origin(r);

        r = launcher_load_policy(launcher, root, &policy);
        if (r)
                return error_trace(r);

        r = launcher_apparmor_apply(&policy.apparmor_mode);
        if (r < 0)
                return error_fold(r);
        if (policy.apparmor_mode == CONFIG_APPARMOR_REQUIRED)
                return 0;

        c_assert(launcher->fd_listen >= 0);

        r = socketpair(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, controller);
        if (r < 0)
                return error_origin(-errno);

        /* consumes FD controller[0] */
        r = sd_bus_set_fd(launcher->bus_controller, controller[0], controller[0]);
        if (r < 0) {
                close(controller[0]);
                close(controller[1]);
                return error_origin(r);
        }

        /* consumes FD controller[1] */
        r = launcher_fork(launcher, controller[1]);
        if (r) {
                close(controller[1]);
                return error_trace(r);
        }

        r = sd_bus_add_object_vtable(launcher->bus_controller, NULL, "/org/bus1/DBus/Controller", "org.bus1.DBus.Controller", launcher_vtable, launcher);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_add_filter(launcher->bus_controller, NULL, launcher_on_message, launcher);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_start(launcher->bus_controller);
        if (r < 0)
                return error_origin(r);

        r = launcher_add_services(launcher);
        if (r)
                return error_trace(r);

        r = launcher_add_listener(launcher, &policy, system_console_users, n_system_console_users);
        if (r)
                return error_trace(r);

        r = launcher_add_metrics(launcher);
        if (r)
                return error_trace(r);

        r = launcher_connect(launcher);
        if (r)
                return error_trace(r);

        r = sd_bus_attach_event(launcher->bus_controller, launcher->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_attach_event(launcher->bus_regular, launcher->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return error_origin(r);

        r = launcher_subscribe(launcher);
        if (r)
                return error_trace(r);

        if (launcher->uid != (uint32_t)-1) {
                r = util_drop_permissions(launcher->uid, launcher->gid);
                if (r)
                        return error_fold(r);
        }

        log_append_here(&launcher->log, LOG_INFO, 0, NULL);
        r = log_commitf(&launcher->log, "Ready\n");
        if (r)
                return error_fold(r);

        r = sd_event_loop(launcher->event);
        if (r < 0)
                return error_origin(r);
        else if (r > 0)
                return error_fold(r);

        return 0;
}
