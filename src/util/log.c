/*
 * Log Context
 *
 * The log context provides an infrastructure to send log-messages to the
 * system log daemon. Both structured and unstructured logging is supported.
 * Depending on which logging daemon is used, a compatible mode is selected.
 *
 * Right now, these modes are supported:
 *
 *     * stderr: Stream-based, unstructured logging to the inherited stderr
 *               channel.
 *               This is the default.
 *
 *     * journal: Datagram-based, structured logging to the journal. Other
 *                journal-API-compatible daemons can be used as well. No
 *                journal-specific API besides the datagram socket is used.
 *
 * The logging API provides a staging buffer to assemble structured log
 * messages. Once a message is complete, it must be committed, which will send
 * it out and prepare the context for the next message.
 *
 * The log_*append*() APIs append log fields to the staging buffer. They can
 * be used consecutively. Convenience wrappers are provided to add the most
 * common structured fields. The staging buffer should only be used for
 * structured logging. The main log-message is not part of it.
 *
 * Once a log message is completed, the log_*commit*() APIs commit the log
 * message. At the time of commit, the caller must provide the actual main log
 * message, which appears in the logs. Multiple convenience wrappers are
 * provided to allow formatted messages.
 * Note that depending on the backend, the structured fields might be
 * discarded. Not all logging systems support them.
 *
 * By default, logging is synchronous and blocking. That is, no data is
 * buffered in the log-context once a message is committed. All data is written
 * into the socket in a blocking manner. The data will be buffered in the
 * kernel socket queues, of course.
 * This mode is not always desirable. In particular, we allow logging on behalf
 * of peers in dbus-broker. This means, whenever a peer screws up, we often
 * have more information than the peer itself, so we want to log data on behalf
 * of them. This, however, makes us susceptible to DoS attacks. Hence, we
 * support a lossy mode. If a log context is set to lossy mode, messages will
 * be submitted to the socket in non-blocking mode. Once the kernel buffers run
 * full, we submit a single, one-time, synchronous warning to the log, and from
 * then on will discard log messages, if the kernel buffers are full.
 *
 * Lastly, please note that each log context must not be used from multiple
 * threads. Use separate contexts for each thread. Also be aware that stream
 * sockets do not have atomic writes, so you might need separate sockets.
 *
 * In case of structured logging, we support:
 *
 *     * MESSAGE: The string-formatted log message.
 *
 *     * CODE_FILE: Source-code file where the logging call originated. Usually
 *                  corresponds to the expanded __FILE__ constant.
 *
 *     * CODE_LINE: Source-code line number where the logging call originated.
 *                  Usually corresponds to the expanded __LINE__ constant.
 *
 *     * CODE_FUNC: Source-code function where the logging call originated.
 *                  Usually correspoends to the expanded __func__ constant.
 *
 *     * PRIORITY: Syslog-compatible log priority formatted as integer. See
 *                 syslog.h for details on LOG_EMERG..LOG_DEBUG.
 *
 *     * SYSLOG_FACILITY: Syslog facility formatted as integer.
 *
 *     * SYSLOG_IDENTIFIER: Name of the program where the log message
 *                          originated.
 *
 *     * ERRNO: Errno-style error code that caused the log-message (or 0 if
 *              none).
 *
 *     * DBUS_BROKER_LOG_DROPPED: Number of total log messages that were
 *                                dropped so far due to excessive logging.
 */

#include <c-stdaux.h>
#include <linux/sockios.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include "util/error.h"
#include "util/log.h"
#include "util/misc.h"

/* lets retrict log records to 2MiB */
#define LOG_SIZE_MAX (2ULL * 1024ULL * 1024ULL)

/* warning that is sent on first dropped log message */
#define LOG_WARNING_DROPPED "<3>Log messages dropped\n"

/**
 * log_init() - initialize log context
 * @log:                log context to initialize
 *
 * This initializes the log-context @log with no output configured. Hence, all
 * log messages will be silently dropped.
 */
void log_init(Log *log) {
        *log = (Log)LOG_NULL;
        log->mode = LOG_MODE_NONE;
        log->consumed = false;
        log->map_size = LOG_SIZE_MAX;
        /* NOTE: Other log_init_*() variants override these. */
}

/**
 * log_init_stderr() - initialize log context
 * @log:                log context to initialize
 * @stderr_fd:          stderr stream FD to use
 *
 * This initializes the log-context @log and prepares it for output to stderr
 * given its file-descriptor as @stderr_fd. Note that the file-descriptor is
 * not consumed, but ownership is retained by the caller.
 */
void log_init_stderr(Log *log, int stderr_fd) {
        c_assert(stderr_fd >= 0);

        log_init(log);
        log->log_fd = stderr_fd;
        log->mode = LOG_MODE_STDERR;
        log->consumed = false;
}

/**
 * log_init_journal() - initialize log context
 * @log:                log context to initialize
 * @journal_fd:         Datagram-FD to the journal
 *
 * This initializes the log-context @log with the journal datagram
 * socket @journal_fd to be used for log-messages.
 */
void log_init_journal(Log *log, int journal_fd) {
        c_assert(journal_fd >= 0);

        log_init(log);
        log->log_fd = journal_fd;
        log->mode = LOG_MODE_JOURNAL;
        log->consumed = false;
}

/**
 * log_init_journal_consume() - initialize log context
 * @log:                log context to initialize
 * @journal_fd:         Datagram-FD to the journal
 *
 * This initializes the log-context @log and consumes the journal datagram
 * socket @journal_fd to be used for log-messages.
 */
void log_init_journal_consume(Log *log, int journal_fd) {
        c_assert(journal_fd >= 0);

        log_init(log);
        log->log_fd = journal_fd;
        log->mode = LOG_MODE_JOURNAL;
        log->consumed = true;
}

/**
 * log_deinit() - deinitialize log context
 * @log:                log to operate on
 *
 * This deinitializes the log context @log and releases all resources. The
 * context is reset to LOG_NULL afterwards.
 *
 * Calling this on LOG_NULL is a no-op.
 */
void log_deinit(Log *log) {
        if (log->map != MAP_FAILED)
                munmap(log->map, log->map_size);
        c_close(log->mem_fd);
        if (log->consumed)
                c_close(log->log_fd);
        *log = (Log)LOG_NULL;
}

/**
 * log_get_fd() - get logging fd
 * @log:                log context to operate on
 *
 * This returns the file-descriptor used to submit log messages to. This is
 * usually the same FD that was passed to the constructor. Note that the FD is
 * still owned by the log context, so it must be treated as read-only.
 *
 * Return: Log file-descriptor in use, or -1 if none.
 */
int log_get_fd(Log *log) {
        return log->log_fd;
}

/**
 * log_set_lossy() - set lossy mode
 * @log:                log context to operate on
 * @lossy:              lossy mode to set
 *
 * This changes the lossy-mode of the log context @log. If @lossy is false, all
 * log messages will be sent in blocking mode to the logging daemon, and
 * transmission will be reliable.
 *
 * If @lossy is true, logging will be lossy. This means, any message submitted
 * to the log context might be dropped, with the advantage of logging being
 * safe even in quotad contexts.
 *
 * Default is non-lossy mode.
 */
void log_set_lossy(Log *log, bool lossy) {
        log->lossy = lossy;
}

static bool log_alloc(Log *log) {
        _c_cleanup_(c_closep) int mem_fd = -1;
        void *p;
        int r;

        if (log->error)
                return false;
        if (log->map != MAP_FAILED)
                return true;

        c_assert(!log->offset);

        /*
         * systemd-journald used to verify seals explicitly, and any new seal
         * showing up was refused. Hence, we cannot set MFD_NOEXEC but have to
         * use MFD_EXEC.
         */
        mem_fd = misc_memfd(
                "dbus-broker-log",
                MISC_MFD_CLOEXEC | MISC_MFD_ALLOW_SEALING | MISC_MFD_EXEC,
                0
        );
        if (mem_fd < 0) {
                /*
                 * In case of EINVAL, memfd_create() is not available. We then
                 * use normal anonymous memory as backing.
                 */
                if (mem_fd != -EINVAL) {
                        log->error = error_fold(mem_fd);
                        return false;
                }
                mem_fd = -1;

                p = mmap(NULL, log->map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (p == MAP_FAILED) {
                        log->error = error_origin(-errno);
                        return false;
                }
        } else {
                r = ftruncate(mem_fd, log->map_size);
                if (r < 0) {
                        log->error = error_origin(-errno);
                        return false;
                }

                p = mmap(NULL, log->map_size, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, 0);
                if (p == MAP_FAILED) {
                        log->error = error_origin(-errno);
                        return false;
                }
        }

        log->mem_fd = mem_fd;
        log->map = p;
        mem_fd = -1;
        return true;
}

static int log_fd_send(int destination_fd, int payload_fd) {
        union {
                char buffer[CMSG_SPACE(sizeof(int))];
                struct cmsghdr cmsg;
        } control;
        struct msghdr msg;
        ssize_t l;

        control.cmsg.cmsg_len = CMSG_LEN(sizeof(int));
        control.cmsg.cmsg_level = SOL_SOCKET;
        control.cmsg.cmsg_type = SCM_RIGHTS;
        c_memcpy(CMSG_DATA(&control.cmsg), &payload_fd, sizeof(int));

        msg = (struct msghdr){
                .msg_control = &control.cmsg,
                .msg_controllen = control.cmsg.cmsg_len,
        };

        l = sendmsg(destination_fd, &msg, MSG_NOSIGNAL);
        if (l)
                return (l < 0) ? error_origin(-errno) : error_origin(-ENOTRECOVERABLE);

        return 0;
}

static int log_loop_send(int destination_fd, const void *blob, size_t n_blob) {
        ssize_t l;

        while (n_blob > 0) {
                l = send(destination_fd, blob, n_blob, MSG_NOSIGNAL);
                if (l < 0)
                        return error_origin(-errno);
                else if (l == 0 || l > (ssize_t)n_blob)
                        return error_origin(-ENOTRECOVERABLE);

                blob += l;
                n_blob -= l;
        }

        return 0;
}

static int log_stream_send(Log *log) {
        bool log_warn = false;
        const void *blob = log->map;
        size_t n_blob = log->offset;
        ssize_t l;
        int r, v;

        /*
         * Stream sockets are a bit nasty since they lack atomic writes. Hence,
         * whenever we end up with a short-write in lossy mode, we need to
         * finish the current message in synchronous mode, and then log a
         * warning. Otherwise, we end up with a garbled output.
         *
         * Now, we remember whenever we dropped message. From then on, we only
         * ever write messages if the output buffer of our socket is empty.
         * Preferably, we would check that the message fits into the kernel
         * buffer, but there is no way to do that. Hence, we simply require the
         * buffer to be empty.
         * This guarantees the operation will be non-blocking, as long as
         * suitably sized log messages are used.
         */

        if (log->lossy) {
                if (log->n_dropped) {
                        r = ioctl(log->log_fd, SIOCOUTQ, &v);
                        if (r < 0) {
                                return error_origin(-errno);
                        } else if (v) {
                                ++log->n_dropped;
                                return 0;
                        }
                }

                l = send(log->log_fd, blob, n_blob, MSG_NOSIGNAL | MSG_DONTWAIT);
                if (l >= (ssize_t)n_blob) {
                        return 0;
                } else if (l < 0) {
                        if (errno != EAGAIN)
                                return error_origin(-errno);

                        l = 0;
                }

                blob += l;
                n_blob -= l;

                if (!log->n_dropped++)
                        log_warn = true;
        }

        r = log_loop_send(log->log_fd, blob, n_blob);
        if (r)
                return error_trace(r);

        if (log_warn) {
                r = log_loop_send(log->log_fd,
                                  LOG_WARNING_DROPPED,
                                  strlen(LOG_WARNING_DROPPED));
                if (r)
                        return error_trace(r);
        }

        return 0;
}

static int log_journal_send(Log *log) {
        _c_cleanup_(c_closep) int mfd = -1;
        ssize_t l;
        int r;

        l = send(log->log_fd,
                 log->map,
                 log->offset,
                 log->lossy ?
                         MSG_NOSIGNAL | MSG_DONTWAIT :
                         MSG_NOSIGNAL);
        if (l == (ssize_t)log->offset) {
                return 0;
        } else if (l >= 0) {
                /*
                 * Partially sent? This should not happen. We require datagram
                 * sockets that send atomically and never truncate unasked.
                 * Tell our caller about this, so they can deal with it.
                 */
                return LOG_E_TRUNCATED;
        } else if (errno == EAGAIN) {
                goto out_drop;
        } else if (errno != EMSGSIZE) {
                return error_origin(-errno);
        }

        /*
         * We could not send the message as a single datagram. Instead, we now
         * seal the memfd and send it as payload of an empty datagram. The
         * journal can deal with this and treats the memfd content as log
         * message.
         *
         * Note that this means there is an inflight memfd pending on the
         * journal that is accounted on us as long as the journal did not read
         * it, yet. Hence, clients should never be able to trigger such log
         * messages, otherwise they could exploit this and make us exceed our
         * inflight FD limit.
         *
         * We could send a pipe-fd as barrier and block on it. Hence, we would
         * be able to know at which point our messages are no longer inflight.
         * However, this would be a quite expensive code-path, making this
         * entire path completely useless.
         *
         * Long story short: Do not write excessive log messages, unless
         *                   debugging is enabled in some way.
         */

        if (log->lossy || log->mem_fd < 0)
                goto out_drop;

        mfd = log->mem_fd;
        log->mem_fd = -1;
        munmap(log->map, log->map_size);
        log->map = MAP_FAILED;

        r = ftruncate(mfd, log->offset);
        if (r < 0)
                return error_origin(-errno);

        r = misc_memfd_add_seals(
                mfd,
                MISC_F_SEAL_SEAL | MISC_F_SEAL_SHRINK |
                MISC_F_SEAL_GROW | MISC_F_SEAL_WRITE
        );
        if (r < 0)
                return error_origin(-errno);

        r = log_fd_send(log->log_fd, mfd);
        if (r < 0)
                return error_trace(r);

        return 0;

out_drop:
        if (!log->n_dropped++) {
                l = send(log->log_fd,
                         LOG_WARNING_DROPPED,
                         strlen(LOG_WARNING_DROPPED),
                         MSG_NOSIGNAL);
                if (l < 0)
                        return error_origin(-errno);
        }

        return 0;
}

static int log_commit_stderr(Log *log, const char *format, va_list args) {
        int r;

        /*
         * Lets format the log-message in our staging buffer and print it out.
         * Note that we don't support structured logging. Hence, we simply
         * ignore anything that is in the staging buffer and instead just print
         * our message.
         * Sadly, `%r' is still no standardized format specifier, so we need
         * the separate calls into log_append() here.
         */

        log->offset = 0;

        if (format && *format) {
                log_appendf(log, "<%d>", log->level ?: LOG_INFO);
                log_vappendf(log, format, args);
                log_appends(log, "\n");
        }

        if (log->error)
                r = error_trace(log->error);
        else if (log->offset)
                r = log_stream_send(log);
        else
                r = 0;

        return error_trace(r);
}

static int log_commit_journal(Log *log, const char *format, va_list args) {
        int r;

        /*
         * Lets append `MESSAGE=%s\n' to the staging buffer and then submit the
         * entire blob to the journal. We support passing it as sealed memfd in
         * case it exceeds the datagram maximum.
         * Sadly, `%r' is still no standardized format specifier, so we need
         * the separate calls into log_append() here.
         */

        if (format && *format) {
                log_appends(log, "MESSAGE=");
                log_vappendf(log, format, args);
                log_appends(log, "\n");
        }

        if (log->error)
                r = error_trace(log->error);
        else if (log->offset)
                r = log_journal_send(log);
        else
                r = 0;

        return error_trace(r);
}

/**
 * log_vcommitf() - commit log message
 * @log:                log to operate on
 * @format:             log message format string
 * @args:               arguments for format string
 *
 * This formats a log message and commits it. @format is used as format string
 * for the log message, with @args filled in at the respective places.
 *
 * Any previously appended log fields are amended to the log message and
 * submitted with it. In case the log output does not support structured
 * logging, they will be lost, and only the message itself is submitted.
 *
 * If the pending log message is poisoned, or if it could not be submitted,
 * an error will be returned. After this call returns (regardless whether it
 * failed or not), the log context is ready to take the next log message.
 *
 * Return: 0 on success, LOG_E_TRUNCATED if the message was truncated by the
 *         log channel, LOG_E_OVERSIZED if the message exceeded the maximum
 *         size, and negative error code on failure.
 */
int log_vcommitf(Log *log, const char *format, va_list args) {
        int r;

        switch (log->mode) {
        case LOG_MODE_NONE:
                r = error_trace(log->error);
                break;
        case LOG_MODE_STDERR:
                r = log_commit_stderr(log, format, args);
                break;
        case LOG_MODE_JOURNAL:
                r = log_commit_journal(log, format, args);
                break;
        default:
                r = error_origin(-ENOTRECOVERABLE);
                break;
        }

        log->error = 0;
        log->level = 0;
        log->offset = 0;

        return r;
}

/**
 * log_append() - append structured fields
 * @log:                log context to operate on
 * @data:               data to append
 * @n_data:             length of data to append
 *
 * This appends the given data to the structured log staging buffer. Note that
 * you can encode binary data, as long as you follow the protocol of journald.
 * But you're recommended to just insert newline separated ascii key-value
 * pairs.
 */
void log_append(Log *log, const void *data, size_t n_data) {
        if (!n_data || !log_alloc(log))
                return;

        if (log->map_size - log->offset < n_data) {
                log->error = LOG_E_TRUNCATED;
                return;
        }

        c_memcpy(log->map + log->offset, data, n_data);
        log->offset += n_data;
}

/**
 * log_vappendf() - append structured fields
 * @log:                log context to operate on
 * @format:             formatted data to append
 * @args:               arguments to fill in via format string
 *
 * This is similar to log_append(), but uses printf-style formatting rather
 * than copying a blob verbatim.
 */
void log_vappendf(Log *log, const char *format, va_list args) {
        int r;

        if (!log_alloc(log))
                return;

        r = vsnprintf(log->map + log->offset,
                      log->map_size - log->offset,
                      format,
                      args);
        if (r < 0 || r >= (ssize_t)(log->map_size - log->offset)) {
                log->error = LOG_E_TRUNCATED;
                return;
        }

        log->offset += r;
}

/**
 * log_append_common() - append common log entries
 * @log:                log to operate on
 * @level:              syslog level indicator
 * @error:              errno-style error code
 * @id:                 log message ID, or NULL
 * @prov:               log provenance
 *
 * This appends known, common fields to the current log message. This should be
 * called for every log message.
 */
void log_append_common(Log *log,
                       int level,
                       int error,
                       const char *id,
                       LogProvenance prov) {
        /*
         * Use LOG_DAEMON if the log-facility is 0. Most people don't specify
         * any facility, so lets just apply a default. Note that 0 actually
         * means 'kernel' as facility, but we just treat it as unspecified
         * here, since no-one should specify 'kernel' from user-space.
         */
        level = LOG_MAKEPRI(LOG_FAC(level) ?: LOG_DAEMON,
                            LOG_PRI(level) ?: LOG_INFO);

        /*
         * Always remember the level of the current log message. In case the
         * journal is not used, we can still prefix the syslog / stderr
         * messages with it.
         */
        log->level = level;

        /*
         * If we have a journal-entry (or successfully allocated one), simply
         * append the known, common fields.
         */
        if (log_alloc(log)) {
                log_appendf(log,
                            "PRIORITY=%i\n"
                            "SYSLOG_FACILITY=%i\n"
                            "SYSLOG_IDENTIFIER=%s\n"
                            "ERRNO=%i\n"
                            "CODE_FILE=%s\n"
                            "CODE_LINE=%i\n"
                            "CODE_FUNC=%s\n"
                            "DBUS_BROKER_LOG_DROPPED=%"PRIu64"\n",
                            LOG_PRI(level),
                            LOG_FAC(level),
                            program_invocation_short_name,
                            error,
                            prov.file ?: "<unknown>",
                            prov.line,
                            prov.func ?: "<unknown>",
                            log->n_dropped);
                if (id)
                        log_appendf(log, "MESSAGE_ID=%s\n", id);
        }
}
