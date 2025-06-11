#pragma once

/*
 * Log Context
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syslog.h>

typedef struct Log Log;
typedef struct LogProvenance LogProvenance;

enum {
        _LOG_E_SUCCESS,

        LOG_E_OVERSIZED,
        LOG_E_TRUNCATED,
};

enum {
        LOG_MODE_NONE,
        LOG_MODE_STDERR,
        LOG_MODE_JOURNAL,
};

struct Log {
        int log_fd;
        unsigned short mode;
        bool consumed : 1;
        bool lossy : 1;
        uint64_t n_dropped;

        int error;
        int level;

        int mem_fd;
        void *map;
        size_t map_size;
        size_t offset;
};

struct LogProvenance {
        const char *file;
        int line;
        const char *func;
};

#define LOG_NULL {                                                              \
                .log_fd = -1,                                                   \
                .mem_fd = -1,                                                   \
                .map = MAP_FAILED,                                              \
        }

#define LOG_PROVENANCE_HERE ((LogProvenance){                                   \
                .file = __FILE__,                                               \
                .line = __LINE__,                                               \
                .func = __func__,                                               \
        })

/* log context */

void log_init(Log *log);
void log_init_stderr(Log *log, int stderr_fd);
void log_init_journal(Log *log, int journal_fd);
void log_init_journal_consume(Log *log, int journal_fd);
void log_deinit(Log *log);

int log_get_fd(Log *log);
void log_set_lossy(Log *log, bool lossy);

int log_vcommitf(Log *log, const char *format, va_list args);

void log_append(Log *log, const void *data, size_t n_data);
void log_vappendf(Log *log, const char *format, va_list args);
void log_append_common(Log *log,
                       int level,
                       int error,
                       const char *id,
                       LogProvenance prov);

/* inline helpers */

static inline int log_commitf(Log *log, const char *format, ...) {
        va_list args;
        int r;

        va_start(args, format);
        r = log_vcommitf(log, format, args);
        va_end(args);

        return r;
}

static inline int log_commit_silent(Log *log) {
        return log_commitf(log, NULL);
}

static inline void log_appends(Log *log, const char *string) {
        return log_append(log, string, strlen(string));
}

static inline void log_appendf(Log *log, const char *format, ...) {
        va_list args;

        va_start(args, format);
        log_vappendf(log, format, args);
        va_end(args);
}

#define log_append_here(_log, _level, _r, _id) \
        log_append_common((_log), (_level), (_r), (_id), LOG_PROVENANCE_HERE)
