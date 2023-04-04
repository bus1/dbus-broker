#pragma once

/*
 * Syscall Wrappers
 *
 * The linux syscalls are usually not directly accessible from applications,
 * since most standard libraries do not provide wrapper functions. This module
 * provides direct syscall wrappers via `syscall(3)' for a set of otherwise
 * unavailable syscalls.
 */

#include <stdlib.h>
#include <sys/resource.h>
#include <sys/syscall.h>

/**
 * syscall_memfd_create() - wrapper for memfd_create(2) syscall
 * @name:       name for memfd inode
 * @flags:      memfd flags
 *
 * This is a wrapper for the memfd_create(2) syscall. Currently, no user-space
 * wrapper is exported by any libc.
 *
 * Return: New memfd file-descriptor on success, -1 on failure.
 */
static inline int syscall_memfd_create(const char *name, unsigned int flags) {
        /* Make Travis happy. */
#if defined __NR_memfd_create
        long nr = __NR_memfd_create;
#elif defined __x86_64__
        long nr = 319;
#elif defined __i386__
        long nr = 356;
#else
#  error "__NR_memfd_create is undefined"
#endif
        return (int)syscall(nr, name, flags);
}

/**
 * syscall_pidfd_open() - wrapper for pidfd_open(2) syscall
 * @pid:        pid to open
 * @flags:      pidfd flags
 *
 * This is a wrapper for the pidfd_open(2) syscall. Only a very recent version
 * of glibc (2.36) exports a wrapper for this syscall, so we provide our own
 * for compatibility with other libc implementations.
 *
 * Return: New pidfd file-descriptor on success, -1 on failure.
 */
static inline int syscall_pidfd_open(pid_t pid, unsigned int flags) {
#if defined __NR_pidfd_open
        long nr = __NR_pidfd_open;
#elif defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || defined(__arm__)
        long nr = 434;
#else
#  error "__NR_pidfd_open is undefined"
#endif
        return (int)syscall(nr, pid, flags);
}
