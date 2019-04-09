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
