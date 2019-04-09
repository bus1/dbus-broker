/*
 * Error Handling
 *
 * This file implements a simple and fast error handling infrastructure. We use
 * C-style integers to signal errors via return values. That is, we use
 * negative error codes to signal fatal errors (e.g., -ENOMEM) just like the
 * linux kernel does. We use 0 to signal success, and positive error codes to
 * signal API-dependent conditions.
 *
 * Our general rule is to never catch negative error codes returned by our own
 * API. That is, we never match on -EINVAL, -EFAULT, etc., but return them
 * unchanged. We only ever match on those codes if returned by external calls.
 * Once our own calls return them, they're considered fatal, and forwarded
 * through the call-chain.
 *
 * Positive error codes, however, signal well-defined API conditions. Those
 * must be caught by the caller of the respective call. That is, those error
 * codes have clear meanings on a given function, and thus can (and must) be
 * handled by the caller. Callers must not forward those codes, since the codes
 * are only well-defined for a single function. The exception is
 * function-groups that share a set of error codes. Those might forward error
 * codes, if, and only if, they call into each other.
 *
 * In other words, our call chains will always propagate fatal errors up to the
 * application entry point. Well-defined API errors are never propagated, but
 * always caught and handled by the caller (which itself might raise its own
 * errors based on them).
 *
 * For debugging purposes, we want to be able to trace those error codes.
 * Therefore, we provide three simple macros, which are a no-op in the
 * success-path, but provide hooks in the case of errors:
 *
 *     error_origin(): This raises a new fatal error. That is, rather than
 *                     returning -ENOMEM directly on allocation failure, you
 *                     can use:
 *
 *                         return error_origin(-ENOMEM);
 *
 *                     Similarly, you can return 'errno' in case it is
 *                     unhandled:
 *
 *                         return error_origin(-errno);
 *
 *                     The default behavior of error_origin() is to print a
 *                     error trace message in case of failure.
 *
 *     error_trace(): This traces negative errors. That is, when another
 *                    function returns a negative error and you want to
 *                    propagate it, wrap it in error_trace() to tell the tracer
 *                    about the path the error took:
 *
 *                        return error_trace(r);
 *
 *                    On success or positive error codes, this is a no-op and
 *                    returns the code unchanged. That is, use it to propagate
 *                    an error of another function unchanged, in case the set
 *                    of error codes for both functions is the same.
 *
 *     error_fold(): This folds positive errors and traces fatal errors. That
 *                   is, whenever another function returns a negative *or*
 *                   positive error that you didn't handle, you can fold and
 *                   propagate them via error_fold(). This function turns
 *                   positive errors into fatal ones, and traces them. On
 *                   success, this function is a no-op:
 *
 *                       return error_fold(r);
 *
 * The combination of those three functions allows us to get nice error-traces
 * on fatal, unexpected errors. That is, imagine a syscall returns an error
 * that we did not handle, we will end up with a nice back-trace that a
 * developer can use to debug and fix this problem, like:
 *
 * ERROR manager_listen_path @ ../src/launch/main.c +234: Address already in use
 *       run @ ../src/launch/main.c +938
 *       main @ ../src/launch/main.c +983
 *
 * At the same time, we avoid fatal exceptions that abort the application
 * unexpectedly. That is, we can still gracefully shutdown and release
 * resources that are not auto-managed.
 * We still recommend fatal exceptions (e.g., assertions) for non-recoverable
 * errors (like a detected memory corruption). However, any error that can be
 * gracefully handled will be suitable for this.
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include "util/error.h"

/**
 * error_slow_origin() - raise an error
 * @r:          error code
 * @function:   calling function
 * @file:       source file
 * @line:       source line
 *
 * Instead of returning a literal error code, wrap the literal in this function
 * to integrate with the tracing infrastructure. That is, whenever you want to
 * raise a fatal error (negative error code), pass it through error_origin().
 *
 * This function will detect 3 cases:
 *
 *  1) The error code is 0. In this case the function is a no-op and 0 is
 *     returned. The fast-path macro error_origin() shortcuts this.
 *
 *  2) The error code is negative. In this case the function will start a new
 *     error trace and return the error code unchanged.
 *
 *  3) The error code is positive. In this case the function will start a new
 *     error trace, but return -ENOTRECOVERABLE.
 *
 * The error-handling is up to the application that links to this code. This
 * macro just provides the hook for the application to start an error trace.
 *
 * Right now, the default behavior is to print a suitable message to stderr.
 *
 * Return: 0 or negative error code, depending on @r.
 */
int error_slow_origin(int r, const char *function, const char *file, int line) {
        int tmp_errno;

        if (r < 0) {
                tmp_errno = errno;
                errno = -r;
                fprintf(stderr, "ERROR %s @ %s +%d: %m\n", function, file, line);
                errno = tmp_errno;
        } else if (r > 0) {
                fprintf(stderr, "ERROR %s @ %s +%d: Return code %d\n", function, file, line, r);
                r = -ENOTRECOVERABLE;
        }

        return r;
}

/**
 * error_slow_trace() - trace a fatal error
 * @r:          error code
 * @function:   calling function
 * @file:       source file
 * @line:       source line
 *
 * Whenever you want to forward an error code unchanged from another function
 * that shares your set of error codes, wrap it in error_trace() to let the
 * tracer know about it. In case @r is 0, or a positive error code, this
 * function is a no-op.
 *
 * In case @r is negative, this function returns @r unchanged, but calls the
 * trace-hook.
 *
 * Right now, the default behavior is to print a suitable message to stderr.
 *
 * Return: @r is returned.
 */
int error_slow_trace(int r, const char *function, const char *file, int line) {
        if (r < 0)
                fprintf(stderr, "      %s @ %s +%d\n", function, file, line);

        return r;
}

/**
 * error_slow_fold() - fold non-fatal errors
 * @r:          error code
 * @function:   calling function
 * @file:       source file
 * @line:       source line
 *
 * This folds any non-fatal error into a fatal one. That is, whenever a
 * function you called failed, but you did not handle the error code (for
 * whatever reason), call error_fold() to let the tracer know and turn it into
 * a fatal error.
 *
 * If @r is 0, this is a no-op. This calls into error_trace() if @r is
 * negative, and error_origin() if @r is positive.
 *
 * Return: 0 or negative error code, depending on @r.
 */
int error_slow_fold(int r, const char *function, const char *file, int line) {
        if (r < 0)
                r = error_slow_trace(r, function, file, line);
        else if (r > 0)
                r = error_slow_origin(r, function, file, line);

        return r;
}
