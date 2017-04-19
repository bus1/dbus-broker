/*
 * Error Handling
 */

#include <c-macro.h>
#include <stdlib.h>
#include "util/error.h"

/**
 * error_slow_fold() - Slow-path of error_fold()
 * @r:          error code to fold
 *
 * This is the slow-path of error_fold(). See its description for details. This
 * function handles the case where we actually have to fold the error code.
 *
 * Return: Folded negative error code.
 */
int error_slow_fold(int r) {
        /* XXX: hook up tracing */
        return (r <= 0) ? r : -ENOTRECOVERABLE;
}
