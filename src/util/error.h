#pragma once

/*
 * Error Handling
 */

#include <c-macro.h>
#include <stdlib.h>

int error_slow_fold(int r);

/**
 * error_fold() - Fold error code
 * @r:          error code to fold
 *
 * XXX
 *
 * Return: Folded negative error code.
 */
static inline int error_fold(int r) {
        return _c_likely_(r <= 0) ? r : error_slow_fold(r);
}
