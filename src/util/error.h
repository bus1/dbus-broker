#pragma once

/*
 * Error Handling
 *
 * All our API calls return integers to signal errors or success. Negative
 * error-codes are fatal errors that the caller should forward unchanged.
 * Positive error-codes are API errors that have documented behavior and must
 * be caught and handled by the caller.
 */

#include <c-stdaux.h>
#include <stdlib.h>

int error_slow_origin(int r, const char *function, const char *file, int line);
int error_slow_trace(int r, const char *function, const char *file, int line);
int error_slow_fold(int r, const char *function, const char *file, int line);

/**
 * error_origin() - fast-path of error_slow_origin()
 * @r:          error code
 *
 * This is the fast-path of error_slow_origin(). See its description for
 * details.
 *
 * Return: 0 or negative error code, depending on @r.
 */
#define error_origin(r) C_CC_MACRO1(ERROR_ORIGIN, (r))
#define ERROR_ORIGIN(r) (_c_likely_(!r) ? 0 : error_slow_origin(r, __func__, __FILE__, __LINE__))

/**
 * error_trace() - fast-path of error_slow_trace()
 * @r:          error code
 *
 * This is the fast-path of error_slow_trace(). See its description for
 * details.
 *
 * Return: @r is returned.
 */
#define error_trace(r) C_CC_MACRO1(ERROR_TRACE, (r))
#define ERROR_TRACE(r) (_c_likely_(r >= 0) ? r : error_slow_trace(r, __func__, __FILE__, __LINE__))

/**
 * error_fold() - fast-path of error_slow_fold()
 * @r:          error code
 *
 * This is the fast-path of error_slow_fold(). See its description for
 * details.
 *
 * Return: 0 or negative error code, depending on @r.
 */
#define error_fold(r) C_CC_MACRO1(ERROR_FOLD, (r))
#define ERROR_FOLD(r) (_c_likely_(!r) ? 0 : error_slow_fold(r, __func__, __FILE__, __LINE__))
