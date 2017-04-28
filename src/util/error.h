#pragma once

/*
 * Error Handling
 */

#include <c-macro.h>
#include <stdlib.h>

int error_slow_origin(int r, const char *function, const char *file, int line);
int error_slow_fold(int r, const char *function, const char *file, int line);

/**
 * error_origin() - XXX
 */
#define error_origin(r) C_CC_MACRO1(ERROR_ORIGIN, (r))
#define ERROR_ORIGIN(r) (_c_likely_(r == 0) ? 0 : error_slow_origin(r, __func__, __FILE__, __LINE__))

/**
 * error_fold() - XXX
 */
#define error_fold(r) C_CC_MACRO1(ERROR_FOLD, (r))
#define ERROR_FOLD(r) (_c_likely_(r >= 0) ? ERROR_ORIGIN(r) : error_slow_fold(r, __func__, __FILE__, __LINE__))

/**
 * error_trace() - XXX
 */
#define error_trace(r) C_CC_MACRO1(ERROR_TRACE, (r))
#define ERROR_TRACE(r) (_c_likely_(r >= 0) ? r : error_slow_fold(r, __func__, __FILE__, __LINE__))
