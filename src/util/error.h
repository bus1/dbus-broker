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
#define error_origin(r)         (_c_likely_(r == 0) ? 0 : error_slow_origin(r, __func__, __FILE__, __LINE__))

/**
 * error_fold() - XXX
 */
#define error_fold(r)           (_c_likely_(r >= 0) ? error_origin(r) : error_slow_fold(r, __func__, __FILE__, __LINE__))

/**
 * error_trace() - XXX
 */
#define error_trace(r)          (_c_likely_(r >= 0) ? r : error_slow_fold(r, __func__, __FILE__, __LINE__))
