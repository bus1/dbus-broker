#pragma once

/*
 * D-Bus Broker Main Entry
 */

#include <c-macro.h>
#include <stdlib.h>

enum {
        _MAIN_SUCCESS,
        MAIN_EXIT,
        MAIN_FAILED,
};

extern int main_arg_controller;
extern bool main_arg_verbose;
