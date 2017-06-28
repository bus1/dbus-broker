#pragma once

/*
 * D-Bus Policy Parser
 */

#include <c-list.h>
#include <c-rbtree.h>
#include <stdlib.h>

enum {
        _POLICY_PARSER_E_SUCCESS,

        POLICY_PARSER_E_INVALID_XML,
        POLICY_PARSER_E_CIRCULAR_INCLUDE,
};

typedef struct PolicyParser PolicyParser;
typedef struct PolicyRegistry PolicyRegistry;

int policy_parser_parse_file(PolicyRegistry *registry, const char *filename, PolicyParser *parent);
