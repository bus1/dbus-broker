#pragma once

/*
 * D-Bus Policy Parser
 */

#include <c-list.h>
#include <c-rbtree.h>
#include <stdlib.h>
#include "policy.h"

enum {
        _POLICY_PARSER_E_SUCCESS,

        POLICY_PARSER_E_INVALID_XML,
        POLICY_PARSER_E_CIRCULAR_INCLUDE,
};

typedef struct PolicyParser PolicyParser;
typedef struct PolicyParserRegistry PolicyParserRegistry;

struct PolicyParserRegistry {
        Policy default_policy;
        PolicyRegistry registry;
        Policy console_policy;
        Policy mandatory_policy;
};

#define POLICY_PARSER_REGISTRY_NULL(_x) {                               \
                .default_policy = POLICY_INIT((_x).default_policy),     \
                .registry = POLICY_REGISTRY_NULL((_x).registry),        \
                .console_policy = POLICY_INIT((_x).console_policy),     \
                .mandatory_policy = POLICY_INIT((_x).mandatory_policy), \
        }

int policy_parser_registry_init(PolicyParserRegistry *registry);
void policy_parser_registry_deinit(PolicyParserRegistry *registry);

int policy_parser_registry_append_file(PolicyParserRegistry *registry, const char *filename, PolicyParser *parent);
