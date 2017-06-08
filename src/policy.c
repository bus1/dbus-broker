/*
 * D-Bus Policy
 */

#include <c-macro.h>
#include <expat.h>
#include <stdlib.h>
#include "util/error.h"

enum {
        _POLICY_E_SUCCESS,

        POLICY_E_INVALID_XML,
};

typedef struct PolicyParser PolicyParser;

struct PolicyParser {
        XML_Parser parser;
        const char *filename;
        int level;
        bool needs_linebreak;
};

#define POLICY_PARSER_NULL {}

static void policy_parser_handler_policy(PolicyParser *parser, const XML_Char **attributes) {
        if (parser->needs_linebreak)
                fprintf(stderr, "\n");

        fprintf(stderr, "<policy");

        while (*attributes) {
                fprintf(stderr, " %s", *(attributes++));
                fprintf(stderr, "=%s", *(attributes++));
        }

        fprintf(stderr, ">\n");

        parser->needs_linebreak = false;
}

static void policy_parser_handler_deny(PolicyParser *parser, const XML_Char **attributes) {
        if (parser->needs_linebreak)
                fprintf(stderr, "\n");

        fprintf(stderr, "    DENY:\n");

        while (*attributes) {
                fprintf(stderr, "        %s", *(attributes++));
                fprintf(stderr, "=%s\n", *(attributes++));
        }

        parser->needs_linebreak = true;
}

static void policy_parser_handler_allow(PolicyParser *parser, const XML_Char **attributes) {
        if (parser->needs_linebreak)
                fprintf(stderr, "\n");

        fprintf(stderr, "    ALLOW:\n");

        while (*attributes) {
                fprintf(stderr, "        %s", *(attributes++));
                fprintf(stderr, "=%s\n", *(attributes++));
        }

        parser->needs_linebreak = true;
}

static void policy_parser_handler_start(void *userdata, const XML_Char *name, const XML_Char **attributes) {
        PolicyParser *parser = userdata;

        switch (parser->level++) {
                case 1:
                        if (!strcmp(name, "policy"))
                                policy_parser_handler_policy(parser, attributes);
                        break;
                case 2:
                        if (!strcmp(name, "deny"))
                                policy_parser_handler_deny(parser, attributes);
                        else if (!strcmp(name, "allow"))
                                policy_parser_handler_allow(parser, attributes);
                        break;
                default:
                        break;
        }
}

static void policy_parser_handler_end(void *userdata, const XML_Char *name) {
        PolicyParser *parser = userdata;

        if (--parser->level == 1 &&
            !strcmp(name, "policy")) {
                fprintf(stderr, "</policy>\n");
                parser->needs_linebreak = true;
        }
}

static void policy_parser_init(PolicyParser *parser) {
        parser->parser = XML_ParserCreate(NULL);
        XML_SetUserData(parser->parser, parser);
        XML_SetElementHandler(parser->parser, policy_parser_handler_start, policy_parser_handler_end);
}

static void policy_parser_deinit(PolicyParser *parser) {
        XML_ParserFree(parser->parser);
        *parser = (PolicyParser)POLICY_PARSER_NULL;
}

static int policy_parser_parse_file(PolicyParser *parser, const char *filename) {
        _c_cleanup_(c_fclosep) FILE *file = NULL;
        char buffer[1024];
        size_t len;
        int r;

        file = fopen(filename, "r");
        if (!file)
                return error_origin(-EIO);

        parser->filename = filename;

        do {
                len = fread(buffer, sizeof(char), sizeof(buffer), file);
                if (!len && ferror(file))
                        return error_origin(-EIO);

                r = XML_Parse(parser->parser, buffer, len, XML_FALSE);
                if (r != XML_STATUS_OK)
                        return POLICY_E_INVALID_XML;
        } while (len == sizeof(buffer));

        return 0;
}

static int policy_parser_finalize(PolicyParser *parser) {
        int r;

        r = XML_Parse(parser->parser, NULL, 0, XML_TRUE);
        if (r != XML_STATUS_OK)
                return POLICY_E_INVALID_XML;

        return 0;
}

static void policy_print_parsing_error(PolicyParser *parser) {
        fprintf(stderr, "%s +%lu: %s\n",
                parser->filename,
                XML_GetCurrentLineNumber(parser->parser),
                XML_ErrorString(XML_GetErrorCode(parser->parser)));
}

int policy_parse(void) {
        PolicyParser parser = (PolicyParser)POLICY_PARSER_NULL;
        /* XXX: only makes sense for the system bus */
        const char *filename = "/usr/share/dbus-1/system.conf";
        int r;

        policy_parser_init(&parser);

        r = policy_parser_parse_file(&parser, filename);
        if (r) {
                if (r == POLICY_E_INVALID_XML)
                        policy_print_parsing_error(&parser);
                else
                        return error_fold(r);
        }

        r = policy_parser_finalize(&parser);
        if (r) {
                if (r == POLICY_E_INVALID_XML)
                        policy_print_parsing_error(&parser);
                else
                        return error_fold(r);
        }

        policy_parser_deinit(&parser);

        return 0;
}
