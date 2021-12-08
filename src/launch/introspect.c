/*
 * Implements D-Bus introspection, allowing to check whether
 * an object supports a given D-Bus interface. Used for backward
 * compatibility checks.
 */

#include <expat.h>
#include "launch/introspect.h"
#include "util/error.h"
#include "util/log.h"

struct parse_params {
    const char *interface_name;
    bool *supported;
};

static void parser_begin_fn(void *userdata, const XML_Char *name, const XML_Char **attrs) {
        struct parse_params *params = userdata;
        const char *k, *v;

        c_assert(params);
        c_assert(params->interface_name);
        c_assert(params->supported);

        if (!attrs)
                return;

        if (strcmp(name, "method") != 0)
                return;

        while (*attrs) {
                k = *(attrs++);
                v = *(attrs++);

                if (!k || !v)
                        continue;

                if (strcmp(k, "name") == 0 && strcmp(v, params->interface_name) == 0) {
                        *params->supported = true;
                        return;
                }
        }
}

int object_supports_interface(Launcher *launcher, const char *bus_name, const char *object, const char *interface_name) {
        _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply_xml = NULL;
        bool supported = false;
        XML_Parser parser;
        const char *xml;
        int r;
        struct parse_params params = {
                .interface_name = interface_name,
                .supported = &supported,
        };

        c_assert(launcher);
        c_assert(bus_name);
        c_assert(object);
        c_assert(interface_name);

        r = sd_bus_call_method(launcher->bus_regular,
                               bus_name,
                               object,
                               "org.freedesktop.DBus.Introspectable",
                               "Introspect",
                               &error, &reply_xml, NULL);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_read(reply_xml, "s", &xml);
        if (r < 0)
                return error_origin(r);

        parser = XML_ParserCreate(NULL);
        if (!parser)
                return error_origin(-ENOMEM);

        XML_SetUserData(parser, &params);
        XML_SetElementHandler(parser, parser_begin_fn, NULL);

        r = XML_Parse(parser, xml, strlen(xml), 1);
        if (r != XML_STATUS_OK) {
                log_append_here(&launcher->log, LOG_ERR, 0, NULL);
                r = log_commitf(&launcher->log,
                                "Parsing the Introspect XML of '%s' failed: %s\n",
                                object,
                                XML_ErrorString(XML_GetErrorCode(parser)));
                if (r)
                        return error_fold(r);

                return error_origin(-EINVAL);
        }

        return supported;
}
