/*
 * Unique Name helpers
 */

#include <stdlib.h>
#include "dbus/unique-name.h"
#include "util/error.h"

/**
 * unique_name_from_id() - generate the unique name from its id
 * @name                string buffer to write to
 * @id                  id to generate name from
 *
 * @name must be at least UNIQUE_NAME_STRING_MAX and @id must not be
 * UNIQUE_NAME_ID_INVALID.
 */
void unique_name_from_id(char *name, uint64_t id) {
        int r;

        assert(id != UNIQUE_NAME_ID_INVALID);

        r = snprintf(name, UNIQUE_NAME_STRING_MAX, ":1.%"PRIu64, id);
        assert(r >= 0 && r < UNIQUE_NAME_ID_INVALID);
}

/**
 * unique_name_to_id() - get the id from a unique name
 * @name                the name to operate on
 * @idp                 the pointer to the id
 *
 * Parse a unique-name string into a 64-bit integer. There is no restriction
 * on the length of the name string, so we can be passed arbitrarily large
 * peer ids. However, as the ids are allocated consequtively, any id exceeding
 * 64 bits cannot refer to a real peer, so we treat such names as invalid.
 * Moreover, we reserve the larges 64-bit integer as the special
 * UNIQUE_NAME_ID_INVALID.
 */
int unique_name_to_id(const char *name, uint64_t *idp) {
        uint64_t id;
        char *end;

        static_assert(UNIQUE_NAME_ID_INVALID == ULLONG_MAX, "UNIQUE_NAME_ID_INVALID does not match strtoull() range.");

        if (strncmp(name, ":1.", strlen(":1.")) != 0)
                return UNIQUE_NAME_E_CORRUPT;

        name += strlen(":1.");

        errno = 0;
        id = strtoull(name, &end, 10);
        if (errno != 0 && errno != ERANGE)
                return error_origin(-errno);
        else if (*end)
                return UNIQUE_NAME_E_CORRUPT;
        else if (id == ULLONG_MAX)
                return UNIQUE_NAME_E_RANGE;

        *idp = id;
        return 0;
}
