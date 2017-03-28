/*
 * D-Bus Match Rules
 */

#include <c-macro.h>
#include <c-list.h>
#include "dbus-match.h"
#include "peer.h"
#include "user.h"

static int dbus_match_entry_assign(DBusMatchEntry *entry,
                                   const char *key,
                                   const char *value) {
        if (strcmp(key, "type") == 0) {
                entry->type = value;
        } else if (strcmp(key, "sender") == 0) {
                entry->sender = value;
        } else if (strcmp(key, "interface") == 0) {
                entry->interface = value;
        } else if (strcmp(key, "member") == 0) {
                entry->member = value;
        } else if (strcmp(key, "path") == 0) {
                entry->path = value;
        } else if (strcmp(key, "path_namespace") == 0) {
                entry->path_namespace = value;
        } else if (strcmp(key, "destination") == 0) {
                entry->destination = value;
        } else if (strcmp(key, "eavesdrop") == 0) {
                entry->eavesdrop = value;
        } else if (strcmp(key, "arg0namespace") == 0) {
                entry->arg0namespace = value;
        } else if (strncmp(key, "arg", strlen("arg")) == 0) {
                unsigned int i = 0;

                key += strlen("arg");

                for (unsigned int j = 0; j < 2; j ++) {
                        if (*key < '0' || *key > '9')
                                break;

                        i = i * 10 + *key - '0';
                        key ++;
                }
                if (strcmp(key, "")  == 0) {
                        entry->arg[i] = value;
                } else if (strcmp(key, "path") == 0) {
                        entry->argpath[i] = value;
                } else
                        return -EBADMSG;
        } else {
                return -EBADMSG;
        }

        return 0;
}

/*
 * Takes a null-termianted stream of characters, removes any quoting, breaks
 * them up at commas and returns them one character at a time.
 */
static char dbus_match_string_pop(const char **match, bool *quoted) {
        /*
         * Within single quotes (apostrophe), a backslash represents itself, and
         * an apostrophe ends the quoted section. Outside single quotes, \'
         * (backslash, apostrophe) represents an apostrophe, and any backslash
         * not followed by an apostrophe represents itself.
         */
        while (**match == '\'') {
                (*match) ++;
                *quoted = !*quoted;
        }

        switch (**match) {
        case '\0':
                return '\0';
        case ',':
                (*match) ++;

                if (*quoted)
                        return ',';
                else
                        return '\0';
        case '\\':
                (*match) ++;

                if (!(*quoted) && **match == '\'') {
                        (*match) ++;
                        return '\'';
                } else {
                        return '\\';
                }
        default:
                return *((*match) ++);
        }
}

static int dbus_match_entry_parse_match(DBusMatchEntry *entry,
                                        const char *match,
                                        size_t n_match) {
        const char *key = NULL, *value = NULL;
        bool quoted = false;
        char c;
        int r;

        for (unsigned int i = 0; i < n_match; i ++) {
                if (!key) {
                        do {
                                /* strip leading space before a key */
                                c = dbus_match_string_pop(&match, &quoted);
                        } while (c == ' ');
                        key = entry->buffer + i;
                } else {
                        c = dbus_match_string_pop(&match, &quoted);
                }

                /* strip key and value at '=' */
                if (c == '=' && !value) {
                        entry->buffer[i] = '\0';
                        value = entry->buffer + i + 1;
                } else {
                        entry->buffer[i] = c;
                }

                /* reached end of key/value pair */
                if (c == '\0') {
                        /* did not finish reading key yet */
                        if (!value)
                                return -EBADMSG;

                        r = dbus_match_entry_assign(entry, key, value);
                        if (r < 0)
                                return r;

                        key = NULL;
                        value = NULL;

                        /* reached the end of the input string */
                        if (*match == '\0')
                                return 0;
                }
        }

        return -EBADMSG;
}

int dbus_match_entry_new(DBusMatchEntry **entryp,
                         DBusMatchRegistry *registry,
                         Peer *peer,
                         const char *match) {
        _c_cleanup_(dbus_match_entry_freep) DBusMatchEntry *entry = NULL;
        size_t n_match;
        int r;

        if (peer->user->n_matches == 0)
                return -EDQUOT;

        n_match = strlen(match);

        entry = calloc(1, sizeof(*entry) + n_match);
        if (!entry)
                return -EINVAL;

        peer->user->n_matches --;

        entry->peer = peer;
        c_list_link_tail(&registry->entries, &entry->link_registry);
        c_list_link_tail(&peer->matches, &entry->link_peer);

        r = dbus_match_entry_parse_match(entry, match, n_match);
        if (r < 0)
                return r;

        *entryp = entry;
        entry = NULL;
        return 0;
}

DBusMatchEntry *dbus_match_entry_free(DBusMatchEntry *entry) {
        if (!entry)
                return NULL;

        entry->peer->user->n_matches ++;

        c_list_unlink(&entry->link_registry);
        c_list_unlink(&entry->link_peer);

        free(entry);

        return NULL;
}

void dbus_match_registry_init(DBusMatchRegistry *registry) {
        registry->entries = (CList)C_LIST_INIT(registry->entries);
}

void dbus_match_registry_deinit(DBusMatchRegistry *registry) {
        assert(c_list_is_empty(&registry->entries));
}
