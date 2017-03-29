/*
 * D-Bus Match Rules
 */

#include <c-list.h>
#include <c-macro.h>
#include <c-string.h>
#include "dbus-match.h"
#include "peer.h"
#include "user.h"

/* XXX: move these defines where they belong */
#define DBUS_MESSAGE_TYPE_INVALID       (0)
#define DBUS_MESSAGE_TYPE_METHOD_CALL   (1)
#define DBUS_MESSAGE_TYPE_METHOD_REPLY  (2)
#define DBUS_MESSAGE_TYPE_ERROR         (3)
#define DBUS_MESSAGE_TYPE_SIGNAL        (4)

static bool dbus_match_keys_equal(DBusMatchKeys *key1, DBusMatchKeys *key2) {
        if (key1->type != key2->type)
                return false;

        if (!c_string_equal(key1->sender, key2->sender))
                return false;

        if (!c_string_equal(key1->interface, key2->interface))
                return false;

        if (!c_string_equal(key1->member, key2->member))
                return false;

        if (!c_string_equal(key1->path, key2->path))
                return false;

        if (!c_string_equal(key1->path_namespace, key2->path_namespace))
                return false;

        if (!c_string_equal(key1->destination, key2->destination))
                return false;

        if (key1->eavesdrop != key2->eavesdrop)
                return false;

        if (!c_string_equal(key1->arg0namespace, key2->arg0namespace))
                return false;

        for (unsigned int i = 0; i < C_ARRAY_SIZE(key1->args); i ++) {
                if (!c_string_equal(key1->args[i], key2->args[i]))
                        return false;

                if (!c_string_equal(key1->argpaths[i], key2->argpaths[i]))
                        return false;
        }

        return true;
}

static bool dbus_match_keys_subset(DBusMatchKeys *key1, DBusMatchKeys *key2) {
        if (key1->type != DBUS_MESSAGE_TYPE_INVALID && key1->type != key2->type)
                return false;

        if (key1->sender && !c_string_equal(key1->sender, key2->sender))
                return false;

        if (key1->interface && !c_string_equal(key1->interface, key2->interface))
                return false;

        if (key1->member && !c_string_equal(key1->member, key2->member))
                return false;

        if (key1->path && !c_string_equal(key1->path, key2->path))
                return false;

        if (key1->path_namespace &&
            !c_string_equal(key1->path_namespace, key2->path_namespace))
                return false;

        if (key1->destination &&
            !c_string_equal(key1->destination, key2->destination))
                return false;

        /* XXX: figure this out */
        if (key1->eavesdrop != key2->eavesdrop)
                return false;

        if (key1->arg0namespace &&
            !c_string_equal(key1->arg0namespace, key2->arg0namespace))
                return false;

        for (unsigned int i = 0; i < C_ARRAY_SIZE(key1->args); i ++) {
                if (key1->args[i] &&
                    !c_string_equal(key1->args[i], key2->args[i]))
                        return false;

                if (key1->argpaths[i] &&
                    !c_string_equal(key1->argpaths[i], key2->argpaths[i]))
                        return false;
        }

        return true;
}

static int dbus_match_keys_assign(DBusMatchKeys *keys,
                                  const char *key,
                                  const char *value) {
        if (strcmp(key, "type") == 0) {
                if (strcmp(value, "signal") == 0)
                        keys->type = DBUS_MESSAGE_TYPE_SIGNAL;
                else if (strcmp(value, "method_call") == 0)
                        keys->type = DBUS_MESSAGE_TYPE_METHOD_CALL;
                else if (strcmp(value, "method_reply") == 0)
                        keys->type = DBUS_MESSAGE_TYPE_METHOD_REPLY;
                else if (strcmp(value, "error") == 0)
                        keys->type = DBUS_MESSAGE_TYPE_ERROR;
                else
                        return -EBADMSG;
        } else if (strcmp(key, "sender") == 0) {
                keys->sender = value;
        } else if (strcmp(key, "interface") == 0) {
                keys->interface = value;
        } else if (strcmp(key, "member") == 0) {
                keys->member = value;
        } else if (strcmp(key, "path") == 0) {
                keys->path = value;
        } else if (strcmp(key, "path_namespace") == 0) {
                keys->path_namespace = value;
        } else if (strcmp(key, "destination") == 0) {
                keys->destination = value;
        } else if (strcmp(key, "eavesdrop") == 0) {
                if (strcmp(value, "true") ==0)
                        keys->eavesdrop = true;
                else if (strcmp(value, "fase") == 0)
                        keys->eavesdrop = false;
                else
                        return -EBADMSG;
        } else if (strcmp(key, "arg0namespace") == 0) {
                keys->arg0namespace = value;
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
                        keys->args[i] = value;
                } else if (strcmp(key, "path") == 0) {
                        keys->argpaths[i] = value;
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

int dbus_match_keys_parse(DBusMatchKeys *keys,
                          char *buffer,
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
                        key = buffer + i;
                } else {
                        c = dbus_match_string_pop(&match, &quoted);
                }

                /* strip key and value at '=' */
                if (c == '=' && !value) {
                        buffer[i] = '\0';
                        value = buffer + i + 1;
                } else {
                        buffer[i] = c;
                }

                /* reached end of key/value pair */
                if (c == '\0') {
                        /* did not finish reading key yet */
                        if (!value)
                                return -EBADMSG;

                        r = dbus_match_keys_assign(keys, key, value);
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

static int dbus_match_entry_new(DBusMatchEntry **entryp, const char *match) {
        _c_cleanup_(dbus_match_entry_freep) DBusMatchEntry *entry = NULL;
        size_t n_match;
        int r;

        n_match = strlen(match);

        entry = calloc(1, sizeof(*entry) + n_match);
        if (!entry)
                return -EINVAL;

        entry->link_registry = (CList)C_LIST_INIT(entry->link_registry);
        entry->link_peer = (CList)C_LIST_INIT(entry->link_peer);

        r = dbus_match_keys_parse(&entry->keys, entry->buffer, match, n_match);
        if (r < 0)
                return r;

        *entryp = entry;
        entry = NULL;
        return 0;
}

DBusMatchEntry *dbus_match_entry_free(DBusMatchEntry *entry) {
        if (!entry)
                return NULL;

        if (entry->peer)
                entry->peer->user->n_matches ++;

        c_list_unlink(&entry->link_registry);
        c_list_unlink(&entry->link_peer);

        free(entry);

        return NULL;
}

int dbus_match_add(DBusMatchRegistry *registry,
                   Peer *peer,
                   const char *match) {
        DBusMatchEntry *entry;
        int r;

        if (peer->user->n_matches == 0)
                return -EDQUOT;

        r = dbus_match_entry_new(&entry, match);
        if (r < 0)
                return r;

        peer->user->n_matches --;

        entry->peer = peer;
        c_list_link_tail(&registry->entries, &entry->link_registry);
        c_list_link_tail(&peer->matches, &entry->link_peer);

        return 0;
}

int dbus_match_remove(Peer *peer, const char *match) {
        char buffer[strlen(match)];
        DBusMatchKeys keys = {};
        DBusMatchEntry *entry;
        int r;

        r = dbus_match_keys_parse(&keys, buffer, match, strlen(match));
        if (r < 0)
                return r;

        c_list_for_each_entry(entry,
                              &peer->matches,
                              link_peer) {
                if (dbus_match_keys_equal(&keys, &entry->keys)) {
                        dbus_match_entry_free(entry);
                        return 0;
                }
        }

        return -ENOENT;
}

DBusMatchEntry *dbus_match_next_entry(DBusMatchRegistry *registry,
                                      DBusMatchEntry *entry,
                                      DBusMatchKeys *keys) {
        CList *link;

        if (!entry)
                link = c_list_loop_first(&registry->entries);
        else
                link = c_list_loop_next(&entry->link_registry);

        while (link != &registry->entries) {
                entry = c_list_entry(link, DBusMatchEntry, link_registry);

                if (dbus_match_keys_subset(&entry->keys, keys))
                        return entry;

                link = c_list_loop_next(link);
        }

        return NULL;
}

void dbus_match_registry_init(DBusMatchRegistry *registry) {
        registry->entries = (CList)C_LIST_INIT(registry->entries);
}

void dbus_match_registry_deinit(DBusMatchRegistry *registry) {
        assert(c_list_is_empty(&registry->entries));
}
