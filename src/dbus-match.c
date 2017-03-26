/*
 * D-Bus Match Rules
 */

#include <c-macro.h>
#include <c-list.h>
#include "dbus-match.h"
#include "peer.h"
#include "user.h"

int dbus_match_entry_new(DBusMatchEntry **entryp,
                         DBusMatchRegistry *registry,
                         Peer *peer,
                         const char *match) {
        _c_cleanup_(dbus_match_entry_freep) DBusMatchEntry *entry = NULL;

        if (peer->user->n_matches == 0)
                return -EDQUOT;

        entry = calloc(1, sizeof(*entry));
        if (!entry)
                return -EINVAL;

        peer->user->n_matches --;

        entry->peer = peer;
        c_list_link_tail(&registry->entries, &entry->link_registry);
        c_list_link_tail(&peer->matches, &entry->link_peer);

        /* XXX: parse match string */

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

        free(entry->sender);
        free(entry->interface);
        free(entry->member);
        free(entry->path);
        free(entry->path_namespace);
        free(entry->destination);
        free(entry->arg0namespace);

        for (unsigned int i = 0; i < 64; i++) {
                free(entry->arg[i]);
                free(entry->argpath[i]);
        }

        free(entry);

        return NULL;
}

void dbus_match_registry_init(DBusMatchRegistry *registry) {
        registry->entries = (CList)C_LIST_INIT(registry->entries);
}

void dbus_match_registry_deinit(DBusMatchRegistry *registry) {
        assert(c_list_is_empty(&registry->entries));
}
