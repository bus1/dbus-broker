#pragma once

/*
 * D-Bus Match Rules
 */

#include <c-list.h>
#include <stdlib.h>

typedef struct DBusMatchEntry DBusMatchEntry;
typedef struct DBusMatchRegistry DBusMatchRegistry;
typedef struct Peer Peer;

struct DBusMatchEntry {
        Peer *peer;

        CList link_registry;
        CList link_peer;

        uint8_t type;
        char *sender;
        char *interface;
        char *member;
        char *path;
        char *path_namespace;
        char *destination;
        char *arg[64];
        char *argpath[64];
        char *arg0namespace;
        bool eavesdrop : 1;
};

struct DBusMatchRegistry {
        CList entries;
};

int dbus_match_entry_new(DBusMatchEntry **entryp,
                         DBusMatchRegistry *registry,
                         Peer *peer,
                         const char *match);
DBusMatchEntry *dbus_match_entry_free(DBusMatchEntry *entry);

void dbus_match_registry_init(DBusMatchRegistry *registry);
void dbus_match_registry_deinit(DBusMatchRegistry *registry);

C_DEFINE_CLEANUP(DBusMatchEntry *, dbus_match_entry_free);
