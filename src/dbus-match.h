#pragma once

/*
 * D-Bus Match Rules
 */

#include <c-list.h>
#include <stdlib.h>

#define DBUS_MATCH_RULE_LENGTH_MAX (1024) /* taken from dbus-daemon */

typedef struct DBusMatchEntry DBusMatchEntry;
typedef struct DBusMatchRegistry DBusMatchRegistry;
typedef struct Peer Peer;

struct DBusMatchEntry {
        Peer *peer;

        CList link_registry;
        CList link_peer;

        const char *type;
        const char *sender;
        const char *interface;
        const char *member;
        const char *path;
        const char *path_namespace;
        const char *destination;
        const char *arg[64];
        const char *argpath[64];
        const char *arg0namespace;
        const char *eavesdrop;

        char buffer[];
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
