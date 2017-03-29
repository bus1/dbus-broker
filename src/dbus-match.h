#pragma once

/*
 * D-Bus Match Rules
 */

#include <c-list.h>
#include <stdlib.h>

#define DBUS_MATCH_RULE_LENGTH_MAX (1024) /* taken from dbus-daemon */

typedef struct DBusMatchEntry DBusMatchEntry;
typedef struct DBusMatchKeys DBusMatchKeys;
typedef struct DBusMatchRegistry DBusMatchRegistry;
typedef struct Peer Peer;

struct DBusMatchKeys {
        uint8_t type;
        bool eavesdrop : 1;
        const char *sender;
        const char *interface;
        const char *member;
        const char *path;
        const char *path_namespace;
        const char *destination;
        const char *args[64];
        const char *argpaths[64];
        const char *arg0namespace;
};

struct DBusMatchEntry {
        Peer *peer;

        CList link_registry;
        CList link_peer;

        DBusMatchKeys keys;

        char buffer[];
};

struct DBusMatchRegistry {
        CList entries;
};

int dbus_match_keys_parse(DBusMatchKeys *keys,
                          char *buffer,
                          const char *match,
                          size_t n_match);

DBusMatchEntry *dbus_match_entry_free(DBusMatchEntry *entry);

int dbus_match_add(DBusMatchRegistry *registry, Peer *peer, const char *match);
int dbus_match_remove(DBusMatchRegistry *registry, Peer *peer, const char *match);

DBusMatchEntry *dbus_match_next_entry(DBusMatchRegistry *registry,
                                      DBusMatchEntry *entry,
                                      DBusMatchKeys *keys);

void dbus_match_registry_init(DBusMatchRegistry *registry);
void dbus_match_registry_deinit(DBusMatchRegistry *registry);

C_DEFINE_CLEANUP(DBusMatchEntry *, dbus_match_entry_free);
