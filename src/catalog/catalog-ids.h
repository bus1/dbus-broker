#pragma once

/**
 * Catalog Message Identifiers
 *
 * This file contains the statically generated identifiers for our log
 * messages. These allow to store additional metadata explaining a log message
 * in the systemd catalog. Each constant must have a corresponding entry in
 * dbus-broker.catalog file.
 */

#define DBUS_BROKER_CATALOG_ACTIVATE_NO_UNIT            "7fc63312330b479bb32e598d47cef1a8"
#define DBUS_BROKER_CATALOG_ACTIVATE_MASKED_UNIT        "ee9799dab1e24d81b7bee7759a543e1b"
#define DBUS_BROKER_CATALOG_BROKER_EXITED               "a0fa58cafd6f4f0c8d003d16ccf9e797"
#define DBUS_BROKER_CATALOG_DIRWATCH                    "c8c6cde1c488439aba371a664353d9d8"
#define DBUS_BROKER_CATALOG_DISPATCH_STATS              "8af3357071af4153af414daae07d38e7"
#define DBUS_BROKER_CATALOG_NO_SOPEERGROUP              "199d4300277f495f84ba4028c984214c"
#define DBUS_BROKER_CATALOG_PROTOCOL_VIOLATION          "b209c0d9d1764ab38d13b8e00d1784d6"
#define DBUS_BROKER_CATALOG_QUOTA_QUEUE_REPLY           "0691c10b72b14341955a75873c867e29"
#define DBUS_BROKER_CATALOG_QUOTA_DEQUEUE               "2809c31175b84192b574d2a3da9fa8da"
#define DBUS_BROKER_CATALOG_RECEIVE_FAILED              "6fa70fa776044fa28be7a21daf42a108"
#define DBUS_BROKER_CATALOG_SERVICE_FAILED_OPEN         "0ce0fa61d1a9433dabd67417f6b8e535"
#define DBUS_BROKER_CATALOG_SERVICE_INVALID             "24dc708d9e6a4226a3efe2033bb744de"
#define DBUS_BROKER_CATALOG_SIGHUP                      "f15d2347662d483ea9bcd8aa1a691d28"
