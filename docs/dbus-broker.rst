============
 dbus-broker
============

--------------------
D-Bus message broker
--------------------

:Manual section: 1
:Manual group: User Commands

SYNOPSIS
========

``dbus-broker`` ``--help``

``dbus-broker`` ``--version``

``dbus-broker`` [ OPTIONS ]


DESCRIPTION
===========

dbus-broker implements the message broker and bus driver of the D-Bus
specification. A controller, such as dbus-broker-launch\(1) must be responsible
for spawning and managing dbus-broker, and pass it a socket file descriptor,
on which the controller can configure the broker. The broker does not itself
read configuration files, spawn activated services, or in any other way
interact with the environment, appart from through the controller socket.

OPTIONS
=======

-v, --verbose              print extra debug output
--controller FD            use the given file descriptor number as the controlling socket
--max-bytes BYTES          the maximum number of bytes each user may own in the broker
--max-fds FDS              the maximum number of file descriptors each user may own in the broker
--max-matches MATCHES      the maximum number of match rules each user may own in the broker
--max-objects OBJECTS      the maximum total number of names, peers, pending replies, etc each user may own in the broker

SEE ALSO
========

``dbus-broker-launch``\(1)
``dbus-daemon``\(1)
