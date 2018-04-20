===================
 dbus-broker-launch
===================

---------------------------------------------------------
dbus-daemon\(1) compatible wrapper around dbus-broker\(1)
---------------------------------------------------------

:Manual section: 1

SYNOPSIS
========

``dbus-broker-launch`` ``--help``

``dbus-broker-launch`` ``--version``

``dbus-broker-launch`` [ OPTIONS ]


DESCRIPTION
===========

dbus-broker-launch provides a drop-in replacement for the functionality of dbus-daemon(1). It
installs a listening socket, or takes one passed in, and it parses the relevant configuration
files. It forks off and controls an instance of dbus-broker\(1), which implements the actual
message bus.

OPTIONS
=======

--listen PATH   install a listening socket at PATH
-f, --force     overwrite any existing listening socket
--scope SCOPE   the scope of the message bus, one of ``system`` or ``user``

SEE ALSO
========

``dbus-daemon``\(1)
``dbus-broker``\(1)
