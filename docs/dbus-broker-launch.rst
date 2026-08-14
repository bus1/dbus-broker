..
    SPDX-License-Identifier: GPL-3.0-or-later
    SPDX-FileCopyrightText: D-Bus Broker Developers

==================
dbus-broker-launch
==================

----------------------------------
Launcher for D-Bus Message Brokers
----------------------------------

:Manual section: 1
:Manual group: User Commands

SYNOPSIS
========

| ``dbus-broker-launch`` [ OPTIONS ]
| ``dbus-broker-launch`` ``--version``
| ``dbus-broker-launch`` ``--help``


DESCRIPTION
===========

**dbus-broker-launch** is a launcher for **dbus-broker**, spawning and managing
a D-Bus Message Bus. The launcher aims to be fully compatible to the D-Bus
reference implementation **dbus-daemon**\(1), supporting the same configuration
syntax and runtime environment.

Each instance of **dbus-broker-launch** manages exactly one message bus. Each
message bus is independent. The configuration file can either be specified via
the command-line, or the default is picked from */usr/share/dbus-1/*. Nearly
all of the configuration attributes are supported. See **dbus-daemon**\(1) for
details on the configuration syntax.

OPTIONS
=======

The following command-line options are supported. If an option is passed, which
is not listed here, the launcher will deny startup and exit with an error.

-h, --help                      print usage information and exit immediately
--version                       print build-version and exit immediately
--audit                         enable logging to the linux audit subsystem
                                (no-op if audit support was not compiled in;
                                **Default**: off)
--config-file=PATH              config file to use (**Default**:
                                */usr/share/dbus-1/{system,session}.conf*)
--scope=SCOPE                   select scope to run in (one of: *system*,
                                *user*; **Default**: *system*)

LOGGING
=======

By default, **dbus-broker-launch** logs messages to the system journal. The
messages are augmented with lots of metadata, so be sure to check the
additional journal-fields. The human-readable log-message is intentionally kept
short.

On startup and shutdown, the launcher logs initial messages that contain
information on the parsed configuration files and service definitions. No other
log-messages are generated, except those originating in **dbus-broker**\(1).

SCOPE
=====

Unlike **dbus-daemon**\(1), **dbus-broker-launch** activates all services as
systemd units. Services that already come with a systemd-unit are activated as
usual, but services that lack a systemd unit are activated as transient unit,
with an ad-hoc unit-file generated at runtime. This guarantees that all
services run in a well-defined environment.

The **--scope** parameter defines which systemd instance the launcher shall use
to activate services. In case of *system*, the launcher will use the system
instance of systemd. In case of *user*, the user instance is used instead.

Furthermore, the selected scope also defines which configuration file is used
if none is specified on the command-line.

The selected scope does not have any further effect. It is only needed to
define the activation environment for loaded service definitions. If no
activatable services are declared, the scope will have no effect at all.

SOCKETS
=======

The socket to listen on for client connections must be created and passed to
**dbus-broker-launch** by its parent process. The protocol must follow the
socket-activation as defined by **systemd.socket**\(1). Only a single socket is
supported right now.

Additional *<listen>%path%</listen>* attributes in the configuration are
ignored.

LIMITS
======

**dbus-broker-launch** reads the same *<limit>* configuration elements as
**dbus-daemon**\(1). In addition to the standard limits, the following
**dbus-broker**-specific limits control the rate at which a single user may
open new connections to the bus:

*connections_rate_limit_per_user_sec*
        Length, in seconds, of the time window used to rate-limit new
        connections per user. Together with
        *connections_rate_limit_per_user_burst* it allows each user to open at
        most *burst* new connections during every *sec* interval. A value of
        *0* (the **Default**) disables connection rate-limiting.

*connections_rate_limit_per_user_burst*
        Maximum number of new connections a single user may open during each
        *connections_rate_limit_per_user_sec* window. A value of *0* (the
        **Default**) disables connection rate-limiting.

Both limits must be set to a non-zero value for the rate-limit to take effect.
Once a user exceeds its connection rate-limit, further connection attempts from
that user are refused until the current window elapses. This complements
*max_connections_per_user*, which caps the number of concurrent connections a
single user may have open at any time.

An example configuration snippet allowing each user to open at most 50 new
connections every 10 seconds looks as follows::

    <busconfig>
      <limit name="connections_rate_limit_per_user_sec">10</limit>
      <limit name="connections_rate_limit_per_user_burst">50</limit>
    </busconfig>

PRIVILEGES
==========

The launcher needs read-access to its configuration file. Other than that, no
privileges are needed. If the *<user>%user%</user>* configuration attribute is
used, the launcher will drop privileges when executing **dbus-broker**.

If activatable services are declared, the launcher will need access to the
corresponding systemd instance. The launcher must be allowed to spawn transient
units, as well as manage units declared in the service definitions.

SEE ALSO
========

``dbus-daemon``\(1)
``dbus-broker``\(1)
