# dbus-broker - Linux D-Bus Message Broker

The dbus-broker project is an implementation of a message bus as
defined by the D-Bus specification. Its aim is to provide high
performance and reliability, while keeping compatibility to the D-Bus
reference implementation. It is exclusively written for Linux systems,
and makes use of many modern features provided by recent linux kernel
releases.

**WIKI:**
        https://github.com/bus1/dbus-broker/wiki

**BUG REPORTS:**
        https://github.com/bus1/dbus-broker/issues

**GIT:**

```
  Cloning over ssh: git@github.com:bus1/dbus-broker.git
  Cloning over https: https://github.com/bus1/dbus-broker.git
```

**GITWEB:**
        https://github.com/bus1/dbus-broker

**MAILINGLIST:**
        https://groups.google.com/forum/#!forum/bus1-devel

## Requirements

The requirements for dbus-broker are:

```
  glibc >= 2.16
  linux kernel >= 4.17
  libaudit >= 3.0               (optional)
  libcap-ng >= 0.6              (optional)
  libselinux >= 3.2             (optional)
```

Additionally, the compatibility launcher requires:

```
  expat >= 2.2
  systemd >= 230
```

At build-time, the following software is required:

```
  linux-api-headers >= 4.13
  meson >= 1.3
  pkg-config >= 0.29
  rust >= 1.84
  rust-bindgen >= 0.60
  dbus >= 1.10                (optional: only for tests)
  python-docutils >= 0.13     (optional: only for docs)
```

## Install

The meson build-system is used for dbus-broker. Contact upstream
documentation for detailed help. In most situations the following
commands are sufficient to build and install dbus-broker from source:

```
  $ meson setup build
  $ meson compile -C build
  $ meson test -C build
  $ meson install -C build
```

For custom configuration options see meson_options.txt.

## License

Apache Software License 2.0
See AUTHORS for details.
