# dbus-broker - Linux D-Bus Message Broker

## CHANGES WITH 17:

        * The `g_shell` subsystem of glib was replaced with a new submodule
          from the c-util suite, called `c-shquote`. It is a small project that
          implements POSIX-Shell compatible quoting. This is required by the
          dbus compatibility launcher to parse activation files.

          Furthermore, the `g_key_file` subsystem of glib was replaced with a
          submodule called `c-ini`, which implements a key-value file-parser.

          Both submodules need to be added if you compile from git. With this
          change, dbus-broker no longer requires glib.

        * The new configuration options introduced in dbus-1.12 are now
          recognized by the compatibility launcher and will no longer trigger
          warnings.

        * The systemd units shipped with dbus-broker now put the broker into
          more isolated environments, hopefully reducing the impact of possible
          security breaches. This requires semi-recent systemd releases to have
          an effect. Older systemd release will ignore these new sandboxing
          features.

        * In case of forced client disconnects, the broker will now be a lot
          more verbose and specific in its log-messages, describing exactly why
          a client was disconnected. This hopefully aids debugging of
          misbehaving clients.

        * Messages with file-descriptors will now be refused if the client did
          not negotiate file-descriptor passing before. This aligns the
          behavior of the broker with the reference implementation. Before, all
          clients were treated as if they support file-desciptor passing. This
          is no longer the case.

        Contributions from: David Herrmann, Jacob Alzén, Tom Gundersen

        - Tübingen, 2018-12-31

## CHANGES WITH 16:

        * Explicitly mention our mailing-list in the README:

              https://groups.google.com/forum/#!forum/bus1-devel

          All dbus-broker releases are announced there, and the list is open
          for any dbus and dbus-broker related discussions.

        * Revert the removal of the --verbose switch of bus launcher. There
          are existing users that pass this switch, and now suddenly fail
          spawning dbus-broker. The switch is now a no-op and silently ignored.

        * The global resource limits were reconsidered and aligned with the
          values used by dbus-daemon(1) and current distributions. Furthermore,
          the limits provided in the bus XML configuration are now interpreted
          by the launcher and converted to the broker-internal accounting
          scheme.

        Contributions from: Daniel Rusek, David Herrmann, Marc-Antoine
                            Perennou, Tom Gundersen

        - Tübingen, 2018-10-09

## CHANGES WITH 15:

        * Fix dbus-broker-launch to retain CAP_AUDIT_WRITE in its ambient
          capability set, so dbus-broker will get it as well.

        * Be less verbose about unknown usernames in the XML config of
          dbus-broker-launch.

        Contributions from: David Herrmann, Tom Gundersen

        - Tübingen, 2018-08-08

## CHANGES WITH 14:

        * The broker now implements the org.freedesktop.DBus.Peer, and
          org.freedesktop.DBus.Properties interfaces.

        * The man-pages have been updated to reflect the current state of
          dbus-broker and dbus-broker-launch.

        * Matches are now indexed by all major fields, greatly improving
          broadcast performance.

        * The launcher now respects the `<user>NAME</user>' configuration and
          correctly drops privileges of the broker and itself after startup.

        * The `send_broadcast', `min_fds', and `max_fds' XML policy attributes
          are now supported (as defined by dbus-daemon(1)).

        * Configuration files are now watched for modifications by the
          launcher. Any modification triggers a configuration reload. This
          follows the behavior of dbus-daemon(1).

        * The broker gained a `--machine-id' command-line switch to specify the
          local machine-id to be served via the org.freedesktop.DBus.Peer
          interface. The launcher uses libsystemd-daemon to provide it.

        * The controller interface of dbus-broker has been renamed from
          org.bus1.DBus.Launcher to org.bus1.DBus.Controller.

        Contributions from: David Herrmann, Khem Raj, Tom Gundersen

        - Tübingen, 2018-07-03

## CHANGES WITH 13:

        * The --verbose command-line switch was dropped from both the broker
          and the launcher. Its behavior is now the default.

        * Fix a startup dead-lock with systemd NSS plugins. This requires
          setting the SYSTEMD_NSS_BYPASS_BUS environment variable, so
          libnss_systemd.so will skip recursive bus-calls.

        * Read /etc/{passwd,groups} early on from the launcher to
          pre-initialize the nss-cache. This allows startup on properly
          configured systems without ever calling into NSS. Furthermore, in
          case this does not resolve all required usernames, the launcher will
          loudly log any call into NSS, to better debug early dead-locks in bus
          startup code.
          Note that this new mechanic overrules /etc/nsswitch.conf for the
          launcher. However, this is only made based on the assumption that
          if an entry is present in /etc/{passwd,groups}, it better be a valid
          entry. If an entry is not present, the launcher will still correctly
          call into NSS.

        Contributions from: David Herrmann, Tom Gundersen

        - Tübingen, 2018-04-23

## CHANGES WITH 12:

        * Building documentation is now optional. Use -Ddocs=true with meson
          to build documentation. It is disabled by default.

        * The compatibility launcher now namespaces transient systemd units
          based on its own name on the scope-bus (i.e., the bus
          dbus-broker-launch uses to ask systemd for activation of units). This
          allows running private dbus-broker instances, while using transient
          systemd-units on the scope-bus for activation. For instance, at-spi2
          can use activated units that clash with the namespace of the session
          or system bus.

        * Several bug-fixes.

        Contributions from: Daniele Nicolodi, David Herrmann, Tom Gundersen

        - Tübingen, 2018-04-17

## CHANGES WITH 11:

        * Building now requires linux-api-headers>=4.13. We expect the
          SO_PEERGROUPS socket-option to be defined in the kernel headers.
          Older kernels are still supported at runtime, but at build-time you
          need to provide recent headers.

        * The build-system now supports a new meson configuration option,
          called 'system-console-users'. It takes an array of user-names which
          should be considered 'at-console' by dbus-broker-launch. These extend
          the existing range based on [SYSTEMUIDMAX+1..-1[ with a list of
          statically provided usernames.

          This allows distributions to provide special system-users that need
          to be considered as 'at-console'. Right now, this should be used for
          users like 'gdm', which are system-users, but need static access to
          the console. Note that these usernames must be reserved by the
          distribution, but don't have to be present at runtime. The launcher
          dynamically picks the usernames that it can resolve, and retries on
          every reload.

        * The policy-type of the dbus-broker API has been simplified. It is now
          reduced to a policy-batch indexed by uids, in combination with a
          policy-batch indexed either by gid or uid-range. Per peer, the broker
          will only ever select one uid-batch, and all matching gid/uid-range
          batches. Note that anything but the per-uid-batch is deprecated, and
          exclusively meant for backwards compatibility.

          This change only affects dbus-broker. The compatibility launcher was
          adapted to use this new API. It still converts the policy as given by
          the XML configuration in a compatible way to the simplified internal
          representation.

        * The launcher now requires an explicit --audit commandline option to
          enable auditing. Before, it was deduced based on the passed scope.
          You now have to pass it explicitly.

        * The launcher now supports a `--config-file PATH` commandline option
          to override the root configuration file, which is still deduced based
          on the passed scope parameter.

        * A path miscomputation in the XML <include> tags was fixed. They should
          work as expected now.

        * The <servicedir> XML tags are now properly supported. Before, they
          were correctly parsed, but never actually sourced for input.

        * The XDG_DATA_DIRS environment variable is now supported by the
          launcher, according to the related xdg spec. Note that this only
          affects the user-scope!

        * The --listen parameter was dropped from the launcher. Only
          socket-activation is supported now. If required, any parent process
          should now create the listener socket themselves, and pass it in like
          socket activation.

        * As usual, a bunch of fixes and small improvements!

        Contributions from: David Herrmann, Tom Gundersen

        - Tübingen, 2018-02-21

## CHANGES WITH 10:

        * Fix RequestName() / ReleaseName() to send signals before their reply,
          to match dbus-daemon behavior.

        * Several bug-fixes, cleanups, and performance improvements.

        Contributions from: David Herrmann, Tom Gundersen

        - Tübingen, 2018-02-07

## CHANGES WITH 9:

        * A configuration reload of the launcher can now be triggered via its
          managing systemd instance. The ExecReload= key is hooked up to
          trigger a ReloadConfig() D-Bus call.

        * The launcher now runs as 'Type=notify' systemd service type. This
          closes a possible dead-lock during startup. Previously, there was a
          chance of systemd itself connecting to D-Bus in a blocking manner,
          before the launcher was ready. This might have resulted in the
          launcher waiting on systemd, and thus dead-lock.
          By running as 'Type=notify' systemd will wait for the launcher to be
          ready before connecting to it.

        * Activated units now inherit their user from the actual D-Bus service,
          if provided. They used to be started as root, but now the 'User=' key
          is properly honored.

        Contributions from: David Herrmann, Marc-Antoine Perennou, Tom
                            Gundersen

        - Tübingen, 2017-11-30

## CHANGES WITH 8:

        * The launcher now uses instantiated systemd template units when
          activating a service that has no associated systemd service file.
          This allows services to stick around after being deactivated. It is
          closer in behavior to the original service activation of dbus-daemon,
          while still keeping them out of the dbus-broker environment.

        * Audit is now only enabled when --audit is passed to dbus-broker. By
          default, the launcher will pass it only for the system bus.

        * The launcher now supports configuration reloading. When triggered, it
          forces the launcher to reload the bus configuration and all service
          files, and adjust the broker state. Note that not all modifiers can
          be adjusted at runtime (e.g., you cannot change the user the broker
          runs as). The set of modifiers that can be adjusted at runtime is the
          same set that dbus-daemon(1) supports.
          The reload operation can be triggered via a direct SIGHUP to the
          launcher, or via the ReloadConfig() call on org.freedesktop.DBus.

        * The AddListener() call on org.bus1.DBus.Broker no longer accepts the
          policy filesystem path. It was a no-op since dbus-broker supports
          parsing policies in the launcher.

        Contributions from: David Herrmann, Tom Gundersen

        - Tübingen, 2017-11-07

## CHANGES WITH 7:

        * More bugfixes for 32bit architectures.

        Contributions from: David Herrmann

        - Berlin, 2017-10-17

## CHANGES WITH 6:

        * Bugfixes for 32bit architectures.

        Contributions from: David Herrmann, Tom Gundersen

        - Tübingen, 2017-10-15

## CHANGES WITH 5:

        * Man-pages for dbus-broker and dbus-broker-launch are now built via
          meson and installed into `$prefix/man' by default.

        * AddListener() on org.bus1.DBus.Broker now supports uid-ranges. This
          is used by the launcher to implement at_console={true,false} policies
          by considering any uid higher than SYSTEMUIDMAX (as defined by
          systemd) to be at the console. For a detailed discussion, see:

              https://github.com/bus1/dbus-broker/issues/56
              https://github.com/systemd/systemd/pull/6762

        * The dbus-broker.service unit is now ordered before basic.target. This
          ensures that D-Bus applications can use the bus during shutdown.
          Until now, shutdown of the message bus was unordered against shutdown
          of D-Bus applications. While applications should handle such
          situations gracefully, ordering dbus-broker.service before
          basic.target eliminates a random source of bus errors during
          shutdown.

        * If running the launcher, you are highly recommended to update
          libexpat to 2.2.3, or newer. It contains fixes to avoid random stalls
          on /dev/random. For details, see:

              https://github.com/libexpat/libexpat/blob/R_2_2_3/expat/Changes
              https://github.com/libexpat/libexpat/pull/92
              https://bugs.freedesktop.org/show_bug.cgi?id=101858

        Contributions from: David Herrmann, Marc-Antoine Perennou, Tom
                            Gundersen

        - Tübingen, 2017-10-10

## CHANGES WITH 4:

        * Add optional libaudit support in combination with SELinux. If
          enabled, SELinux AVC violations will end up in the audit log, rather
          than syslog.

        * Drop auto-detection of dependencies. The build-system now requires
          explicit configuration via meson (see `mesonconf' or `-Dfoo=bar').

          3 user-options are provided:

              - audit=off
                Whether libaudit should be used as dependency to log AVC
                violations in combination with SELinux.

              - selinux=off
                Whether libselinux should be used as dependency to implement
                MAC-security compatible to dbus-daemon(1).

              - launcher=on
                Whether the dbus-broker-launch compatibility binary should be
                built or not.

        * Submodule fallback logic is no longer available. All submodules are
          forcibly linked from now on. Once the submodules have public, stable
          releases, we will make them mandatory dependencies. Until then, they
          will be mandatory builtins.

        * The compatibility launcher now supports extended service search-paths
          according to the D-Bus Specification. Before, it hard-coded
          /usr/share/dbus-1, but now it correctly follows the XDG Base Dir
          Spec.

        * Units will now be activated via explicit calls to StartUnit() rather
          than faking a ActivationRequest directed signal. This allows to catch
          startup failures (or rejections) and allows to reject all pending
          activation requests right away.

        * The broker now logs policy violations to the system log.

        * Lots of bug fixes all around.

        Contributions from: David Herrmann, Laurent Bigonville, Michal Schmidt,
                            Mike Gilbert, Tom Gundersen

        - Tübingen, 2017-09-07

## CHANGES WITH 3:

        * Added manpages.

        Contributions from: Tom Gundersen

        - Oslo, 2017-08-18

## CHANGES WITH 2:

        * Added SELinux support.

        Contributions from: Tom Gundersen

        - Oslo, 2017-08-16

## CHANGES WITH 1:

        * Initial release of dbus-broker.

        * Contains dbus-broker, an independent D-Bus message broker
          implementation, which provides near perfect compatibility to the
          D-Bus reference implementation dbus-daemon(1).
          The broker binary is a pure bus implementation that does not depend
          on any external resources or environments. Rather it is controlled
          via a private control-connection from its parent process. This allows
          the parent to modify the broker at runtime, get notified of specific
          events, and control its lifetime.

        * The dbus-broker-launch application implements the D-Bus system and
          session bus compatible to dbus-daemon(1). It reads the known policy
          and service files, reacts to well-defined signals, and employs
          dbus-broker for the actual message passing.

        Contributions from: David Herrmann, Georg Müller, Marc-Antoine Perennou,
                            Tom Gundersen

        - Tübingen, 2017-08-03
