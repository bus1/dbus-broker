# dbus-broker - Linux D-Bus Message Broker

## CHANGES WITH 37:

        * Add `/etc` and `/run` to the search-paths for system services. This
          change is aligned with recent changes to the reference
          implementation.

        * Support systemd's `notify-reload` to trigger a reload operation.
          This replaces the old `busctl call ...ReloadConfig` operation.

        * Extend `org.freedesktop.DBus.Debug.Stats.GetStats` with all the
          fields defined by the specification.

        * Fix a bug in match-rule processing which caused argument processing
          to fail for any but the first message argument.

        * Fix a memory leak in configuration processing when parsing invalid
          user or group IDs.

        Contributions from: Attila Lakatos, Barnabás Pőcze, darkblaze69, David
                            Rheinsberg, Evgeny Vereshchagin, Frantisek Sumsal,
                            Jeffrey Bosboom, Luca Boccassi, Ryan Wilson,
                            seaeunlee, Tomas Korbar

        - Dußlingen, 2025-06-16

## CHANGES WITH 36:

        * Fix possible file-descriptor use-after-close, which can lead to
          broker termination or disclosure of internal file-desciptors to
          clients.

        * Be more verbose about activation failures and include suitable
          information in related log messages.

        * New Meson build option `tests` allows installing tests as part
          of the distribution into `<prefix>/lib/dbus-broker/tests`. This
          is not recommended for production environments.

        * Many updates to the test suite and packing of the upstream project.

        Contributions from: Camron Carter, David Rheinsberg, Frantisek Sumsal,
                            Jake Dane, Tom Gundersen

        - Dußlingen, 2024-04-12

## CHANGES WITH 35:

        * Fix crash on startup/reload when corrupt configuration or
          service files are used.

        Contributions from: Allison Karlitskaya, David Rheinsberg, Lily Danzig

        - Dußlingen, 2023-12-20

## CHANGES WITH 34:

        * Use `AT_RANDOM` for libexpat initialization to avoid a hidden
          dependency in libexpat-hashtables on `/dev/urandom` at runtime.

        * Check for SELinux Enforcing-mode and honor its value.

        * Support the new `ProcessFD` key in `GetConnectionCredentials()`.

        * Loading files from a directory will not enumerate the files in a
          predictable order rather than the pseudo-random order returned by
          the kernel.

        Contributions from: David Rheinsberg, Luca Boccassi, Mark Esler,
                            Stefan Agner, Tom Gundersen

        - Dußlingen, 2023-12-12

## CHANGES WITH 33:

        * Fix a race-condition when starting systemd-services from the
          launcher. In particular, services with guarding systemd `Condition*`
          configurations might have incorrectly stalled activation attempts.

        * Return `org.freedesktop.DBus.Error.Failed` rather than a permission
          error for unimplemented functionality. The human-readable part of the
          error will contain "Unimplemented functionality" as explanation.

        * Improve resiliency of the launcher against runtime changes in dbus
          service-files. Changes to the files will no longer affect ongoing
          activation attempts.

        * Fix `GetStats()` returning two replies.

        * Fix missing origin-information in the startup log-message.

        Contributions from: David Rheinsberg, draconicfae, Marcus Sundberg,
                            Mike Gilbert, Stefan Agner, Tom Gundersen

        - Dußlingen, 2023-02-03

## CHANGES WITH 32:

        * Fix several bugs in the d-bus marshalling layer c-dvar, including
          out-of-bound reads.

        * Fix ubsan and asan warnings in c-stdaux and related subprojects.

        * Add initial infrastructure for the upcoming AppArmor security layer.
          This does not include full AppArmor support, yet, but merely prepares
          the code-base for it.

        Contributions from: David Rheinsberg, Evgeny Vereshchagin, Frantisek
                            Sumsal, Sebastian Reichel

        - Dußlingen, 2022-08-05

## CHANGES WITH 31:

        * Fix assertion failures in the user accounting, uncovered by the
          changes to accounting in v30.

        * Fix a memory leak in service-file re-loading, in particular in the
          command-line argument handling.

        * Fix a set of UBs related to memcpy(3), memset(3), and others, called
          with NULL on empty memory areas.

        Contributions from: David Rheinsberg, Evgeny Vereshchagin, Mel34,
                            Torge Matthies

        - Dußlingen, 2022-05-16

## CHANGES WITH 30:

        * Pull in subprojects via meson wraps. Subprojects are no longer
          included via git submodules, but instead pulled in at build-time via
          meson. All subprojects are converted to follow semver-style
          versioning, and dbus-broker pulls them in via a versioned dependency.
          All subprojects are still statically linked and considered part of
          dbus-broker. Any critical update to any subproject will cause a new
          release of dbus-broker, as it always did. Distributions are not
          required to monitor the subprojects manually.
          The official release-tarballs of dbus-broker include up-to-date
          subproject sources and can be used for offline builds. Distributions
          are free to use newer subproject sources for their rebuilds, and this
          is explicitly supported.
          Please refer to the meson documentation for details on how to manage
          subprojects. You can still pull in other versions of the dependencies
          by putting the sources into ./subprojects/. This change merely makes
          meson pull in the newest sources via a meson-wrap-file, if, and only
          if, no other sources have been provided.
          This change requires `meson-0.60` or newer.

        * Systemd units with failed `Condition*=` directives are now correctly
          considered failed, even if they report success.

        * Failed service activations now report more detailed information on
          the activation failure back through the activating client. The exact
          error information is now transmitted back from the launcher to the
          broker and then included in the dbus error message to the client.

        * Order the broker unit explicitly after `dbus.socket` to enforce the
          dependency even if the broker is disable temporarily. When the unit
          is enabled, this dependency is implicit due to the used alias to
          `dbus.service`.

        * The broker now runs in `session.slice` if applicable. The broker is
          thus considered more vital to the session and thus is less likely to
          be collected on resource exhaustion.

        * The `GetStats()` call on `org.freedeskop.DBus.Debug` now properly
          returns reply-owner statistics. Before, those were always set to 0.

        * Fix incorrect resource accounting of connecting peers. Before, only
          the data a peer actually transmitted/received was accounted, but the
          management object of the peer itself was not. This is now fixed to
          properly account all resources a peer uses.

        * Fix NULL-derefs in the XML configuration parser. Empty XML tags could
          have caused NULL-derefs before. This is now fixed.

        * Fix a buffer-overflow in shell-quote parsing, used by the `Exec=`
          line in activation service files.

        * Fix the launcher to obtain service-paths from systemd directly rather
          than building them manually. This will correctly resolve unit aliases
          and other quirks of systemd units.

        Contributions from: David Rheinsberg, Hugo Osvaldo Barrera, Luca
                            Boccassi, Zbigniew Jędrzejewski-Szmek, msizanoen1

        - Dußlingen, 2022-05-10

## CHANGES WITH 29:

        * Improve SELinux audit messages. This requires the new libselinux-3.2
          and libaudit-3.0 releases. If audit/selinux support is enabled, those
          are now the minimum required versions.

        * Make linux-4.17 a hard-requirements. Older kernels are no longer
          supported.

        * Fix startup failures when at-console users have consecutive uids.

        Contributions from: Chris PeBenito, David Rheinsberg, Thomas Mühlbacher

        - Dußlingen, 2021-06-02

## CHANGES WITH 28:

        * Further improvements to the service activation tracking. This better
          tracks units in systemd and closes some races where a repeated
          activation would incorrectly fail.

        * Fix a crash where duplicate monitor matches would be incorrectly
          installed in the broker.

        * Clear the ambient capability set to harden against possible exploits.

        * A couple of bug-fixes in the utility libraries, and static
          dependencies of the broker.

        Contributions from: David Rheinsberg

        - Dußlingen, 2021-03-17

## CHANGES WITH 27:

        * Fix several bugs with the new service-activation tracking, including
          a race-condition when restarting activatable services. Note that this
          includes a change to the internal controller API, which is used to
          communicate between the launcher and the broker.

        * Be more verbose about denied configuration access and print the
          file-path for better diagnostics.

        Contributions from: David Rheinsberg

        - Dußlingen, 2021-02-24

## CHANGES WITH 26:

        * Improve the service activation tracking of the compatibility
          launcher. We now track spawned systemd units for their entire
          lifetime, so we can properly detect when activations fail.

        * Work around a kernel off-by-one error in the socket queue accounting
          to fix a race-condition where dbus clients might not be dispatched.

        * Support running without `shmem` configured in the kernel. This will
          make the broker run better on limited embedded devices.

        Contributions from: Chris Paulson-Ellis, David Rheinsberg, Tim Gates

        - Dußlingen, 2021-01-20

## CHANGES WITH 25:

        * Fix an assertion failure when disconnecting monitors with active
          unique-name matches.

        * Fix the selinux error-handling to no longer mark all errors as
          auditable by default.

        * Minor improvements to the test-suite for better debugging.

        Contributions from: Chris PeBenito, David Rheinsberg

        - Tübingen, 2020-12-03

## CHANGES WITH 24:

        * Improve log messages for invalid configuration files, as well as
          early start-up errors.

        * Make audit-events properly typed and prevent non-auditable events
          from being forwarded to the linux audit system.

        Contributions from: Chris PeBenito, David Rheinsberg

        - Tübingen, 2020-09-04

## CHANGES WITH 23:

        * Expose supplementary groups as `UnixGroupIDs` as defined by the dbus
          specification in 0.53.

        * Fix an issue where the launcher incorrectly reported success even
          though it could not parse the bus configuration.

        * Fix an issue where the launcher was unnecessarily verbose about trying
          to start masked units. It will now only log once per unit.

        * Fix an issue where transient systemd unit names were not correctly
          escaped.

        * The broker now uses the peer-pid from `SO_PEERCRED` on the controller
          socket, rather than relying on `getppid()`. This allows creating the
          broker from intermediate processes without having any credentials of
          the intermediate leak into the broker.

        Contributions from: David Rheinsberg

        - Tübingen, 2020-05-11

## CHANGES WITH 22:

        * Implement org.freedesktop.DBus.Debug.Stats in the driver. This
          interface is defined by dbus-daemon and we use it similarly to expose
          internal state of the broker. For now, only the GetStats() call is
          supported, and it dumps the full accounting state to the caller.
          This will hopefully aid resource-debugging in the future.

        * Support no-op activation files. If neither a binary to execute, nor a
          service to activate, is specified, the service is expected to spawn
          via its own means (for instance spawned automatically during bootup,
          or activated via side-channels).

        * The new configuration option `linux-4-17`, if set to true (default is
          false), makes dbus-broker assume it runs on linux-v4.17 or newer. It
          will make use of features introduced up to linux-v4.17. This allows
          to forcibly disable workarounds for old kernels, where a feature
          detection at runtime is not possible.

          This option is meant to allow distributions to circumvent the
          workarounds, in case their setup does not work with them. Unless you
          have reason to set this option, it is safe to keep the default.

          Once the mandatory required kernel version of dbus-broker is bumped
          to v4.17, this option will default to `true` (an override to `false`
          will then no longer be allowed).

        * The `BecomeMonitor()` call now allows `eavesdrop={true|false}`
          attributes. This is required for compatibility with `dbus-monitor`,
          which always forcibly sets this attribute. Note that the attribute
          has no effect (nor meaning) when specified with `BecomeMonitor()`. It
          is completely ignored by dbus-broker.

        * The SELinux configuration parser is fixed regarding some wrongly
          placed assertions.

        * DBus socket handling is fixed to no longer fault on `MSG_CTRUNC`.
          Without this, clients can DoS dbus-broker, if, and only if, they can
          make the active LSM drop file-descriptors in a transmitted message
          due to policy denials. This has no effect if LSMs are not used.

        * Minor bugfixes all over the place, including fixes to build under
          musl libc.

        Contributions from: David Rheinsberg, Luca Boccassi, Tom Gundersen

        - Tübingen, 2020-02-17

## CHANGES WITH 21:

        * A handful of bugfixes for the launcher.

        Contributions from: David Rheinsberg, Tom Gundersen

        - Tübingen, 2019-05-02

## CHANGES WITH 20:

        * Major improvements in the logging infrastructure of the launcher.
          Messages are now directly forwarded to the journal and amended with
          additional fields. The journal-catalog now contains entries with
          background information on runtime log messages. Lastly, many of the
          log-messages were overhauled to be more descriptive.

        * The `c-sundry` submodule was dropped and replaced by `c-stdaux`. This
          is a much smaller project with a clearly stated goal. The old dumping
          gound `c-sundry` is no longer needed (remaining bits were moved into
          the dbus-broker codebase).

        Contributions from: David Herrmann, Tom Gundersen

        - Tübingen, 2019-04-10

## CHANGES WITH 19:

        * Fix a possible integer overflow in resource quota calculations.
          Before this, it was possible to exceed the assigned resource limits
          by crafting messages that trigger this integer overflow. This
          effectively allows machine-local resource exhaustion.

        * Fix the resource limit calculation. Previously, resource limits were
          incorrectly calculated, leading too limits that were higher than
          intended.

        Contributions from: David Herrmann, Tom Gundersen

        - Tübingen, 2019-03-28

## CHANGES WITH 18:

        * The handling of configuration parsing errors of the compatibility
          launcher is now aligned with dbus-daemon. This means, non-existant
          service files and file-system errors are now ignored and do not cause
          the launcher to refuse to start.

        * The compatibility launcher is no longer isolated in its own network
          namespace, since the SELinux APIs require access to the root network
          namespace. If you package the launcher with SELinux disabled, you can
          get back the old behavior by using `PrivateNetwork=true` in your dbus
          service file.

        Contributions from: David Herrmann, Tom Gundersen, Yanko Kaneti

        - Tübingen, 2019-02-20

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

        - Tübingen, 2019-01-01

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
