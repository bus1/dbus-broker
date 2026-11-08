# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: D-Bus Broker Developers

import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import unittest


NAME = "org.example.Alias"
LAUNCHER = os.environ.get("DBUS_BROKER_TEST_LAUNCHER", "dbus-broker-launch")


class ServiceAliases(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="dbus-broker-alias-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.root.chmod(0o755)
        self.first = self.root / "first"
        self.second = self.root / "second"
        self.first.mkdir()
        self.second.mkdir()
        self.source = self.first / (NAME + ".service")
        self.alias = self.second / self.source.name
        self.write_service(self.source)
        self.journal = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(self.journal.close)
        self.journal.bind("/run/systemd/journal/socket")
        self.addCleanup(os.unlink, "/run/systemd/journal/socket")
        os.chmod("/run/systemd/journal/socket", 0o666)
        self.journal.setblocking(False)
        self.messages = b""

    def write_service(self, path, name=NAME):
        path.write_text(f"[D-BUS Service]\nName={name}\nExec=/bin/false\n")
        path.chmod(0o644)

    def call(self, method):
        result = subprocess.run(
            ["busctl", "--address=" + self.address, "--timeout=5", "call",
             "org.freedesktop.DBus", "/org/freedesktop/DBus",
             "org.freedesktop.DBus", method],
            env=self.environment, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def start(self, uid=0):
        runtime = self.root / "runtime"
        runtime.mkdir(mode=0o700)
        os.chown(runtime, uid, uid)
        config = self.root / "bus.conf"
        config.write_text(
            "<busconfig><type>session</type>"
            f"<servicedir>{self.first}</servicedir>"
            f"<servicedir>{self.second}</servicedir>"
            '<policy context="default"><allow user="*"/>'
            '<allow own="*"/><allow send_destination="*"/>'
            '<allow receive_sender="*"/></policy></busconfig>'
        )
        config.chmod(0o644)
        self.environment = {
            "PATH": os.environ["PATH"],
            "HOME": str(runtime),
            "XDG_RUNTIME_DIR": str(runtime),
            "XDG_DATA_HOME": str(runtime),
            "XDG_DATA_DIRS": str(runtime),
            "XDG_CONFIG_HOME": str(runtime),
            "XDG_CONFIG_DIRS": str(runtime),
            "XDG_CACHE_HOME": str(runtime),
            "DBUS_SYSTEM_BUS_ADDRESS": "unix:path=" + str(runtime / "no-system-bus"),
        }
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        bus_path = runtime / "bus"
        listener.bind(str(bus_path))
        os.chown(bus_path, uid, uid)
        listener.listen()
        self.address = "unix:path=" + str(bus_path)
        pid = os.fork()
        if pid == 0:
            try:
                os.dup2(listener.fileno(), 3, inheritable=True)
                os.setgroups([])
                os.setgid(uid)
                os.setuid(uid)
                environment = dict(self.environment, LISTEN_PID=str(os.getpid()),
                                   LISTEN_FDS="1", LISTEN_FDNAMES="dbus.socket")
                os.execvpe(LAUNCHER, [LAUNCHER, "--scope=user",
                                    "--config-file=" + str(config)], environment)
            finally:
                os._exit(1)
        self.addCleanup(self.stop, pid)
        self.assertIn('"org.freedesktop.DBus"', self.call("ListActivatableNames"))

    def stop(self, pid):
        os.kill(pid, signal.SIGTERM)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)

    def logs(self):
        while True:
            try:
                self.messages += self.journal.recv(65536)
            except BlockingIOError:
                return self.messages.decode()

    def assert_registered(self, name=NAME):
        self.assertIn('"' + name + '"', self.call("ListActivatableNames"))

    def test_symlink_alias(self):
        self.alias.symlink_to(self.source)
        self.start()
        self.assert_registered()
        self.assertNotIn("Ignoring duplicate name", self.logs())

    def test_distinct_copy(self):
        shutil.copyfile(self.source, self.alias)
        self.start()
        self.assert_registered()
        self.assertIn("Ignoring duplicate name", self.logs())

    def test_hard_link(self):
        os.link(self.source, self.alias)
        self.start()
        self.assert_registered()
        self.assertIn("Ignoring duplicate name", self.logs())

    def test_reload_retargeted_alias(self):
        self.alias.symlink_to(self.source)
        self.start()
        self.assert_registered()
        self.assertNotIn("Ignoring duplicate name", self.logs())
        replacement = self.root / "replacement"
        self.write_service(replacement)
        self.alias.unlink()
        self.alias.symlink_to(replacement)
        self.call("ReloadConfig")
        self.assert_registered()
        self.assertIn("Ignoring duplicate name", self.logs())
        self.messages = b""
        self.alias.unlink()
        self.alias.symlink_to(self.source)
        self.call("ReloadConfig")
        self.assert_registered()
        self.assertNotIn("Ignoring duplicate name", self.logs())

    def test_reload_changed_source(self):
        self.alias.symlink_to(self.source)
        self.start()
        self.assert_registered()
        renamed = "org.example.Renamed"
        self.write_service(self.source, renamed)
        self.call("ReloadConfig")
        names = self.call("ListActivatableNames")
        self.assertIn('"' + renamed + '"', names)
        self.assertNotIn('"' + NAME + '"', names)
        self.assertIn("not named after", self.logs())
        self.assertIn("Ignoring duplicate name", self.logs())

    def protected_link(self):
        if Path("/proc/sys/fs/protected_symlinks").read_text().strip() != "1":
            self.skipTest("requires fs.protected_symlinks=1")
        self.second.chmod(0o1777)
        self.alias.symlink_to(self.source)
        os.lchown(self.alias, 1001, 1001)
        self.assertEqual(self.second.stat().st_uid, 0)
        self.assertEqual(self.alias.lstat().st_uid, 1001)

    def test_protected_alias(self):
        self.protected_link()
        self.start(uid=1002)
        self.assert_registered()
        self.assertIn("Read access denied for service file '" + str(self.alias), self.logs())
        self.assertNotIn("Ignoring duplicate name", self.logs())

    def test_matching_link_owner(self):
        self.protected_link()
        os.lchown(self.alias, 1002, 1002)
        self.start(uid=1002)
        self.assert_registered()
        self.assertNotIn("Read access denied", self.logs())
        self.assertNotIn("Ignoring duplicate name", self.logs())

    def test_protected_only_source(self):
        self.protected_link()
        self.source.rename(self.root / "target")
        self.alias.unlink()
        self.alias.symlink_to(self.root / "target")
        os.lchown(self.alias, 1001, 1001)
        self.start(uid=1002)
        self.assertNotIn('"' + NAME + '"', self.call("ListActivatableNames"))
        self.assertIn("Read access denied for service file '" + str(self.alias), self.logs())


if __name__ == "__main__":
    unittest.main()
