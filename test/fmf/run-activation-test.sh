#!/bin/bash

set -e

busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus StartServiceByName su "org.freedesktop.systemd1" 0 --user

busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus StartServiceByName su "org.freedesktop.systemd1" 0 --system
