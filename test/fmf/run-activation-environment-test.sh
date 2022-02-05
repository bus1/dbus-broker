#!/bin/bash

set -e

busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus UpdateActivationEnvironment a{ss} 1 "KEY" "VALUE" --user
busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus UpdateActivationEnvironment a{ss} 1 "KEY2" "VALUE2" --user
systemctl show-environment --user | grep "KEY=VALUE"
systemctl show-environment --user | grep "KEY2=VALUE2"
busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus UpdateActivationEnvironment a{ss} 1 "KEY2" "VALUE2B" --user
systemctl show-environment --user | grep "KEY2=VALUE2B"
