#
# dbrk-fedora - Fedora Test Image for DBus Broker
#
# A small Fedora-based image with dbus-broker included from a new build. Easy
# way to test changes to dbus-broker on a real Fedora boot.
#
# Arguments:
#
#   * DBRK_FROM="ghcr.io/bus1/dbrk-fedora-base:latest"
#       This controls the host container used as base for the image.
#

ARG             DBRK_FROM="ghcr.io/bus1/dbrk-fedora-base:latest"
FROM            "${DBRK_FROM}" AS target

#
# Import our build sources and prepare the target environment. When finished,
# we drop the build sources again, to keep the target layers small.
#

WORKDIR         /dbrk
COPY            . src

WORKDIR         /dbrk/build
RUN             meson setup \
                        --prefix=/usr \
                        -Daudit=true \
                        -Dselinux=true \
                        . ../src
RUN             meson compile
RUN             meson test
RUN             meson install

WORKDIR         /dbrk/home
RUN             rm -rf /dbrk/src /dbrk/build
