#
# Maintenance Scripts
#
# This Makefile contains a random selection of targets for easy development.
# They mostly serve as example how most of the build/test infrastructure is
# used. Feel free to adjust them to your needs.
#

#
# The gcc warning sets -Wall and -Wextra enable some annoying warnings, which
# we really do not care about. Disable them here.
#
MYCFLAGS= \
	-Wno-unused-parameter \
	-Wno-maybe-uninitialized

all:
	@echo "Available targets:"
	@echo "  meson: Generate build files via meson"
	@echo "  ninja: Build project via ninja"
	@echo "   test: Run test suite via ninja"
	@echo "    osi: Build test-container via mkosi"
	@echo "    run: Run test-container via nspawn"
.PHONY: all

meson:
	rm -Rf ./mybuild
	CFLAGS="${MYCFLAGS} $$CFLAGS" \
		meson \
			./mybuild \
			--prefix /usr \
			--buildtype debugoptimized \
			--warnlevel 2
.PHONY: meson

ninja:
	ninja \
		-C ./mybuild
.PHONY: ninja

test:
	ninja \
		-C ./mybuild \
		test
.PHONY: test

osi:
	mkosi -C test/osi/
.PHONY: osi

run:
	systemd-nspawn \
		-b \
		-D test/osi/rootfs/ \
		--bind-ro "$$PWD/mybuild/src/dbus-broker:/usr/bin/dbus-broker" \
		--bind-ro "$$PWD/mybuild/src/dbus-broker-launch:/usr/bin/dbus-broker-launch"
.PHONY: run
