#
# Maintenance Scripts
#
# This Makefile contains a random selection of targets for easy development.
# They mostly serve as example how most of the build/test infrastructure is
# used. Feel free to adjust them to your needs.
#

#
# The gcc warning-sets -Wall and -Wextra enable some annoying warnings, which
# we really do not care about. Disable them here. Additionally, add some
# warnings that we consider mandatory for our code-base.
#
MYCFLAGS= \
	-Wno-unused-parameter \
	-Wno-maybe-uninitialized \
	-Wno-pointer-arith \
	-Wno-unknown-warning-option \
	\
	-Wundef \
	-Wlogical-op \
	-Wmissing-include-dirs \
	-Wold-style-definition \
	-Wdeclaration-after-statement \
	-Wfloat-equal \
	-Wsuggest-attribute=noreturn \
	-Wstrict-prototypes \
	-Wredundant-decls \
	-Wmissing-noreturn \
	-Wshadow \
	-Wendif-labels \
	-Wstrict-aliasing=3 \
	-Wwrite-strings \
	-Wdate-time \
	-Wnested-externs \
	-Werror=overflow \
	-Werror=missing-prototypes \
	-Werror=implicit-function-declaration \
	-Werror=missing-declarations \
	-Werror=return-type \
	-Werror=incompatible-pointer-types

BUILDDIR?="$$PWD/mybuild"

all:
	@echo "Available targets:"
	@echo "  meson: Generate build files via meson"
	@echo "  ninja: Build project via ninja"
	@echo "   test: Run test suite via ninja"
	@echo "    osi: Build test-container via mkosi"
	@echo "    run: Run test-container via nspawn"
	@echo "release: Print checklist for releases"
.PHONY: all

meson:
	rm -Rf ${BUILDDIR}
	CFLAGS="${MYCFLAGS} $$CFLAGS" \
		meson \
			${BUILDDIR} \
			--prefix /usr \
			--buildtype debugoptimized \
			--warnlevel 2 \
			-Dlauncher=false \
			${MESONFLAGS}
.PHONY: meson

ninja:
	ninja \
		-C ${BUILDDIR} \
		${NINJAFLAGS}
.PHONY: ninja

docs:
	mkdir -p ${BUILDDIR}/docs
	rst2man docs/dbus-broker-launch.rst ${BUILDDIR}/docs/dbus-broker-launch.1
	rst2man docs/dbus-broker.rst ${BUILDDIR}/docs/dbus-broker.1
.PHONY: docs

test:
	ninja \
		-C ${BUILDDIR} \
		${NINJAFLAGS} \
		test
.PHONY: test

osi:
	mkosi \
		-C test/osi/ \
		--build-sources "../../" \
		--force
.PHONY: osi

run:
	systemd-nspawn \
		-b \
		-D test/osi/rootfs/ \
		--bind-ro "${BUILDDIR}/src/dbus-broker:/usr/bin/dbus-broker" \
		--bind-ro "${BUILDDIR}/src/dbus-broker-launch:/usr/bin/dbus-broker-launch"
.PHONY: run

VNEXT=2
VPREV="$$((${VNEXT} - 1))"
release:
	@echo "Checklist for release of dbus-broker-${VNEXT}:"
	@echo
	@echo " * Fill in NEWS via:"
	@echo "       git log v${VPREV}..HEAD"
	@echo " * List contributors in NEWS via:"
	@echo "       git log --format='%an, ' v${VPREV}..HEAD | sort -u | tr -d '\n'"
	@echo " * Bump project.version in ./meson.build"
	@echo
	@echo " * Commit and push at least once"
	@echo
	@echo " * Tag 'v${VNEXT}' with content 'dbus-broker ${VNEXT}' via:"
	@echo "       git tag -s -m 'dbus-broker ${VNEXT}' v${VNEXT} HEAD"
	@echo " * Create tarball via: (VERIFY YOU HAVE v${VNEXT} CHECKED OUT!)"
	@echo "       git archive-all -v --prefix dbus-broker-${VNEXT}/ dbus-broker-${VNEXT}.tar"
	@echo "       xz dbus-broker-${VNEXT}.tar"
	@echo
	@echo " * Build and test tarball"
	@echo
	@echo " * Push tag via:"
	@echo "       git push <remote> v${VNEXT}"
	@echo " * Upload tarball to github via custom release"
	@echo
.PHONY: release
