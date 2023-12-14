#
# Maintenance Scripts
#
# This Makefile contains a random selection of targets for easy development.
# They mostly serve as example how most of the build/test infrastructure is
# used. Feel free to adjust them to your needs.
#

# Enforce bash with fatal errors.
SHELL			:= /bin/bash -eo pipefail

# Keep intermediates around on failures for better caching.
.SECONDARY:

# Default build and source directories.
BUILDDIR		?= ./build
SRCDIR			?= .

#
# Target: help
#

.PHONY: help
help:
	@# 80-width marker:
	@#     01234567012345670123456701234567012345670123456701234567012345670123456701234567
	@echo "make [TARGETS...]"
	@echo
	@echo "The following targets are provided by this maintenance makefile:"
	@echo
	@echo "    help:               Print this usage information"
	@echo
	@echo "    release-fedora:     Print checklist for Fedora releases"
	@echo "    release-github:     Print checklist for Github releases"
	@echo
	@echo "    meson-build:        Build the Meson-based project"
	@echo "    meson-setup:        Reconfigure the Meson setup"
	@echo "    meson-test:         Run the Meson-based test suite"
	@echo
	@echo "    system-build:       Build system test-image"
	@echo "    system-run:         Run system test-image"

#
# Target: BUILDDIR
#

$(BUILDDIR)/:
	mkdir -p "$@"

$(BUILDDIR)/%/:
	mkdir -p "$@"

#
# Target: FORCE
#
# Used as alternative to `.PHONY` if the target is not fixed.
#

.PHONY: FORCE
FORCE:

#
# Target: meson-*
#

MESON_SETUP		= \
	meson \
		setup \
		--buildtype "debugoptimized" \
		--reconfigure \
		--warnlevel "2" \
		-D "audit=true" \
		-D "docs=true" \
		-D "launcher=true" \
		-- \
		$(BUILDDIR)/meson \
		$(SRCDIR)

$(BUILDDIR)/meson/: | $(BUILDDIR)/
	$(MESON_SETUP)

.PHONY: meson-build
meson-build: $(BUILDDIR)/meson/
	meson \
		compile \
		-C "$(BUILDDIR)/meson/"

.PHONY: meson-setup
meson-setup: | $(BUILDDIR)/
	$(MESON_SETUP)

.PHONY: meson-test
meson-test: $(BUILDDIR)/meson/
	meson \
		test \
		--print-errorlogs \
		-C "$(BUILDDIR)/meson/"

#
# Target: release-*
#

VNEXT=2
VPREV="$$((${VNEXT} - 1))"

.PHONY: release-fedora
release-fedora:
	@echo "Checklist for Fedora releases (for each branch):"
	@echo
	@echo " * Fetch Kerberos ticket:"
	@echo "       kinit <fas>@FEDORAPROJECT.ORG"
	@echo
	@echo " * Edit and Update dbus-broker.spec"
	@echo
	@echo " * Pull new sources:"
	@echo "       curl -O dbus-broker-${VNEXT}.tar.xz https://github.com/bus1/dbus-broker/releases/download/v${VNEXT}/dbus-broker-${VNEXT}.tar.xz"
	@echo " * Push new sources:"
	@echo "       fedpkg new-sources dbus-broker-${VNEXT}.tar.xz"
	@echo
	@echo " * Commit and push at least once"
	@echo
	@echo " * Submit build to Koji:"
	@echo "       fedpkg build"
	@echo
	@echo " * Submit update to Bodhi"
	@echo

.PHONY: release-github
release-github:
	@echo "Checklist for release of dbus-broker-${VNEXT}:"
	@echo
	@echo " * Update subprojects via:"
	@echo "       meson subprojects update"
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
	@echo "       meson dist -C build --include-subprojects"
	@echo " * Sign tarball via:"
	@echo "       gpg --armor --detach-sign \"./build/meson-dist/dbus-broker-${VNEXT}.tar.xz\""
	@echo
	@echo " * Push tag via:"
	@echo "       git push <remote> v${VNEXT}"
	@echo " * Upload tarball to github via custom release"
	@echo

#
# Target: system-*
#

.PHONY: system-build
system-build:
	podman \
		build \
		--file "$(SRCDIR)/test/image/dbrk-fedora.Dockerfile" \
		--tag "dbrk-fedora" \
		-- \
		"$(SRCDIR)"

.PHONY: system-run
system-run:
	podman \
		run \
		--interactive \
		--rm \
		--tty \
		"dbrk-fedora"
