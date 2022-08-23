#
# Maintenance Scripts
#
# This Makefile contains a random selection of targets for easy development.
# They mostly serve as example how most of the build/test infrastructure is
# used. Feel free to adjust them to your needs.
#

all:
	@echo "Available targets:"
	@echo "release: Print checklist for releases"
	@echo " fedpkg: Print checklist for fedora packaging"
.PHONY: all

VNEXT=2
VPREV="$$((${VNEXT} - 1))"
release:
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
.PHONY: release

fedpkg:
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
