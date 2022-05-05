#
# Maintenance Scripts
#
# This Makefile contains a random selection of targets for easy development.
# They mostly serve as example how most of the build/test infrastructure is
# used. Feel free to adjust them to your needs.
#

all:
	@echo "Available targets:"
	@echo "    osi: Build test-container via mkosi"
	@echo "    run: Run test-container via nspawn"
	@echo "release: Print checklist for releases"
.PHONY: all

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
	@echo "       meson dist -C build --include-subprojects"
	@echo
	@echo " * Push tag via:"
	@echo "       git push <remote> v${VNEXT}"
	@echo " * Upload tarball to github via custom release"
	@echo
.PHONY: release
