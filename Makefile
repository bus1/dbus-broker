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
	@echo "    coverity-scan:      Run a full analysis via Coverity"
	@echo "    coverity-upload:    Upload a Coverity analysis"
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
# Target: coverity-*
#

COVERITY_EMAIL		?= no-reply@example.com
COVERITY_PROJECT	?= dbus-broker
COVERITY_TOKEN		?=
COVERITY_URL_DOWN	?= https://scan.coverity.com/download/linux64
COVERITY_URL_UP		?= https://scan.coverity.com/builds

COVERITY_P_BASE		= $(BUILDDIR)/coverity

COVERITY_P_ANALYSIS	= $(COVERITY_P_BASE)/analysis.tar.gz
COVERITY_P_BUILD	= $(COVERITY_P_BASE)/build
COVERITY_P_INT		= $(COVERITY_P_BASE)/cov-int
COVERITY_P_MD5		= $(COVERITY_P_BASE)/coverity.md5
COVERITY_P_MD5SUM	= $(COVERITY_P_BASE)/coverity.md5sum
COVERITY_P_SCAN		= $(COVERITY_P_BASE)/scan
COVERITY_P_TAR		= $(COVERITY_P_BASE)/coverity.tar.gz

$(COVERITY_P_MD5): FORCE | $(COVERITY_P_BASE)/
	@echo -e "\033[33;1mcoverity: check for updates\033[0m"
	@COVERITY_MD5=$$( \
		curl \
			--data "token=$(COVERITY_TOKEN)&project=$(COVERITY_PROJECT)&md5=1" \
			--fail \
			--show-error \
			--silent \
			"$(COVERITY_URL_DOWN)" \
	) ; \
	if [[ \
		-e "$(COVERITY_P_MD5)" \
		&& $${COVERITY_MD5} == $$(cat "$(COVERITY_P_MD5)") \
	]] ; then \
		echo -e "\033[33;1mcoverity: cached version is up to date\033[0m" ; \
	else \
		echo -e "\033[33;1mcoverity: local version is missing or outdated\033[0m" ; \
		echo -n "$${COVERITY_MD5}" >"$(COVERITY_P_MD5)" ; \
		echo "$${COVERITY_MD5}  coverity.tar.gz" >"$(COVERITY_P_MD5SUM)" ; \
	fi ;

$(COVERITY_P_TAR): $(COVERITY_P_MD5)
	@echo -e "\033[33;1mcoverity: download analysis tool\033[0m"
	@curl \
		--data "token=$(COVERITY_TOKEN)&project=$(COVERITY_PROJECT)" \
		--fail \
		--output "$(COVERITY_P_TAR)" \
		"$(COVERITY_URL_DOWN)"
	@(cd "$(COVERITY_P_BASE)" && md5sum --check --status --strict "./coverity.md5sum")

$(COVERITY_P_SCAN): $(COVERITY_P_TAR)
	@echo -e "\033[33;1mcoverity: extract analysis tool\033[0m"
	@rm -rf "$(COVERITY_P_SCAN)"
	@mkdir -p "$@"
	@tar -xf "$(COVERITY_P_TAR)" --strip 1 -C "$(COVERITY_P_SCAN)"

.PHONY: coverity-scan
coverity-scan: $(COVERITY_P_SCAN)
	@echo -e "\033[33;1mcoverity: run full analysis\033[0m"
	@rm -rf "$(COVERITY_P_BUILD)" "$(COVERITY_P_INT)"
	@mkdir -p "$(COVERITY_P_BUILD)" "$(COVERITY_P_INT)"
	@meson \
		setup \
		--buildtype debugoptimized \
		--warnlevel 2 \
		-D debug=true \
		-D errorlogs=true \
		\
		-D apparmor=true \
		-D audit=true \
		-D launcher=true \
		-D selinux=true \
		-- \
		$(COVERITY_P_BUILD) \
		$(SRCDIR)
	@PATH="$(COVERITY_P_SCAN)/bin:${PATH}" cov-build \
		--dir $(COVERITY_P_INT) \
		meson compile -C $(COVERITY_P_BUILD)
	@PATH="$(COVERITY_P_SCAN)/bin:${PATH}" cov-import-scm \
		--dir $(COVERITY_P_INT) \
		--log $(COVERITY_P_INT)/scm_log.txt \
		--scm git
	@tar -czf "$(COVERITY_P_ANALYSIS)" -C "$(COVERITY_P_BASE)" "./cov-int"
	@rm -rf "$(COVERITY_P_BUILD)" "$(COVERITY_P_INT)"

.PHONY: coverity-upload
coverity-upload: | $(COVERITY_P_ANALYSIS)
	@echo -e "\033[33;1mcoverity: upload analysis\033[0m"
	@curl \
		--fail \
		--form "description=automated build" \
		--form "email=$(COVERITY_EMAIL)" \
		--form "file=@$(COVERITY_P_ANALYSIS)" \
		--form "project=$(COVERITY_PROJECT)" \
		--form "token=$(COVERITY_TOKEN)" \
		--form "version=$$(git rev-parse --short HEAD)" \
		"$(COVERITY_URL_UP)"

#
# Target: meson-*
#

MESON_SETUP		= \
	meson \
		setup \
		--buildtype "debugoptimized" \
		--reconfigure \
		--warnlevel "2" \
		-D "debug=true" \
		-D "errorlogs=true" \
		\
		-D "apparmor=true" \
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

.PHONY: meson-setup
meson-setup-32: | $(BUILDDIR)/
	CFLAGS="-m32" \
	PKG_CONFIG_LIBDIR="/usr/lib32/pkgconfig:/usr/share/pkgconfig" \
	RUSTFLAGS="--target i686-unknown-linux" \
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
