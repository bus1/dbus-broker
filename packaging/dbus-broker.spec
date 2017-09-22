%global c_dvar_version 1
%global c_list_version 3
%global c_rbtree_version 3
%global c_sundry_commit bdf6e5fcfd0c8bc956545ebf2855de36cab855b5

Name:           dbus-broker
Version:        4
Release:        1%{?dist}
Summary:        Linux D-Bus Message Broker
License:        ASL 2.0
URL:            https://github.com/bus1/dbus-broker
Source0:        https://github.com/bus1/dbus-broker/archive/v%{version}/dbus-broker-%{version}.tar.gz
Source1:        https://github.com/c-util/c-dvar/archive/v%{c_dvar_version}/c-dvar-%{c_dvar_version}.tar.gz
Source2:        https://github.com/c-util/c-list/archive/v%{c_list_version}/c-list-%{c_list_version}.tar.gz
Source3:        https://github.com/c-util/c-rbtree/archive/v%{c_rbtree_version}/c-rbtree-%{c_rbtree_version}.tar.gz
Source4:        https://github.com/c-util/c-sundry/archive/%{c_sundry_commit}/c-sundry-%{c_sundry_commit}.tar.gz
Provides:       bundled(c-dvar) = %{c_dvar_version}
Provides:       bundled(c-list) = %{c_list_version}
Provides:       bundled(c-rbtree) = %{c_rbtree_version}
%{?systemd_requires}
BuildRequires:  pkgconfig(audit)
BuildRequires:  pkgconfig(expat)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(libselinux)
BuildRequires:  pkgconfig(libsystemd)
BuildRequires:  pkgconfig(systemd)
BuildRequires:  gcc
BuildRequires:  glibc-devel
BuildRequires:  meson
BuildRequires:  python2-docutils
Requires:       dbus

%description
dbus-broker is an implementation of a message bus as defined by the D-Bus
specification. Its aim is to provide high performance and reliability, while
keeping compatibility to the D-Bus reference implementation. It is exclusively
written for Linux systems, and makes use of many modern features provided by
recent Linux kernel releases.

%prep
%autosetup
%setup -q -T -D -b 1
%setup -q -T -D -b 2
%setup -q -T -D -b 3
%setup -q -T -D -b 4
cd subprojects
rm * -r
ln -s ../../c-dvar-%{c_dvar_version} c-dvar
ln -s ../../c-list-%{c_list_version} c-list
ln -s ../../c-rbtree-%{c_rbtree_version} c-rbtree
ln -s ../../c-sundry-%{c_sundry_commit} c-sundry
cd -

%build
%meson -Dselinux=true -Daudit=true
%meson_build

%install
%meson_install

%check
%meson_test

%post
%systemd_post dbus-broker.service

%preun
%systemd_preun dbus-broker.service

%postun
%systemd_postun dbus-broker.service

%files
%license COPYING
%license LICENSE
%{_bindir}/dbus-broker
%{_bindir}/dbus-broker-launch
%{_mandir}/man1/dbus-broker.1*
%{_mandir}/man1/dbus-broker-launch.1*
%{_unitdir}/dbus-broker.service
%{_userunitdir}/dbus-broker.service

%changelog
* Fri Sep 08 2017 Tom Gundersen <teg@jklm.no> - 4-1
- Use audit for SELinux logging
- Support full search-paths for service files
- Log policy failures

* Fri Aug 18 2017 Tom Gundersen <teg@jklm.no> - 3-1
- Add manpages

* Wed Aug 16 2017 Tom Gundersen <teg@jklm.no> - 2-2
- Add license to package

* Wed Aug 16 2017 Tom Gundersen <teg@jklm.no> - 2-1
- Add SELinux support

* Sun Aug 13 2017 Tom Gundersen <teg@jklm.no> - 1-1
- Initial RPM release

