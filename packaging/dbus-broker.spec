%global c_dvar_commit 7706828ecda2d8c508d6fc233dc9d198bab482ad
%global c_list_commit 9e50b8b08e0b0b75e1c651d5aa4e3cf94368a574
%global c_rbtree_commit 6181232360c9b517a6af3d82ebdbdce5fe36933a
%global c_sundry_commit 50c8ccf01b39b3f11e59c69d1cafea5bef5a9769

Name:           dbus-broker
Version:        5
Release:        1%{?dist}
Summary:        Linux D-Bus Message Broker
License:        ASL 2.0
URL:            https://github.com/bus1/dbus-broker
Source0:        https://github.com/bus1/dbus-broker/archive/v%{version}/dbus-broker-%{version}.tar.gz
Source1:        https://github.com/c-util/c-dvar/archive/%{c_dvar_commit}/c-dvar-%{c_dvar_commit}.tar.gz
Source2:        https://github.com/c-util/c-list/archive/%{c_list_commit}/c-list-%{c_list_commit}.tar.gz
Source3:        https://github.com/c-util/c-rbtree/archive/%{c_rbtree_commit}/c-rbtree-%{c_rbtree_commit}.tar.gz
Source4:        https://github.com/c-util/c-sundry/archive/%{c_sundry_commit}/c-sundry-%{c_sundry_commit}.tar.gz
Provides:       bundled(c-dvar) = 1
Provides:       bundled(c-list) = 3
Provides:       bundled(c-rbtree) = 3
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
ln -s ../../c-dvar-%{c_dvar_commit} c-dvar
ln -s ../../c-list-%{c_list_commit} c-list
ln -s ../../c-rbtree-%{c_rbtree_commit} c-rbtree
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
* Tue Oct 10 2017 Tom Gundersen <teg@jklm.no> - 5-1
- Drop downstream SELinux module
- Support (in a limited way) at_console= policies
- Order dbus-broker before basic.target

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

