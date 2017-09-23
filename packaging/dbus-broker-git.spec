Name:           dbus-broker-git
Version:        99
Release:        1%{?dist}
Summary:        Linux D-Bus Message Broker
License:        ASL 2.0
URL:            https://github.com/bus1/dbus-broker
%{?systemd_requires}
BuildRequires:  pkgconfig(audit)
BuildRequires:  pkgconfig(expat)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(libselinux)
BuildRequires:  pkgconfig(libsystemd)
BuildRequires:  pkgconfig(systemd)
BuildRequires:  gcc
BuildRequires:  git
BuildRequires:  glibc-devel
BuildRequires:  meson
BuildRequires:  python2-docutils
Requires:       dbus
Conflicts:      dbus-broker

%description
Linux D-Bus Message Broker

%prep
rm -rf dbus-broker
git clone --recurse-submodules https://github.com/bus1/dbus-broker.git

%build
cd dbus-broker
%meson -Dselinux=true -Daudit=true
%meson_build

%install
cd dbus-broker
%meson_install

%check
cd dbus-broker
%meson_test

%post
%systemd_post dbus-broker.service

%preun
%systemd_preun dbus-broker.service

%postun
%systemd_postun dbus-broker.service

%files
%{_bindir}/dbus-broker
%{_bindir}/dbus-broker-launch
%{_mandir}/man1/dbus-broker.1*
%{_mandir}/man1/dbus-broker-launch.1*
%{_unitdir}/dbus-broker.service
%{_userunitdir}/dbus-broker.service

%changelog
* Tue Aug 29 2017 <teg@jklm.no> 1-1
- dbus-broker 1-1
