%global build_date %(date +"%%a %%b %%d %%Y")
%global build_timestamp %(date +"%%Y%%m%%d.%%H%M%%S")

Name:           dbus-broker-git
Version:        1
Release:        %{build_timestamp}%{?dist}
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
BuildRequires:  glibc-devel
BuildRequires:  meson
BuildRequires:  python2-docutils
BuildRequires:  checkpolicy, selinux-policy-devel
Requires:       dbus

%description
Linux D-Bus Message Broker

%prep
rm -rf dbus-broker
git clone --recurse-submodules https://github.com/bus1/dbus-broker.git
cd dbus-broker
rm -rf %{_vpath_builddir}/docs
mkdir -p %{_vpath_builddir}/docs
rm -rf %{_vpath_builddir}/selinux
mkdir -p %{_vpath_builddir}/selinux
cp %{_vpath_srcdir}/selinux/dbus-broker.{te,fc} %{_vpath_builddir}/selinux/

%build
cd dbus-broker
%meson
mesonconf -Dselinux=true -Daudit=true %{_vpath_builddir}
%meson_build
rst2man %{_vpath_srcdir}/docs/dbus-broker-launch.rst %{_vpath_builddir}/docs/dbus-broker-launch.1
rst2man %{_vpath_srcdir}/docs/dbus-broker.rst %{_vpath_builddir}/docs/dbus-broker.1
cd %{_vpath_builddir}/selinux
make NAME=targeted -f /usr/share/selinux/devel/Makefile
cd -

%install
cd dbus-broker
%meson_install
install -d %{buildroot}%{_mandir}/man1
install -p -m 644 %{_vpath_builddir}/docs/dbus-broker-launch.1 %{buildroot}%{_mandir}/man1/dbus-broker-launch.1
install -p -m 644 %{_vpath_builddir}/docs/dbus-broker.1 %{buildroot}%{_mandir}/man1/dbus-broker.1
install -d %{buildroot}%{_datadir}/selinux/targeted
install -p -m 644 %{_vpath_builddir}/selinux/dbus-broker.pp %{buildroot}%{_datadir}/selinux/targeted/dbus-broker.pp

%post
/usr/sbin/semodule -s targeted -i %{_datadir}/selinux/targeted/dbus-broker.pp
/sbin/fixfiles -R %{name} restore
%systemd_post dbus-broker.service

%preun
%systemd_preun dbus-broker.service

%postun
%systemd_postun dbus-broker.service
if [ $1 -eq 0 ] ; then
  /usr/sbin/semodule -s targeted -r dbus-broker
fi

%files
%{_bindir}/dbus-broker
%{_bindir}/dbus-broker-launch
%{_datadir}/selinux/*/dbus-broker.pp
%{_mandir}/man1/dbus-broker.1*
%{_mandir}/man1/dbus-broker-launch.1*
%{_unitdir}/dbus-broker.service
%{_userunitdir}/dbus-broker.service

%changelog
* Tue Aug 29 2017 <teg@jklm.no> 1-1
- dbus-broker 1-1
