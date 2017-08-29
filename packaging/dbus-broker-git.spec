%global _vpath_srcdir dbus-broker
%global _vpath_builddir build
%define build_date %(date +"%%a %%b %%d %%Y")
%define build_timestamp %(date +"%%Y%%m%%d.%%H%M%%S")

Name:           dbus-broker-git
Version:        1
Release:        %{build_timestamp}%{?dist}
Summary:        Linux D-Bus Message Broker
License:        ASL 2.0
URL:            https://github.com/bus1/dbus-broker
Requires:       dbus
BuildRequires:  expat-devel
BuildRequires:  glib2-devel
BuildRequires:  glibc-devel
BuildRequires:  git
BuildRequires:  libselinux-devel
BuildRequires:  python2-docutils
BuildRequires:  systemd-devel
BuildRequires:  meson, gcc
BuildRequires:  checkpolicy, selinux-policy-devel

%description
Linux D-Bus Message Broker

%prep
rm -rf dbus-broker
git clone --recurse-submodules https://github.com/bus1/dbus-broker.git
rm -rf %{_vpath_builddir}/docs
mkdir -p %{_vpath_builddir}/docs
rm -rf selinux
mkdir selinux
cp dbus-broker/selinux/dbus-broker.{te,fc} selinux/

%build
meson --prefix=/usr --buildtype=release "dbus-broker" "build"
%meson_build
rst2man %{_vpath_srcdir}/docs/dbus-broker-launch.rst %{_vpath_builddir}/docs/dbus-broker-launch.1
rst2man %{_vpath_srcdir}/docs/dbus-broker.rst %{_vpath_builddir}/docs/dbus-broker.1
cd selinux
make NAME=targeted -f /usr/share/selinux/devel/Makefile
cd -

%install
%meson_install
install -d %{buildroot}%{_mandir}/man1
install -p -m 644 %{_vpath_builddir}/docs/dbus-broker-launch.1 %{buildroot}%{_mandir}/man1/dbus-broker-launch.1
install -p -m 644 %{_vpath_builddir}/docs/dbus-broker.1 %{buildroot}%{_mandir}/man1/dbus-broker.1
install -d %{buildroot}%{_datadir}/selinux/targeted
install -p -m 644 selinux/dbus-broker.pp %{buildroot}%{_datadir}/selinux/targeted/dbus-broker.pp

%post
/usr/sbin/semodule -s targeted -i %{_datadir}/selinux/targeted/dbus-broker.pp
/sbin/fixfiles -R dbus-broker-git restore

%postun
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
