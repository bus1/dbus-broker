%define build_date %(date +"%%a %%b %%d %%Y")
%define build_timestamp %(date +"%%Y%%m%%d.%%H%M%%S")

Name:           dbus-broker
Version:        1
Release:        %{build_timestamp}%{?dist}
Summary:        Linux D-Bus Message Broker
License:        ASL2.0
URL:            https://github.com/bus1/dbus-broker
Source0:        https://github.com/bus1/dbus-broker/archive/v%{version}.tar.gz
BuildRequires:  expat-devel
BuildRequires:  glib2-devel
BuildRequires:  glibc-devel
BuildRequires:  git
BuildRequires:  libselinux-devel
BuildRequires:  meson
BuildRequires:  ninja-build
BuildRequires:  systemd-devel
BuildRequires:  checkpolicy, selinux-policy-devel, /usr/share/selinux/devel/policyhelp

%description
Linux D-Bus Message Broker

%prep
%setup -q

%build
git clone --recurse-submodules https://github.com/bus1/dbus-broker.git
meson --prefix=/usr --buildtype=release "dbus-broker" "build"
ninja -v -C "build"
mkdir build/selinux
cp selinux/dbus-broker.{te,fc} build/selinux/
cd build/selinux
make NAME=targeted -f /usr/share/selinux/devel/Makefile
cd -

%install
DESTDIR=$RPM_BUILD_ROOT ninja -v -C "build" install
install -d %{buildroot}%{_datadir}/selinux/targeted
install -p -m 644 build/selinux/dbus-broker.pp %{buildroot}%{_datadir}/selinux/targeted/dbus-broker.pp

%post
/usr/sbin/semodule -s targeted -i %{_datadir}/selinux/targeted/dbus-broker.pp
/sbin/fixfiles -R dbus-broker restore

%postun
if [ $1 -eq 0 ] ; then
  /usr/sbin/semodule -s targeted -r dbus-broker
fi

%files
#%license AUTHORS
#%license COPYRIGHT
#%license LICENSE
%{_bindir}/dbus-broker
%{_bindir}/dbus-broker-launch
%{_datadir}/selinux/*/dbus-broker.pp
%{_unitdir}/%{name}.service
%{_userunitdir}/%{name}.service

%changelog
* %{build_date} <teg@jklm.no> %{version}-%{build_timestamp}
- %{name} %{version}
