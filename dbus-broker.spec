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

%description
Linux D-Bus Message Broker

%prep
%setup -q

%build
git clone --recurse-submodules https://github.com/bus1/dbus-broker.git
meson --prefix=/usr --buildtype=release "dbus-broker" "build"
ninja -v -C "build"

%install
DESTDIR=$RPM_BUILD_ROOT ninja -v -C "build" install

%files
#%license AUTHORS
#%license COPYRIGHT
#%license LICENSE
%{_bindir}/dbus-broker
%{_bindir}/dbus-broker-launch
%{_unitdir}/%{name}.service
%{_userunitdir}/%{name}.service

%changelog
* %{build_date} <teg@jklm.no> %{version}-%{build_timestamp}
- %{name} %{version}
