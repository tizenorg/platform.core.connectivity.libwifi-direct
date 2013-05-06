Name:       libwifi-direct
Summary:    wifi direct library
Version:    0.3.7
Release:    1
Group:      Connectivity/Wireless
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  cmake
BuildRequires:  gettext-devel
%description
wifi direct library (Shared Library)

%package devel 
Summary:    wifi direct library (Shared Library) (Developement)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
wifi direct library (Shared Library) (Developement)

%prep
%setup -q

%ifarch %{arm}
export ARCH=arm
%else
export ARCH=i586
%endif

%build
%cmake .

%install
%make_install

mkdir -p %{buildroot}/usr/share/license
cp %{_builddir}/%{buildsubdir}/LICENSE.APLv2 %{buildroot}/usr/share/license/%{name}

%files
%manifest libwifi-direct.manifest
%defattr(-,root,root,-)
%{_libdir}/libwifi-direct.so
%{_libdir}/libwifi-direct.so.0
%{_libdir}/libwifi-direct.so.0.0
/usr/share/license/%{name}

%files devel 
%defattr(-,root,root,-)
%{_libdir}/pkgconfig/wifi-direct.pc
%{_includedir}/wifi-direct/wifi-direct.h
%{_includedir}/wifi-direct/wifi-direct-internal.h
