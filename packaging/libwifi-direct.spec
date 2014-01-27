Name:       libwifi-direct
Summary:    Wifi Direct Library
Version:    1.0.7
Release:    1
Group:      Network & Connectivity/Wireless 
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: 	libwifi-direct.manifest
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  cmake
BuildRequires:  gettext-devel

%description
wifi direct library (Shared Library)

%package devel 
Summary:    Wifi Direct Library (Shared Library) (Development)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
wifi direct library (Shared Library) (Development)

%prep
%setup -q
cp %{SOURCE1001} .

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


%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_libdir}/libwifi-direct.so
%{_libdir}/libwifi-direct.so.0
%{_libdir}/libwifi-direct.so.0.0
/usr/share/license/%{name}

%files devel 
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_libdir}/pkgconfig/wifi-direct.pc
%{_includedir}/wifi-direct/wifi-direct.h
%{_includedir}/wifi-direct/wifi-direct-internal.h
