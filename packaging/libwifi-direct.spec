Name:       libwifi-direct
Summary:    wifi direct library (Shared Library)
Version:    0.3.1
Release:    1
Group:      TO_BE_FILLED
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(vconf)

BuildRequires:  cmake
BuildRequires:  gettext-devel

#%define debug_package %{nil}  

%description
wifi direct library (Shared Library)


%package devel 
Summary:    wifi direct library (Shared Library) (Developement)
Group:      TO_BE_FILLED 
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
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}
#make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install
%__strip %{buildroot}%{_libdir}/libwifi-direct.so.0.0

mkdir -p %{buildroot}/usr/share/license
cp %{_builddir}/%{buildsubdir}/LICENSE %{buildroot}/usr/share/license/%{name}

%post

%postun


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

