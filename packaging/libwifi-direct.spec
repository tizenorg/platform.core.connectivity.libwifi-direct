Name:       libwifi-direct
Summary:    wifi direct library (Shared Library)
Version:    0.2.11
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

%ifarch %{arm}
Provides: libbcmp2p.so
Provides: libbcmp2papp.so
Provides: libwpscli.so
Provides: libbcmp2psig.so
Provides: wfd-manager
Provides: wifi-direct-plugin-broadcom.so
%endif



%package devel 
Summary:    wifi direct library (Shared Library) (Developement)
Group:      TO_BE_FILLED 
Requires:   %{name} = %{version}-%{release}

%description devel
wifi direct library (Shared Library) (Developement)

%prep
%setup -q

%ifarch %{arm}
%define ARCH arm
%else
%define ARCH i586 
%endif

%build
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix} -DARCH=%{ARCH}
#make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install
%__strip %{buildroot}%{_libdir}/libwifi-direct.so.0.0

%post

%postun


%files
%defattr(-,root,root,-)
%{_libdir}/libwifi-direct.so
%{_libdir}/libwifi-direct.so.0
%{_libdir}/libwifi-direct.so.0.0

%ifarch %{arm}
/usr/etc/wifi-direct/dhcpd.p2p.conf
/usr/etc/wifi-direct/dhcpd.wl0.conf
/usr/etc/wifi-direct/dhcpd.eth.conf
/usr/etc/wifi-direct/udhcp_script.non-autoip
%{_bindir}/dhcpd-notify.sh
%{_bindir}/wifi-direct-server.sh
%{_bindir}/wifi-direct-dhcp.sh

%{_bindir}/wfd-manager
%{_libdir}/wifi-direct-plugin-broadcom.so
%{_libdir}/libbcmp2p.so
%{_libdir}/libbcmp2papp.so
%{_libdir}/libbcmp2psig.so
%{_libdir}/libwpscli.so

%attr(755,-,-) %{_bindir}/wfd-manager
%attr(755,-,-) %{_bindir}/dhcpd-notify.sh
%attr(755,-,-) %{_bindir}/wifi-direct-server.sh
%attr(755,-,-) %{_bindir}/wifi-direct-dhcp.sh
%attr(755,-,-) /usr/etc/wifi-direct/udhcp_script.non-autoip

%endif


%files devel 
%defattr(-,root,root,-)
%{_libdir}/pkgconfig/wifi-direct.pc
%{_includedir}/wifi-direct/wifi-direct.h
%{_includedir}/wifi-direct/wifi-direct-internal.h

