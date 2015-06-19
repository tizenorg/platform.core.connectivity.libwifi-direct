Name:       libwifi-direct
Summary:    Wifi Direct Library
Version:    1.2.33
Release:    1
Group:      Network & Connectivity/Wireless 
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
BuildRequires:  cmake
BuildRequires:  gettext-devel

%description
wifi direct library (Shared Library)


%prep
%setup -q

%ifarch %{arm}
export ARCH=arm
%else
export ARCH=i586
%endif

%install
rm -rf %{buildroot}

mkdir -p %{buildroot}/usr/share/license
cp %{_builddir}/%{buildsubdir}/LICENSE.APLv2 %{buildroot}/usr/share/license/%{name}

%files
/usr/share/license/%{name}
