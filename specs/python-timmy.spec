%{!?__python2: %global __python2 /usr/bin/python2}
%{!?python2_sitelib: %global python2_sitelib %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}
%{!?python2_sitearch: %global python2_sitearch %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib(1))")}
%endif

%define name python-timmy
%{!?version: %define version 1.8.1}
%{!?release: %define release 1}

Summary:    Console utility for collecting cluster information
Name:       %{name}
Version:    %{version}
Release:    %{release}
Source0:    %{name}-%{version}.tar.gz
License:    Apache
Group:      Support/Tools
BuildRoot:  %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix:     %{_prefix}

BuildArch:  noarch

BuildRequires: python-setuptools

%if 0%{!?rhel:0} == 6
Requires: python-argparse
%endif

Requires: PyYAML

%description
Summary: Console utility for collecting cluster information

%prep
%setup -cq -n %{name}-%{version}

%build
cd %{_builddir}/%{name}-%{version} && %{__python2} setup.py build

%install
rm -rf $RPM_BUILD_ROOT
cd %{_builddir}/%{name}-%{version} && %{__python2} setup.py install --single-version-externally-managed -O1 --root=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT
