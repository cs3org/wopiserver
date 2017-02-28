#
# cernbox-wopi-server spec file
#
Name:      cernbox-wopi-server
Summary:   A WOPI server to support Microsoft Office online on CERNBox
Version:   1.0
Release:   2%{?dist}
License:   GPLv3
Buildroot: %{_tmppath}/%{name}-buildroot
Group:     CERN-IT/ST
BuildArch: noarch
Source: %{name}-%{version}.tar.gz

# The required Python version makes this package depend on at least CentOS 7 to compile and run.
BuildRequires: python >= 2.7
Requires: python >= 2.7, python-flask, python-jwt, xrootd-python
# The following to avoid to pick up /bin/python as an automatic dependency
AutoReq: no

%description
This RPM provides a Flask-based web server to implement the Microsoft WOPI protocol for CERNBox

# Don't do any post-install weirdness, especially compiling .py files
%define __os_install_post %{nil}

# Get the python lib directory
%define _python_lib %(python -c "from distutils import sysconfig; print sysconfig.get_python_lib()")

%prep
%setup -n %{name}-%{version}

%install
# server versioning
sed -i "s/WOPISERVERVERSION = 'git'/WOPISERVERVERSION = '%{version}'/" src/wopiserver.py
# installation
rm -rf %buildroot/
mkdir -p %buildroot/usr/bin
mkdir -p %buildroot/%_python_lib
mkdir -p %buildroot/etc/wopi
mkdir -p %buildroot/etc/logrotate.d
mkdir -p %buildroot/usr/lib/systemd/system
mkdir -p %buildroot/var/log/cernbox
install -m 755 src/wopiserver.py     %buildroot/usr/bin/wopiserver.py
install -m 755 src/wopicheckfile.py  %buildroot/usr/bin/wopicheckfile.py
install -m 644 src/xrootiface.py     %buildroot/%_python_lib/xrootiface.py
install -m 644 wopiserver.service    %buildroot/usr/lib/systemd/system/wopiserver.service
install -m 644 wopiserver.conf       %buildroot/etc/wopi/wopiserver.defaults.conf
install -m 644 wopiserver.logrotate  %buildroot/etc/logrotate.d/cernbox-wopi-server

%clean
rm -rf %buildroot/

%preun

%post
# enable listening on port < 1024: unfortunately we have to do it on the python binary...
setcap 'cap_net_bind_service=+ep' /usr/bin/python2.7
touch /etc/wopi/wopisecret
touch /etc/wopi/ocsecret

%files
%defattr(-,root,root,-)
/etc/wopi
/etc/logrotate.d/cernbox-wopi-server
%attr(-,cboxwopi,def-cg) /var/log/cernbox
/usr/lib/systemd/system/wopiserver.service
/usr/bin/*
%_python_lib/*

%changelog
* Fri Feb 24 2017 Giuseppe Lo Presti <lopresti@cern.ch> 1.0
- First official release for internal deployment after first round of tests
* Fri Feb 17 2017 Giuseppe Lo Presti <lopresti@cern.ch> 0.4
- Release for pre-production tests including https, download URL and minor fixes
* Tue Feb 14 2017 Giuseppe Lo Presti <lopresti@cern.ch> 0.3
- Added the Locking interface and PutRelative, RenameFile, DeleteFile
- Refined the /cbox API to interact with OwnCloud
* Wed Jan 18 2017 Giuseppe Lo Presti <lopresti@cern.ch> 0.2
- First complete version for test deployment with eosbackup
* Thu Jan  5 2017 Giuseppe Lo Presti <lopresti@cern.ch> 0.1
- First packaging for the WOPI server prototype

