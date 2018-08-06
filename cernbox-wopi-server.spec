#
# cernbox-wopi-server spec file
#
Name:      cernbox-wopi-server
Summary:   A WOPI server to support Microsoft Office online on CERNBox
Version:   2.8
Release:   1%{?dist}
License:   GPLv3
Buildroot: %{_tmppath}/%{name}-buildroot
Group:     CERN-IT/ST
BuildArch: noarch
Source: %{name}-%{version}.tar.gz

# The required Python version makes this package depend on at least CentOS 7 to compile and run.
BuildRequires: python >= 2.7
Requires: python >= 2.7, python-flask, python-jwt, python2-xrootd, pyOpenSSL
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
sed -i "s/WOPISERVERVERSION = 'git'/WOPISERVERVERSION = '%{version}-%{release}'/" src/wopiserver.py
# installation
rm -rf %buildroot/
mkdir -p %buildroot/usr/bin
mkdir -p %buildroot/%_python_lib
mkdir -p %buildroot/etc/wopi
mkdir -p %buildroot/etc/logrotate.d
mkdir -p %buildroot/etc/nginx/conf.d
mkdir -p %buildroot/etc/uwsgi.d
mkdir -p %buildroot/usr/lib/systemd/system
mkdir -p %buildroot/var/log/wopi
install -m 755 src/wopiserver.py     %buildroot/usr/bin/wopiserver.py
install -m 755 src/wopicheckfile.py  %buildroot/usr/bin/wopicheckfile.py
install -m 755 src/wopilistopenfiles.sh %buildroot/usr/bin/wopilistopenfiles.sh
install -m 644 src/xrootiface.py     %buildroot/%_python_lib/xrootiface.py
install -m 644 src/wsgi.py           %buildroot/usr/bin/wsgi.py
install -m 644 wopiserver.service    %buildroot/usr/lib/systemd/system/wopiserver.service
install -m 644 wopiserver.conf       %buildroot/etc/wopi/wopiserver.defaults.conf
install -m 644 wopiserver.logrotate  %buildroot/etc/logrotate.d/cernbox-wopi-server
install -m 644 nginx.conf            %buildroot/etc/nginx/conf.d/wopiserver.conf
install -m 644 uwsgi-wopiserver.ini  %buildroot/etc/uwsgi.d/wopiserver.ini

install -m 755 mon/wopi_grafana_feeder.py  %buildroot/usr/bin/wopi_grafana_feeder.py

%clean
rm -rf %buildroot/

%preun

%post
touch /etc/wopi/wopisecret
touch /etc/wopi/ocsecret

%files
%defattr(-,root,root,-)
/etc/wopi
/etc/logrotate.d/cernbox-wopi-server
/etc/nginx/conf.d/wopiserver.conf
/etc/uwsgi.d/wopiserver.ini
%attr(-,cboxwopi,def-cg) /var/log/wopi
/usr/lib/systemd/system/wopiserver.service
/usr/bin/*
%_python_lib/*

%changelog
* Mon Jul  2 2018 Giuseppe Lo Presti <lopresti@cern.ch> 2.8
- Introduced support for multiple storage backends
* Thu Feb 15 2018 Giuseppe Lo Presti <lopresti@cern.ch> 2.7
- Improved handling of newly created files, including working
  around an issue with concurrent editing from Office Online
* Mon Jan 22 2018 Giuseppe Lo Presti <lopresti@cern.ch> 2.6
- Port to xrootd 4.8 and its python bindings
- Docker and docker-compose files made available in the repo
* Thu Dec  7 2017 Giuseppe Lo Presti <lopresti@cern.ch> 2.5
- Improved logging to get time statistics about xrootd remote calls
  and consistently log the access token across all relevant log messages
- Included script to parse logs and send statistics to grafana
* Mon Aug 21 2017 Giuseppe Lo Presti <lopresti@cern.ch> 2.0
- Incorporated contributions from AARNet, introduced many configurable items
- Improved docker image configuration for running behind a load balancer
- Included support for nginx as load balancer (this is still experimental
  and not required for the functioning of the WOPI server)
- Improved logging for monitoring purposes, introduced script
  to populate a grafana instance with relevant metrics
- Fixed WebDAV URL
* Fri May 19 2017 Giuseppe Lo Presti <lopresti@cern.ch> 1.5
- Improved support for anonymous shares
- Added support for desktop access via WebDAV
- Fixed handling of expired WOPI locks
* Fri May  5 2017 Giuseppe Lo Presti <lopresti@cern.ch> 1.4
- Disabled renaming and added work-around for looping locking requests
- Get list of currently opened files for operations purposes
- General refactoring of the code
* Fri Apr  7 2017 Giuseppe Lo Presti <lopresti@cern.ch> 1.3
- Improved navigation and properties in Office Online
- Fixed lock handling to adhere to specifications (this is known
  to break renaming in Word and PowerPoint)
* Wed Mar 22 2017 Giuseppe Lo Presti <lopresti@cern.ch> 1.2
- Support creation of new documents
* Wed Mar  1 2017 Giuseppe Lo Presti <lopresti@cern.ch> 1.1
- Improved lock handling to fully support concurrent editing
* Fri Feb 24 2017 Giuseppe Lo Presti <lopresti@cern.ch> 1.0
- First official release for internal deployment after first round of tests
* Fri Feb 17 2017 Giuseppe Lo Presti <lopresti@cern.ch> 0.4
- Support for https, download URL and minor fixes
- Release for pre-production tests
* Tue Feb 14 2017 Giuseppe Lo Presti <lopresti@cern.ch> 0.3
- Implemented the locking interface
- Support the PutRelativeFile, RenameFile, DeleteFile operations
- Refined the /cbox API to interact with OwnCloud
* Wed Jan 18 2017 Giuseppe Lo Presti <lopresti@cern.ch> 0.2
- First nearly complete version for test deployment with eosbackup
* Thu Jan  5 2017 Giuseppe Lo Presti <lopresti@cern.ch> 0.1
- First packaging for the WOPI server prototype

