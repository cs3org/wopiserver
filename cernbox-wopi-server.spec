#
# cernbox-wopi-server spec file
#
Name:      cernbox-wopi-server
Summary:   A WOPI server to support Office online suites for the ScienceMesh IOP
Version:   %{_version}
Release:   0%{?dist}
License:   GPLv3
Buildroot: %{_tmppath}/%{name}-buildroot
Group:     CERN-IT/ST
BuildArch: noarch
Source: %{name}-%{version}.tar.gz

BuildRequires: python(abi) >= 3.6
Requires: python(abi) >= 3.6, python36-pip
# pip3-installed "Requires" are to be found in the requirements.txt file.
# Note that python3-xrootd and the CS3APIs bindings are not explicit dependencies given that they are dynamically loaded.
# Also note that when using the CS3APIs the required python version is 3.8, which is NOT available
# in CentOS 7. This RPM targets xrootd based deployments, where python 3.6 is sufficient.

# The following to avoid to pick up /bin/python as an automatic dependency
AutoReq: no

%description
This RPM provides a Flask-based reference implementation of the WOPI protocol for the CS3 ScienceMesh IOP.

The server supports storage via the CS3 APIs to the IOP, local storage for testing purposes,
as well as xrootd-based storages currently used in production at CERN for CERNBox.

# Don't do any post-install weirdness, especially compiling .py files
%define __os_install_post %{nil}

# Get the python lib directory
%define _python_lib %(python3 -c "from distutils import sysconfig; print(sysconfig.get_python_lib())")

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
mkdir -p %buildroot/usr/lib/systemd/system
mkdir -p %buildroot/var/log/wopi
install -m 755 src/wopiserver.py     %buildroot/usr/bin/wopiserver.py
install -m 644 src/wopiutils.py      %buildroot/%_python_lib/wopiutils.py
install -m 644 src/xrootiface.py     %buildroot/%_python_lib/xrootiface.py
install -m 644 src/localiface.py     %buildroot/%_python_lib/localiface.py
install -m 644 src/cs3iface.py       %buildroot/%_python_lib/cs3iface.py
install -m 644 wopiserver.service    %buildroot/usr/lib/systemd/system/wopiserver.service
install -m 644 wopiserver.conf       %buildroot/etc/wopi/wopiserver.defaults.conf
install -m 644 wopiserver.logrotate  %buildroot/etc/logrotate.d/cernbox-wopi-server
install -m 755 mon/wopi_grafana_feeder.py  %buildroot/usr/bin/wopi_grafana_feeder.py
install -m 755 tools/wopicheckfile.py      %buildroot/usr/bin/wopicheckfile.py
install -m 755 tools/wopilistopenfiles.sh  %buildroot/usr/bin/wopilistopenfiles.sh
install -m 755 tools/wopiopen.py           %buildroot/usr/bin/wopiopen.py

%clean
rm -rf %buildroot/

%preun

%post
touch /etc/wopi/wopisecret
touch /etc/wopi/iopsecret

%files
%defattr(-,root,root,-)
/etc/wopi
/etc/logrotate.d/cernbox-wopi-server
%attr(0775,cboxwopi,def-cg) /var/log/wopi
/usr/lib/systemd/system/wopiserver.service
/usr/bin/*
%_python_lib/*

%changelog
* Tue Sep 22 2020 Giuseppe Lo Presti <lopresti@cern.ch> 5.5.0
- Moved to 3-digit releases to help drone-based automatic builds
- Minor fixes in cboxLock and CheckFileInfo
- Made logs group-writable for flume agents to push them to Kibana
* Thu Aug 27 2020 Giuseppe Lo Presti <lopresti@cern.ch> 5.4
- Make CS3-based uploads work with tus and through gateway
- Fixed race condition in cboxLock
- Delay lock checks when needed (i.e. in WOPI LOCK), not
  at access token creation time
* Tue Aug  4 2020 Giuseppe Lo Presti <lopresti@cern.ch> 5.3
- Fixed CS3-based workflows: the wopiopen.py tool and the
  open-file-in-app-provider reva command both support
  generic storage ids and have been tested with Collabora
- Fixed wopiurl config parameter
* Fri Jul  2 2020 Giuseppe Lo Presti <lopresti@cern.ch> 5.2
- Fixed xrootd encoding of file names with special chars
- Incorporated unit test suite in the docker images
* Fri Jun 26 2020 Giuseppe Lo Presti <lopresti@cern.ch> 5.1
- Exposed a new /wopi/iop/open endpoint to match Reva. The
  former /wopi/cbox/open endpoint is deprecated and will
  be dropped once production moves forward.
- Added support for inodes invariant to save operations,
  in order to properly support collaborative editing
* Fri Jun  5 2020 Giuseppe Lo Presti <lopresti@cern.ch> 5.0
- General refactoring of the code base and evolution to become
  fully vendor-neutral: see https://github.com/cs3org/wopiserver/pull/14
- Included a pure python-based docker image
- Ported to xrootd 4.12 and python 3.8
- Moved to the CS3 Organisation
* Wed May 14 2020 Giuseppe Lo Presti <lopresti@cern.ch> 4.3
- Included some fixes around locking; this is hopefully the last release
  before the ScienceMesh integration
* Wed Apr 08 2020 Giuseppe Lo Presti <lopresti@cern.ch> 4.2
- Introduced two new lock-related endpoints to cover interoperability
  with OnlyOffice
* Wed Apr 01 2020 Giuseppe Lo Presti <lopresti@cern.ch> 4.1
- Improved WOPI lock handling
- Added detection of lock files created by Desktop apps
  (Microsoft Office and LibreOffice) to prevent data losses
* Fri Mar 06 2020 Giuseppe Lo Presti <lopresti@cern.ch> 4.0
- Major refactoring to introduce support of multiple storage access plugins:
  currently supported xrootd (default) and local storage, a CS3APIs-compliant
  access plugin is foreseen in an upcoming release.
- Added support for multiple office-like applications: currently supported
  office apps are Microsoft Office Online and Collabora Online
- Included minor fixes in the core WOPI code
* Mon Jul  1 2019 Giuseppe Lo Presti <lopresti@cern.ch> 3.1
- Fixed handling of strings/byte-arrays
- Packaging adapted to CentOS7 and pip3
* Tue Oct  9 2018 Giuseppe Lo Presti <lopresti@cern.ch> 3.0
- Ported software to Python 3
- Removed experimental nginx configuration
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
