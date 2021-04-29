## Changelog for the WOPI server

### Thu Apr 29 2021 - v6.5.0
- Extended the REFRESH_LOCK API to support relocking
  a file when it was not externally modified
- Fixed /cbox/lock in order to ensure the returned
  lockid is never older than the token expiration time
- Introduced a new .epd file extension for Etherpad

### Tue Apr 13 2021 - v6.4.0
- Fixed WOPI locking when a stale LibreOffice/OnlyOffice
  lock was found on the storage
- Improved PutFile responses when dealing with conflicts
- Fixed CS3 APIs bindings import

### Fri Mar 12 2021 - v6.3.0
- Fixed unique inodes by using a base64 encoding of the
  underlying inode (endpoint + fileid for xrootd-EOS)
- Extended validity of WOPI locks to take into account
  PutFile operations: the lock will be valid until the most
  recent value between its expiration time and the last
  save time + `wopilockexpiration`
- Added support for a dynamic list of file extensions for
  Collabora Online
- Fixed and improved logging

### Tue Feb  9 2021 - v6.2.0
- Fixed responses of GET_LOCK and REFRESH_LOCK calls when no
  existing lock is found: 404 is now returned as opposed to 409
- Fixed response of PUT in case of missing lock
- Improved probing of target locks in PUT_RELATIVE
- Make sure inodes are unique across eos instances with the
  xrootd storage interface, similarly to the CS3 interface

### Mon Jan 25 2021 - v6.1.0
- Fixed JWT generation following latest pyjwt package
- Improved prometheus monitoring to cover /cbox/lock calls
- Improved logging

### Tue Dec  8 2020 - v6.0.0
- Migrated the xrootd-based docker image to xrootd 5.0 and CentOS 8.2
  (with crypto legacy mode enabled to keep TLS 1.1 support)
- Migrated the default image to python 3.9 and fixed requirements
  accordingly (will revert to latest grpcio once it is fixed)
- Introduced a check on /open and /lock in case the file is
  a directory: now an error is returned as opposed to let such
  operations succeed
- Added a /metrics endpoint for Prometheus integration
- Several minor fixes as hinted by the MS WOPI validator tests
- As of this version, RPMs are not built any longer and the
  supported deployment is docker-based only

### Mon Nov 30 2020 - v5.7.0
- Log is now in JSON format as opposed to syslog-like
- Use direct data transfers (non-TUS-based) with CS3 storages
- Improved locks handling and responses
- Improved exception handling in /cbox/lock

### Mon Oct 19 2020 - v5.6.0
- Renamed codimdurl to wopibridgeurl
- Improved logging and exception handling
- Minor fix on PutFile
- Improved locking for non-office files

### Tue Sep 22 2020 - v5.5.0
- Moved to 3-digit releases to help drone-based automatic builds
- Minor fixes in cboxLock and CheckFileInfo
- Made logs group-writable for flume agents to push them to Kibana
### Thu Aug 27 2020 - v5.4
- Make CS3-based uploads work with tus and through gateway
- Fixed race condition in cboxLock
- Delay lock checks when needed (i.e. in WOPI LOCK), not
  at access token creation time

### Tue Aug  4 2020 - v5.3
- Fixed CS3-based workflows: the wopiopen.py tool and the
  open-file-in-app-provider reva command both support
  generic storage ids and have been tested with Collabora
- Fixed wopiurl config parameter

### Thu Jul  2 2020 - v5.2
- Fixed xrootd encoding of file names with special chars
- Incorporated unit test suite in the docker images

### Fri Jun 26 2020 - v5.1
- Exposed a new /wopi/iop/open endpoint to match Reva. The
  former /wopi/cbox/open endpoint is deprecated and will
  be dropped once production moves forward.
- Added support for inodes invariant to save operations,
  in order to properly support collaborative editing

### Fri Jun  5 2020 - v5.0
- General refactoring of the code base and evolution to become
  fully vendor-neutral: see https://github.com/cs3org/wopiserver/pull/14
- Included a pure python-based docker image
- Ported to xrootd 4.12 and python 3.8
- Moved to the CS3 Organisation

### Thu May 14 2020 - v4.3
- Included some fixes around locking; this is hopefully the last release
  before the ScienceMesh integration

### Wed Apr 08 2020 - v4.2
- Introduced two new lock-related endpoints to cover interoperability
  with OnlyOffice

### Wed Apr 01 2020 - v4.1
- Improved WOPI lock handling
- Added detection of lock files created by Desktop apps
  (Microsoft Office and LibreOffice) to prevent data losses

### Fri Mar 06 2020 - v4.0
- Major refactoring to introduce support of multiple storage access plugins:
  currently supported xrootd (default) and local storage, a CS3APIs-compliant
  access plugin is foreseen in an upcoming release.
- Added support for multiple office-like applications: currently supported
  office apps are Microsoft Office Online and Collabora Online
- Included minor fixes in the core WOPI code

### Mon Jul  1 2019 - v3.1
- Fixed handling of strings/byte-arrays
- Packaging adapted to CentOS7 and pip3

### Tue Oct  9 2018 - v3.0
- Ported software to Python 3
- Removed experimental nginx configuration

### Mon Jul  2 2018 - v2.8
- Introduced support for multiple storage backends

### Thu Feb 15 2018 - v2.7
- Improved handling of newly created files, including working
  around an issue with concurrent editing from Office Online

### Mon Jan 22 2018 - v2.6
- Port to xrootd 4.8 and its python bindings
- Docker and docker-compose files made available in the repo

### Thu Dec  7 2017 - v2.5
- Improved logging to get time statistics about xrootd remote calls
  and consistently log the access token across all relevant log messages
- Included script to parse logs and send statistics to grafana

### Mon Aug 21 2017 - v2.0
- Incorporated contributions from AARNet, introduced many configurable items
- Improved docker image configuration for running behind a load balancer
- Included support for nginx as load balancer (this is still experimental
  and not required for the functioning of the WOPI server)
- Improved logging for monitoring purposes, introduced script
  to populate a grafana instance with relevant metrics
- Fixed WebDAV URL

### Fri May 19 2017 - v1.5
- Improved support for anonymous shares
- Added support for desktop access via WebDAV
- Fixed handling of expired WOPI locks

### Fri May  5 2017 - v1.4
- Disabled renaming and added work-around for looping locking requests
- Get list of currently opened files for operations purposes
- General refactoring of the code

### Fri Apr  7 2017 - v1.3
- Improved navigation and properties in Office Online
- Fixed lock handling to adhere to specifications (this is known
  to break renaming in Word and PowerPoint)

### Wed Mar 22 2017 - v1.2
- Support creation of new documents

### Wed Mar  1 2017 - v1.1
- Improved lock handling to fully support concurrent editing

### Fri Feb 24 2017 - v1.0
- First official release for internal deployment after first round of tests

### Fri Feb 17 2017 - v0.4
- Support for https, download URL and minor fixes
- Release for pre-production tests

### Tue Feb 14 2017 - v0.3
- Implemented the locking interface
- Support the PutRelativeFile, RenameFile, DeleteFile operations
- Refined the /cbox API to interact with OwnCloud

### Wed Jan 18 2017 - v0.2
- First nearly complete version for test deployment with eosbackup

### Thu Jan  5 2017 - v0.1
- First packaging for the WOPI server prototype
