## Changelog for the WOPI server

### Future - v11.0.0
- Adopted the cs3 python client (#161), and optimized the logic
  that deals with extended attributes
- Ported xrootd docker image to Alma9 (#164)
- Forced preview mode for non-regular (non-primary) accounts

### Fri May 24 2024 - v10.5.0
- Added timeout settings for GRPC and HTTP connections (#149)
- Fixed handing of trailing slashes (#151)
- Moved docker image to 3.12.3-alpine (#147)

### Tue May 14 2024 - v10.4.0
- Added support for Microsoft compliance domains
- Fixed opening of markdown files created on Windows platforms
- Improved lock handling on write and xattr operations (#137)
- Improved logs

### Fri Jan 19 2024 - v10.3.0
- Implemented support for X-Trace-Id header (#64)
- Fixed SaveAs logic for non-authenticated (anonymous) users
- Improved handling of HTTP requests
- Improved memory efficiency by streaming files' content (#136, #141)
- Fixed 0-byte uploads (#142)

### Mon Oct 23 2023 - v10.2.0
- Implemented cache for xattrs in the cs3 storage (#128)
- Implemented advisory locking via xattrs for cs3 storages that
  do not support native locking (#129)
- Improved handling of default values, in order to clean up
  the default config file
- Fixed the PostMessageOrigin property in CheckFileInfo when
  using the same wopiserver with multiple cloud storages
- Fixed xroot build
- Fixed failed precondition error handling in unlock

### Wed Jul  5 2023 - v10.1.0
- Fixed handling of filenames with non latin-1 characters (#127)
- Improved logging and adjusted log levels (#123)
- Switched from CentOS Stream 8 to AlmaLinux 8 for the
  xroot-flavoured docker image

### Wed May 31 2023 - v10.0.0
- Added CloseUrl and other properties to CheckFileInfo
- Introduced health check of the configured storage interface
  to ease deployment validation (#122)
- Inverted default for wopilockstrictcheck
- Fixed Preview mode
- Removed legacy logic for discovery of app endpoints (#119):
  this is now only implemented by Reva's app providers, and
  legacy ownCloud/CERNBox UIs are not supported any longer
- Removed support to forcefully evict valid locks, introduced
  to compensate a Microsoft Word issue
- Converted all responses to JSON-formatted (#120)
- Cleaned up obsoleted scripts

### Fri Mar 10 2023 - v9.5.0
- Introduced concept of user type, given on `/wopi/iop/open`,
  to better serve federated vs regular users with respect to
  folder URLs and SaveAs operations
- Redefined `conflictpath` option as `homepath` (the former is
  still supported for backwards compatibility): when defined,
  a SaveAs operation falls back to the user's `homepath` when
  it can't work on the original folder
- Fixed PutUserInfo to use the user's username as xattr key
- Added arm64-based builds

### Tue Jan 31 2023 - v9.4.0
- Introduced support to forcefully evict valid locks
  to compensate Microsoft Online mishandling of collaborative
  sessions. This workaround will stay until a proper fix
  is implemented following Microsoft CSPP team's advices
- Improved logging, in particular around lock eviction
- Bridged apps: moved plugin loading apps out of the deprecated
  discovery module, and fixed some minor bugs
- CI: moved release builds to GitHub actions

### Thu Nov 24 2022 - v9.3.0
- Introduced heuristic to log which sessions are allowed
  to open a collaborative session and which ones are
  prevented by the application
- Introduced support for app-aware locks in EOS (#94)
- Disabled SaveAs action when user is not owner
- Improved error coverage in case of transient errors
  in bridged apps and in PutFile operations
- Moved from LGTM to CodeQL workflow on GitHub (#100)
- Introduced support for PutUserInfo
- Added support for the Microsoft "business" flow (#105)

### Mon Oct 17 2022 - v9.2.0
- Added option to use file or stream handler for logging (#91)
- Introduced configurable hostURLs for CheckFileInfo (#93)
- Fixed duplicate log entries (#92)
- CodiMD: added support for direct storage access via
  the ownCloud file picker (#95)
- Fixed check for external locks
- Further fixes to improve coverage of the WOPI validator tests

### Wed Oct  5 2022 - v9.1.0
- Introduced support for PREVIEW mode (#82)
- Improved UnlockAndRelock logic (#85, #87)
- Switched to python-alpine docker image (#88)
- Introduced further branding options in CheckFileInfo
- Further improvements in the bridged apps logic
- Added more logging and a new endpoint to monitor
  conflicted sessions

### Thu Sep  1 2022 - v9.0.0
- Refactored and strengthened save workflow for
  bridged applications, and simplified lock metadata (#80)
  [Note: this change is not backwards compatibile and
  prevents a transparent upgrade; see also wopiserver.conf]
- Refactored PutFile logic when handling conflict files (#78)
- Improved support for Spaces in Reva (#79)
- Implemented save workflow for Etherpad documents (#81)
- Fixed direct download in case of errors
- Updated dependencies and documentation

### Thu Jun 16 2022 - v8.3.0
- Improved logging around lock conflict handling
- Added logging of additional headers as provided
  by MS Office 365
- Readded tool to test the open-in-app workflow
- Extend creation of recovery files when a PutFile
  fails because of a lock mismatch
- Added support for disabling write access to ODF
  files when opened with MS Office

### Fri May  6 2022 - v8.2.0
- Added support for etags to represent file versions (#65)
- Use relative references for CS3-compatible storages (#74)
- Improved support for ownCloud WOPI proxy
- Simplified SetLock logic
- Fixed some metadata responses (#76) following Microsoft
  WOPI validation tests. In particular, WOPISrc
  values are now URL-encoded as per specifications,
  and PutRelative is fully compliant

### Fri Apr 29 2022 - v8.1.0
- Fixed handling of files with a `&` char in xroot
- Improved stat/version folder logic and logging in xroot
- Added reva traces to all relevant logs (#75)
- Restored full URL logging in case of critical errors
- Fixed uncaught exceptions
- Code linting and cleanup campaign

### Fri Apr  8 2022 - v8.0.0
- The new Lock API is now fully supported (#51),
  including in the CS3APIs-compatible layer;
  in addition, locks are passed along to CS3APIs
  backends on any operation that implies a modification
- Moved part of the lock handling logic to the storage
  providers (#69), as Reva implements it natively: this
  removes the non-standard feature that the expiration time
  of a lock was extended by `PutFile` operations without
  needing to call `RefreshLock`, as introduced in v6.3.0
- Added support for Reva spaces in the CS3API-compatible
  storage layer (#67)
- Introduced a `recoverypath` configuration option as a
  local path where to store files in case of I/O errors
  with the remote storage. Fixes bug #39
- Introduced a `conflictpath` configuration option as the
  target location where to store webconflict files
- Introduced a `detectexternallocks` option, to control
  the additional logic that allows to operate the WOPI
  server on shared online storages
- Improved logging: lock-related logs were made more
  consistent and informative, and access tokens have
  been redacted from logged URLs
- The docker image has been upgraded to python 3.10
- Support for the ownCloud WOPI proxy was extended
  to the legacy `/cbox/open` endpoint

### Fri Dec  3 2021 - v8.0.0rc1
- Refactored the locking logic to use a new
  Lock API (#51) and corresponding xattr support
  in xrootd/EOS. Note that for this pre-release,
  the CS3APIs-compatible implementation of locking
  is not yet available
- Removed legacy crypto settings from docker image
- Adapted the xrootd/EOS storage interface to
  support the new `/openinapp` Reva workflow
- Implemented support for the ownCloud WOPI proxy

### Wed Oct 27 2021 - v7.5.0
- Improved support for bridged apps when opened
  in legacy mode via /cbox/open
- Improved JSON representation of log messages
- Ensure the `UserId` WOPI property is
  consistent over multiple sessions for
  any given user (#48)
- Added support for disabling zipped bundles
  in CodiMD (#49)
- Added support for disabling renames from apps

### Tue Sep  7 2021 - v7.4.0
- Changed the inode scheme for the xrootd
  storage interface to match the cs3 one and
  enable co-operation in mixed deployments
- Made `folderurl` argument fully optional
  in /wopi/iop/openinapp
- Improved logging and error reporting
  from the storage layers
- Added minimal validation of cert/key files
  prior to starting the Flask server
  in https mode
- Fixed some return codes in case of
  invalid access token
- Refactoring: deprecated REST endpoints
  under /wopi/cbox were all clearly marked

### Wed Sep  1 2021 - v7.3.0
- Fixed WOPI GetFile to return HTTP 500
  in case of failures fetching the file
  from the backend
- Raised log levels in case of unexpected
  user actions or storage failures
- Improved logs readability when userids
  are long Reva JWT tokens
- Implemented a `wopilockstrictcheck` config
  parameter (see wopiserver.conf)
- Limit conflict files to one per hour (#45)
- Fixed default for appviewurl (#46)

### Mon Aug 16 2021 - v7.2.0
- Reverted because of a bug in GetFile

### Fri Aug  6 2021 - v7.1.0
- Handled cases of too large files as well as
  invalid UTF encoding in CodiMD
- Improved initialization of bridge plugins
- Reworked openinapp endpoint following
  developments in the AppProviders model

### Tue Jun 29 2021 - v7.0.0
- Merged wopibridge functionality: now
  the server supports a new `codimdurl` parameter
  as well as a `codimd_apikey` file as a "secret",
  whereas `wopibridgeurl` was removed
- Introduced a new /wopi/iop/openinapp endpoint,
  which does not use the discovery but relies on
  Reva to have the needed app URLs: the discovery
  logic was moved to a separate module and will
  be deprecated once reva#1779 is fixed
- Complete refactoring/linting of the code
  to follow PEP8 standards
- Enhanced logging to include the python module
- Fixed some uncaught exceptions found in production

### Tue Jun  8 2021 - v6.6.0
- Make SSL certificate validation configurable for Reva
- Removed workarounds targeting MS Word Online

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
