## Changelog for the WOPI bridge

### wopibridge 4.0.0 (2021-06-14)
* Refactored code to support plugins, and
  introduced a plugin for Etherpad with
  minimal functionality
* Fixed public links for CodiMD
* Fixed repeated autosaving in CodiMD when
  a document is left open (#11)

### wopibridge 3.2.0 (2021-04-23)
* Introduced a shared secret as an `apikey`
  parameter to be passed to CodiMD
* Fixed case of double redirection
* Improved display name

### wopibridge 3.1.0 (2021-03-19)
* Fixed a number of corner cases with the CodiMD
  update API and the WOPI Put/PutRelative calls

### wopibridge 3.0.0 (2021-03-05)
* Added support for the Update CodiMD API and for
  deterministic noteid hashing (#7), which requires
  CodiMD to have `ALLOW_FREEURL` set to true
* Added a secret file in the docker configuration,
  for the noteid hashing and for the /list endpoint
* Simplified bookkeeping logic of the save thread
* Improved logging

### wopibridge 2.2.0 (2021-02-11)
* Improved logic for cleaning up current sessions
  and better handling of failure scenarios
* Improved logging

### wopibridge 2.1.0 (2021-02-05)

* Reworked logic to recover when lock is missing (#4)
* Improved UI feedback messages
* Introduced a new parameter `APP_UNLOCK_INTERVAL`
  to control when a file is unlocked following
  a close event from all concurrent sessions
* Code further refactored and simplified

### wopibridge 2.0.0 (2020-12-14)

* Full refactoring of the code, to separate
  the core server from the CodiMD-specific code
* Fixed handling of multiple collaborating users
  and multiple wopibridge instances by storing
  more state in the WOPI locks

### wopibridge 1.2.0 (2020-12-01)

* Better support for slides
* Improved logging and UI responses
* Added versioning

### wopibridge 1.1.0 (2020-11-11)

* Several fixes around saving and feedback to UI
* First version fully integrated in CERNBox (Canary mode)

### wopibridge 1.0.0 (2020-10-13)

* Full refactoring to achieve a MVP
* Added support for autosave
* Removed dependency on locally mounted CodiMD storage
* Added support for a custom `APP_ROOT`

### wopibridge 0.3 (2020-08-05)

* Make use of extended features of CodiMD to support
  read-only mode and display name
* Introduced K8s deployment
* Automatic build with drone

### wopibridge 0.2 (2020-05-18)

* Repo moved to the CS3 Organisation
* Added support for attachments (images)

### wopibridge 0.1 (2020-04-08)

* First PoC of a WOPI bridge service for CodiMD,
  including collaborative editing and WOPI-compliant locking.
