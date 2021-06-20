## WOPI server - core module

This module includes the core WOPI protocol implementation, the discovery logic, and the storage access interfaces.

Three storage interfaces are provided:

* `xrootiface.py` to interface to an EOS storage via the xrootd protocol. Though the code is generic enough to enable support for any xrootd-based storage, it does include EOS-specific calls.

* `cs3iface.py` to interface to a storage provider via CS3 APIs.

* `localiface.py` to interface to a local filesystem. This is provided for testing purposes

The `/test` folder contains a unit test suite for the storage interfaces.
