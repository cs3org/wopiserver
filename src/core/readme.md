## WOPI server - core module

This module includes the core WOPI protocol implementation.
To access the storage, three interfaces are provided:

* `xrootiface.py` to interface to an EOS storage via the xrootd protocol. Though the code is generic enough to enable support for any xrootd-based storage, it does include EOS-specific calls.

* `cs3iface.py` to interface to storage providers via [CS3 APIs](https://github.com/cs3org/cs3apis).

* `localiface.py` to interface to a local filesystem. Note that this interface is provided for testing purposes only, and it is supported on Linux and WSL for Windows, not on native Windows nor on native MacOS systems as they lack support for extended attributes in Python.

The `/test` folder contains a unit test suite for the storage interfaces.
