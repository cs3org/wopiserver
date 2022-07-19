[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
 [![Gitter chat](https://badges.gitter.im/cs3org/wopiserver.svg)](https://gitter.im/cs3org/wopiserver) [![Build Status](https://drone.cernbox.cern.ch/api/badges/cs3org/wopiserver/status.svg)](https://drone.cernbox.cern.ch/cs3org/wopiserver)
 [![codecov](https://codecov.io/gh/cs3org/wopiserver/branch/master/graph/badge.svg)](https://codecov.io/gh/cs3org/wopiserver)
========

# WOPI Server

This service is part of the ScienceMesh Interoperability Platform (IOP) and implements a vendor-neutral application gateway compatible with the Web-application Open Platform Interface ([WOPI](https://docs.microsoft.com/en-us/microsoft-365/cloud-storage-partner-program/online)) specifications.

It enables ScienceMesh EFSS storages to integrate Office Online platforms including Microsoft Office Online and Collabora Online. In addition it implements a [bridge](src/bridge/readme.md) module with dedicated extensions to support apps like CodiMD and Etherpad.

Author: Giuseppe Lo Presti (@glpatcern) <br/>
Contributors:
- Michael DSilva (@madsi1m)
- Lovisa Lugnegaard (@LovisaLugnegard)
- Samuel Alfageme (@SamuAlfageme)
- Diogo Castro (@diocas)
- Ishank Arora (@ishank011)
- Willy Kloucek (@wkloucek)
- Gianmaria Del Monte (@gmgigi96)
- Klaas Freitag (@dragotin)
- Jörn Friedrich Dreyer (@butonic)

Initial revision: December 2016 <br/>
First production version for CERNBox: September 2017 (presented at [oCCon17](https://occon17.owncloud.org) - [slides](https://www.slideshare.net/giuseppelopresti/collaborative-editing-and-more-in-cernbox))<br/>
Integration in the CS3 Organisation: April 2020


## Modules

* [core](src/core/readme.md)
* [bridge](src/bridge/readme.md)

## Changelog

[Available here](CHANGELOG.md)

## Compatibility

This WOPI server implements the required APIs to ensure full compatibility with Collabora Online and Microsoft Office. For the latter, however, the OneNote application uses newer WOPI APIs and is currently not supported.

## Unit testing

The `/test` folder contains some unit tests for the supported storage interfaces.
No tests are provided (yet) for the core WOPI server, though the test suite aims at covering all
storage access patterns used by the WOPI server.

By default, the local storage is tested, and the CI runs it as well (_TODO_ test against Reva in the CI).
To run the tests, either run `pytest` if available in your system, or execute the following:

1. Run all tests: `python3 test/test_storageiface.py [-v]`
2. Run only one test: `python3 test/test_storageiface.py [-v] TestStorage.<the test you would like to run>`

### Test against a Reva endpoint:

1. Clone reva (https://github.com/cs3org/reva)
2. Run Reva according to <https://reva.link/docs/tutorials/share-tutorial/> (ie up until step 4 in the instructions).
3. Run the tests: `WOPI_STORAGE=cs3 python3 test/test_storageiface.py`

### Test against an Eos endpoint:

1. Make sure your Eos instance is configured to accept connections from WOPI as a privileged gateway
2. Configure `wopiserver-test.conf` according to your Eos setup. The provided defaults are valid at CERN.
3. Run the tests: `WOPI_STORAGE=xroot python3 test/test_storageiface.py`

### Test using the Microsoft WOPI validator test suite

This is work in progress. Refer to [these notes](test/wopi-validator.md).


## Run the WOPI server locally for development purposes

1. Install all requirements: `pip install -r requirements.txt`
2. Add log file directory: `sudo mkdir /var/log/wopi/ && sudo chmod a+rwx /var/log/wopi`
3. Create the folder for the wopi config: `sudo mkdir /etc/wopi/ && sudo chmod a+rwx /etc/wopi`
4. Create recoveryfolder: `sudo mkdir /var/spool/wopirecovery && sudo chmod a+rwx /var/spool/wopirecovery`
5. Create the files `iopsecret` and `wopiscret` in the folder `/etc/wopi/`, create random strings for the secrets
6. Copy the provided `wopiserver.conf` to `/etc/wopi/wopiserver.defaults.conf`
7. Create a config file `/etc/wopi/wopiserver.conf`: start from `docker/etc/wopiserver.conf` for a minimal configuration and add from the defaults file as needed
8. From the WOPI server folder run: `python3 src/wopiserver.py`

### Test the open-in-app workflow on the local WOPI server

Once the WOPI server runs on top of local storage, the `tools/wopiopen.py` script can be used
to test the open-in-app workflow. For that, assuming you have e.g. CodiMD deployed in your (docker-compose) cluster:

1. Create a `test.md` file in your local storage folder, e.g. `/var/wopi_local_storage`
2. From the WOPI server folder, execute `tools/wopiopen.py -a CodiMD -i "internal_CodiMD_URL" -u "user_visible_CodiMD_URL" -k CodiMD_API_Key test.md`
3. If everything was setup correctly, you'll get a JSON response including an `app-url`. Open it in a browser to access the file. Otherwise, the tool prints the response from the WOPI server and the logs should help troubleshooting the problem.
