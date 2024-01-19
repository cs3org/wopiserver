[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
 [![Gitter chat](https://badges.gitter.im/cs3org/wopiserver.svg)](https://gitter.im/cs3org/wopiserver)
 [![Build Status](https://github.com/cs3org/wopiserver/actions/workflows/release.yml/badge.svg)](https://github.com/cs3org/wopiserver/actions)
 [![Codacy Badge](https://app.codacy.com/project/badge/Grade/e4e7c46c39b04bddbf63ade4cacdcc7d)](https://www.codacy.com/gh/cs3org/wopiserver/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=cs3org/wopiserver&amp;utm_campaign=Badge_Grade)
 [![codecov](https://codecov.io/gh/cs3org/wopiserver/branch/master/graph/badge.svg)](https://codecov.io/gh/cs3org/wopiserver)
========

# WOPI Server

This service is part of the ScienceMesh Interoperability Platform ([IOP](https://developer.sciencemesh.io)) and implements a vendor-neutral application gateway compatible with the Web-application Open Platform Interface ([WOPI](https://docs.microsoft.com/en-us/microsoft-365/cloud-storage-partner-program/online)) specifications.

It enables ScienceMesh EFSS storages to integrate Office Online platforms including Microsoft Office Online and Collabora Online. In addition it implements a [bridge](src/bridge/readme.md) module with dedicated extensions to support apps like CodiMD and Etherpad.

Author: Giuseppe Lo Presti (@glpatcern) <br/>
Contributors (oldest contributions first):
- Michael DSilva (@madsi1m)
- Lovisa Lugnegaard (@LovisaLugnegard)
- Samuel Alfageme (@SamuAlfageme)
- Diogo Castro (@diocas)
- Ishank Arora (@ishank011)
- Willy Kloucek (@wkloucek)
- Gianmaria Del Monte (@gmgigi96)
- Klaas Freitag (@dragotin)
- Jörn Friedrich Dreyer (@butonic)
- Michael Barz (@micbar)
- Robert Kaussow (@xoxys)
- Javier Ferrer (@javfg)
- Vasco Guita (@vascoguita)
- Thomas Mueller (@deepdiver1975)
- Andre Duffeck (@aduffeck)

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

### Test against a Reva CS3 endpoint:

1. Clone reva (https://github.com/cs3org/reva)
2. Run Reva according to <https://reva.link/docs/tutorials/share-tutorial/> (ie up until step 4 in the instructions)
4. Configure `test/wopiserver-test.conf` such that the wopiserver can talk to your Reva instance: use [this example](docker/etc/wopiserver.cs3.conf) for a skeleton configuration
5. Run the tests: `WOPI_STORAGE=cs3 python3 test/test_storageiface.py`
3. For a production deployment, configure your `wopiserver.conf` following the example above, and make sure the `iopsecret` file contains the same secret as configured in the [Reva appprovider](https://developer.sciencemesh.io/docs/technical-documentation/iop/iop-optional-configs/collabora-wopi-server/wopiserver)

### Test against an Eos endpoint:

1. Make sure your Eos instance is configured to accept connections from WOPI as a privileged gateway
2. Configure `test/wopiserver-test.conf` according to your Eos setup (the provided defaults are valid at CERN)
3. Run the tests: `WOPI_STORAGE=xroot python3 test/test_storageiface.py`
4. For a production deployment (CERN only), configure your `wopiserver.conf` according to the Puppet infrastructure

### Test using the Microsoft WOPI validator test suite

Refer to [these notes](test/wopi-validator.md). Microsoft also provides a graphical version of the test suite
as part of their Office 365 offer, which is also supported via the Reva open-in-app workflow.


## Run the WOPI server locally for development purposes

1. Install all requirements: `pip install -r requirements.txt`
2. Add log file directory: `sudo mkdir /var/log/wopi/ && sudo chmod a+rwx /var/log/wopi`
3. Create the folder for the wopi config: `sudo mkdir /etc/wopi/ && sudo chmod a+rwx /etc/wopi`
4. Create recoveryfolder: `sudo mkdir /var/spool/wopirecovery && sudo chmod a+rwx /var/spool/wopirecovery`
5. Create the files `iopsecret` and `wopisecret` in the folder `/etc/wopi/`, create random strings for the secrets
6. Copy the provided [wopiserver.conf](./wopiserver.conf) to `/etc/wopi/wopiserver.defaults.conf`
7. Create a config file `/etc/wopi/wopiserver.conf`: start from `docker/etc/wopiserver.conf` for a minimal configuration and add from the defaults file as needed
8. From the WOPI server folder run: `python3 src/wopiserver.py`

### Test the open-in-app workflow on the local WOPI server

Once the WOPI server runs on top of local storage, the `tools/wopiopen.py` script can be used
to test the open-in-app workflow.
For that, assuming you have e.g. CodiMD deployed in your cluster:

1. Create a `test.md` file in your local storage folder, e.g. `/var/wopi_local_storage`
2. From the WOPI server folder, execute `tools/wopiopen.py -a CodiMD -i "internal_CodiMD_URL" -u "user_visible_CodiMD_URL" -k CodiMD_API_Key test.md`
3. If everything was setup correctly, you'll get a JSON response including an `app-url`. Open it in a browser to access the file. Otherwise, the tool prints the response from the WOPI server and the logs should help troubleshooting the problem.
