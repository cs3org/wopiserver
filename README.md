# WOPI Server

A Vendor-neutral Web-application Open Platform Interface (WOPI) gateway for EFSS systems,
to integrate several Office Online platforms including Microsoft Office Online and Collabora Online.

Author: Giuseppe Lo Presti (@glpatcern) <br/>
Contributions: Michael DSilva (@madsi1m), Lovisa Lugnegaard (@LovisaLugnegard), Samuel Alfageme (@SamuAlfageme), Ishank Arora (@ishank011)

Initial revision: December 2016 <br/>
First production version for CERNBox: September 2017 <br/>
Integration in the CS3 Organisation: April 2020

This project has been presented at the [ownCloud Conference 2017](https://occon17.owncloud.org).
Slides available at [slideshare.net](https://www.slideshare.net/giuseppelopresti/collaborative-editing-and-more-in-cernbox).

## Changelog

[Available here](CHANGELOG.md)

## Unit testing

The `/test` folder contains some unit tests for the supported storage interfaces.
No tests are provided (yet) for the core WOPI server, though the test suite aims at covering all
storage access patterns used by the WOPI server.

By default, the local storage is tested. To run the tests, use the standard python unittest arguments:

1. Go to the test folder `cd test`
2. Run all tests: `python3 test_storageiface.py [-v]`
3. Run only one test: `python3 test_storageiface.py [-v] TestStorage.<the test you would like to run>`

### Test against a Reva endpoint:

1. Clone reva (https://github.com/cs3org/reva)
2. Run Reva according to <https://reva.link/docs/tutorials/share-tutorial/> (ie up until step 4 in the instructions).
3. Go to the test folder `cd test`
4. Run the tests: `WOPI_STORAGE=cs3 python3 test_storageiface.py`

### Test against an Eos endpoint:

1. Make sure your Eos instance is configured to accept connections from WOPI as a privileged gateway
2. Go to the test folder `cd test`
3. Configure `wopiserver-test.conf` according to your Eos setup. The provided defaults are valid at CERN.
4. Run the tests: `WOPI_STORAGE=xroot python3 test_storageiface.py`


## Test the `open` workflow with Reva

1. Run Reva as detailed above
2. Login with `reva login`
3. Extract (from the logs) your `x-access-token`
4. Upload an ODF or .md file with the reva CLI (or copy it to Reva's storage, e.g. in `/var/tmp/reva/data/einstein`)
5. From the wopiserver container, execute `wopiopen.py -v READ_WRITE /<your_file.odt> <your_x-access-token>`
6. If the above call is successful, you are given the URL of the application provider, with appropriate parameters (including a WOPI access token) to open your file: open it in a browser to start your edit session via WOPI

For testing collaborative scenarios, repeat the above for each user participating in the collaborative session. Reusing the `x-access-token` is OK, however it is generally not OK to open multiple times the same application provider URL, and different WOPI access tokens are needed instead.


## Run the WOPI server locally for development purposes

1. Install all requirements listed in `requirements.txt`
2. Add log file directory: `sudo mkdir /var/log/wopi/ && sudo chmod a+rwx /var/log/wopi`
3. Create the folder for the wopi config: `sudo mkdir /etc/wopi/ && sudo chmod a+rwx /etc/wopi`
4. Create the files `iopsecret` and `wopiscret` in the folder `/etc/wopi/`, create random strings for the secrets
5. Create a local config file `/etc/wopi/wopiserver.conf` with the needed parameters: start from `docker/etc/wopiserver.conf`, and make sure that at least an application provider URL is configured (e.g. `codeurl` for Collabora)
6. From the WOPI server folder run: `python3 src/wopiserver.py`

