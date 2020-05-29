# WOPI Server

A Vendor-neutral Web-application Open Platform Interface (WOPI) gateway for EFSS systems,
to integrate several Office Online platforms including Microsoft Office Online and Collabora Online.

Author: Giuseppe.LoPresti@cern.ch (@glpatcern) <br/>
Contributions: Michael.DSilva@aarnet.edu.au (@madsi1m), Lovisa.Lugnegaard@cern.ch (@LovisaLugnegard), Samuel.Alfageme@cern.ch (@SamuAlfageme)

Initial revision: December 2016 <br/>
First production version for CERNBox: September 2017 <br/>
Integration in the CS3 Organisation: April 2020

This project has been presented at the [ownCloud Conference 2017](https://occon17.owncloud.org).
Slides available at [slideshare.net](https://www.slideshare.net/giuseppelopresti/collaborative-editing-and-more-in-cernbox).

## Unit testing

The `/test` folder contains some unit tests for the supported storage interfaces. No tests are provided (yet) for the core WOPI server.

By default, the local storage is tested. To run the tests, use the standard python unittest arguments:

1. Go to the test folder `cd test`
2. Run all tests: `python3 test_storageiface.py [-v]`
3. Run only one test: `python3 test_storageiface.py [-v] TestStorage.<the test you would like to run>`

### Test against a Reva endpoint:

1. Clone reva (https://github.com/cs3org/reva)
2. Configure `http.services.dataprovider` in `examples/ocmd/ocmd-server-1.toml` with `disable_tus = true`, it will look like this:

   ```
   ...
   [http.services.dataprovider]
   driver = "local"
   temp_folder = "/var/tmp/"
   disable_tus = true
   ...
   ```

3. Run Reva according to <https://reva.link/docs/tutorials/share-tutorial/> (ie up until step 4 in the instructions).
4. Go to the test folder `cd test`
5. Run the tests: `WOPI_STORAGE=cs3 python3 test_storageiface.py`

### Test against an Eos endpoint:

1. Make sure your Eos instance is configured to accept connections from WOPI as a privileged gateway
2. Go to the test folder `cd test`
3. Configure `wopiserver-test.conf` according to your Eos setup. The provided defaults are valid at CERN.
4. Run the tests: `WOPI_STORAGE=xroot python3 test_storageiface.py`
