# WOPI Server

A Vendor-neutral Web-application Open Platform Interface (WOPI) gateway for EFSS systems,
to integrate several Office Online platforms including Microsoft Office Online and Collabora Online.

Author: Giuseppe.LoPresti@cern.ch <br/>
Contributions: Michael.DSilva@aarnet.edu.au

Initial revision: December 2016 <br/>
First production version for CERNBox: September 2017 <br/>
Integration in the CS3 Organisation: April 2020

This project has been presented at the [ownCloud Conference 2017](https://occon17.owncloud.org).
Slides available at [slideshare.net](https://www.slideshare.net/giuseppelopresti/collaborative-editing-and-more-in-cernbox).

## Unit testing

The `/test` folder contains some unit tests for the supported storage interfaces. No tests are provided (yet) for the core WOPI server.

By default, the local storage is tested. To run the tests, use the standard python unittest arguments:

1. Run all tests: `python3 test_storageiface.py [-v]`
2. Run only one test: `python3 test_storageiface.py [-v] TestStorage.<the test you would like to run>`

### Test against a Reva endpoint:

1. Clone reva (https://github.com/cs3org/reva)
2. Configure `grpc.services.storageprovider` in `examples/ocmd/ocmd-server-1.toml` with `disable_tus = true`, it will look like this:

   ```
   ...
   [grpc.services.storageprovider]
   driver = "local"
   mount_path = "/"
   mount_id = "123e4567-e89b-12d3-a456-426655440000"
   expose_data_server = true
   data_server_url = "http://localhost:19001/data"
   enable_home_creation = true
   disable_tus = true
   ...
   ```

3. Run Reva according to <https://reva.link/docs/tutorials/share-tutorial/> (ie up until step 4 in the instructions).
4. Run the tests: `WOPI_STORAGE=cs3 python3 test_storageiface.py`

### Test against an Eos endpoint:

1. Make sure your Eos instance is configured to accept connections from WOPI as a privileged gateway
2. Configure `wopiserver-test.conf` according to your Eos setup. The provided defaults are valid at CERN.
3. Run the tests: `WOPI_STORAGE=xroot python3 test_storageiface.py`
