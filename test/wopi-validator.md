## How to run the wopi-validator on a local setup for testing

These notes have been adaped from the enterprise ownCloud WOPI implementation, credits to @deepdiver1975.

1. Setup your WOPI server as well as Reva as required. Make sure the WOPI storage interface unit tests pass.

2. Create an empty folder and touch a file named `test.wopitest` in that folder. For a local Reva setup:

   `mkdir /var/tmp/reva/data/einstein/wopivalidator && touch /var/tmp/reva/data/einstein/wopivalidator/test.wopitest`.

3. Ensure you run your WOPI server in http mode, that is you have `usehttps = no` in your configuration.

4. Generate the input for the test suite:

   `curl -H "Authorization: Bearer <wopisecret>" "http://your_wopi_server:port/wopi/iop/test?filepath=<your_file>&endpoint=<your_storage_endpoint>&usertoken=<your_user_credentials_or_id>"`

5. Run the testsuite:

   `docker run --rm --add-host="localhost:<your_external_wopiserver_IP>" <output from step 4> deepdiver/wopi-validator-core-docker:latest`

   If you want to select a specific test group, add `-e WOPI_TESTGROUP=<group>` (e.g. `-e WOPI_TESTGROUP=FileVersion`) to the above command.
