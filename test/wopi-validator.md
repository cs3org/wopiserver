# How to run the wopi-validator on a local setup for testing

These notes have been adaped from the enterprise ownCloud WOPI implementation, credits to @deepdiver1975.

1. Setup your WOPI server as well as Reva as required. Make sure the WOPI storage interface unit tests pass.

2. Create an empty file named `test.wopitest` in the user folder, e.g. `touch /var/tmp/reva/einstein/test.wopitest` for a local Reva setup.

3. Generate a WOPI URL and token for that file, e.g. `wopiopen.py /test.wopitest 1000 1000`. Remote setups would require appropriate userids and file paths.

4. Amend the `WOPI_URL` env variable such that it looks like `http://localhost:<wopiport>/wopi/files/<fileid>`. Note the hardcoded `localhost`.

5. Run the testsuite (you can select a specific test group with e.g. `-e WOPI_TESTGROUP=FileVersion`):
`docker run --add-host="localhost:<your_external_wopiserver_IP>" -e WOPI_URL=$WOPI_URL -e WOPI_TOKEN=$WOPI_TOKEN deepdiver/wopi-validator-core-docker:use-different-branch-to-make-ci-finally-green`

