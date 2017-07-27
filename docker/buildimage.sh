#!/bin/sh
#
# buildimage.sh
#
# This script can be used to generate a docker image of the WOPI server.
# Prior to run it, you need to collect here a valid wopiserver.conf and
# an ocsecret file that contains the shared secret used by your OwnCloud
# servers to authenticate to the WOPI server.
#
# If you want the WOPI server to run in secure mode, you need to generate
# a certificate/key with the hostname of the node that will be running 
# the generated docker image, and copy them into the generated image.

pushd ..
sed -i 's/, nginx//' *spec
make rpm
make clean
popd
mv ../cernbox-wopi*rpm .

sudo docker build -t your-personal-repo-area/cloudstor-wopi-server --pull=true --no-cache --force-rm . && \
sudo docker push your-personal-repo-area/cloudstor-wopi-server
