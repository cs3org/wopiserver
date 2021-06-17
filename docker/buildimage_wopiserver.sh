#!/bin/sh
#
# buildimage.sh
#
# This script can be used to generate a docker image of the WOPI server.
# Prior to run it, you need to collect here a valid wopiserver.conf and
# an iopsecret file that contains a shared secret used to strengthen the
# open REST endpoint, as they give access to any file of the underlying
# storage: the secret is only to be used between the client of the
# /wopi/iop/open endpoint and the WOPI server.
#
# If you want the WOPI server to run in secure mode, you need to generate
# a certificate/key with the hostname of the node that will be running 
# the generated docker image, and copy them into the generated image.

pushd ..
make rpm
make clean
popd
mv ../cernbox-wopi*rpm .

sudo docker build -t your-personal-repo-area/cloudstor-wopi-server --pull=true --no-cache --force-rm wopiserver.Dockerfile && \
sudo docker push your-personal-repo-area/cloudstor-wopi-server
