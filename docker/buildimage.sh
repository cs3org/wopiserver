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
make rpm
make clean
popd
mv ../cernbox-wopi*rpm .

# if no secret was provided, provide one for bootstrapping the
# image. Of course, the WOPI server won't show more than its index page.
[[ -e ocsecret ]] || echo 'your OwnCloud secret' > ocsecret
chmod 400 ocsecret

# build and run the image
docker build -t wopi .
docker run -t -v /var/log/wopi:/var/log/wopi --net=host -d wopi
