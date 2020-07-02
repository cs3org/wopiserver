#!/bin/bash
#
# Minimal script to get the WOPI version at build time out of the most recent git tag

ver=`git describe --exact-match HEAD 2> /dev/null`
if [[ $? -gt 0 ]]; then
  ver=`git describe`
fi
echo $ver | sed 's/^v//'
