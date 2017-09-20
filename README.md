# WOPI Server

A Web-application Open Platform Interface (WOPI) gateway for CERNBox
to embed Microsoft Office Online into the CERNBox/OwnCloud web interface

Author: Giuseppe.LoPresti@cern.ch <br/>
Contributions: Michael.DSilva@aarnet.edu.au

Initial revision: December 2016 <br/>
First production version: September 2017

This project has been presented at the [ownCloud Conference 2017](https://occon17.owncloud.org).
Slides available at [slideshare.net](https://www.slideshare.net/giuseppelopresti/collaborative-editing-and-more-in-cernbox).

## Environment variables

A docker container is provided, which takes the following variables from the environment:

- __CONFIGURATION__ - HTTP URL pointing to the configuration files in your-personal-internal-area
- __OCSECRET__ - password between oc and wopiserver
- __WOPISECRET__ - password between wopiserver and oos

