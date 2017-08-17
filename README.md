# WOPI Server

A Web-application Open Platform Interface (WOPI) gateway for CERNBox
to embed Microsoft Office Online into the CERNBox/OwnCloud web interface

Author: Giuseppe.LoPresti@cern.ch

Contributions: Michael.DSilva@aarnet.edu.au

Initial revision: December 2016

## Environment variables

A container is provided, which takes the following variables from the environment:

- __CONFIGURATION__ - HTTP URL pointing to the configuration files in your-personal-internal-area
- __OCSECRET__ - password between oc and wopiserver
- __WOPISECRET__ - password between wopiserver and oos

