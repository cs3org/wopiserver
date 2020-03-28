# WOPIForCodiMD

This is a proof-of-concept WOPI client for CodiMD, to allow bridging a CodiMD instance to a WOPI-enabled EFSS service like ownCloud or CERNBox. It uses the private REST API of CodiMD, which will be hopefully made public and complete in the future.

## What works:
* REST service with two endpoints:
  - `/open`   meant to be called by the EFSS with a WOPISrc and a WOPI access token, returns a file displayed in CodiMD
  - `/close`  auto-called when browsing away from the page displayed by `/open`
* Readonly (publish) mode vs. read/write mode
* Collaborative editing and locking of the file

## CodiMD APIs used 
* `/new`                push a file from WOPI to CodiMD
* `/<noteid>`           display a file
* `/<noteid>/publish`   display a file in readonly mode
* `/<noteid>/download`  get a raw file to push it back to WOPI

## WOPI APIs used
* `GetFileInfo`: get all file metadata
* `GetFile`: get the file content
* `GetLock`: check if the file is locked
* `Lock`: lock a file on open for write
* `PutFile`: store a file's content
* `Unlock`: unlock a file on close

## TODO
* permissions management: e.g. from readonly mode one can switch to edit mode (but modifications are silently dropped)
* blobs management
* detect changes in CodiMD and push them to WOPI every N minutes
* delete files/entries from CodiMD DB
