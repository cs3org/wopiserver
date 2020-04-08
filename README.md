# WOPI For CodiMD

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
* blobs management: uploaded files end up in the designated uploads folder in CodiMD, need to fetch them back and associate them to the md file "forever" in the storage. Could do the association via xattrs, but API required to fetch blobs from CodiMD
* detect changes in CodiMD and push them to WOPI every N minutes
* delete files/entries from CodiMD DB

### Required CodiMD APIs to implement the above features
* given a note id, change permissions of a note, e.g. make it read only.
* upload a file to be used as "attachment": a proposal could be an HTTP POST to `/<nodeid>/attach` with the attachment in the payload. The payload could be a zip file for multiple attachments.
* download all attached files of a given note. E.g. GET `/<nodeid>/attach` to return a zip of all files.
* given a note id, delete a note from DB as well as its attached files.
* given a note id, return the note's last modification time.
