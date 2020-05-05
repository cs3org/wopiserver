# WOPI Bridge for CodiMD

This is a proof-of-concept WOPI bridge server targeting CodiMD, to allow bridging a CodiMD instance to a WOPI-enabled EFSS service like ownCloud or CERNBox. It uses the private REST API of CodiMD, which will be hopefully made public and complete in the future. The approach is generic to allow for extending the concept to other Office-like applications exposing a minimal load/save REST API.

## What works:
* REST service with two endpoints:
  - `/open`   meant to be called by the EFSS with a WOPISrc and a WOPI access token, returns a file displayed in CodiMD
  - `/close`  auto-called when browsing away from the page displayed by `/open`
* Stateless server, all context stored in the WOPI lock or passed through arguments
* Readonly (publish) mode vs. read/write mode
* Collaborative editing and locking of the file
* Transparent handling of uploads (i.e. pictures):
  * If a note has no pictures, it is handled as a text file.
  * Once a picture is included, the save to WOPI is executed as a zipped bundle, with a `.mtx` extension.
  * Files ending as `.mtx` are equally treated as zipped bundles and expanded to CodiMD: this currently requires direct access to the underlying storage used by CodiMD when pushing the pictures from the EFSS storage.

## CodiMD APIs used 
* `/new`                        push a file from WOPI to CodiMD
* `/<noteid>`                   display a file
* `/<noteid>/publish`           display a file in readonly mode
* `/<noteid>/download`          get a raw file to push it back to WOPI
* `/uploads/upload_<filename>`  get an uploaded picture/attachment

## WOPI APIs used
* `GetFileInfo`: get all file metadata
* `GetFile`: get the file content
* `GetLock`: check if the file is locked
* `Lock`: lock a file on open for write
* `PutFile`: store a file's content
* `PutRelative`: store a file under a different name
* `Unlock`: unlock a file on close

## TODO
* permissions management: e.g. from readonly mode one can switch to edit mode (but modifications are silently dropped)
* detect changes in CodiMD and push them to WOPI every N minutes
* delete files/entries from CodiMD DB

### Required CodiMD APIs to implement the above features
* given a note id and a user id, change permissions of a note for that user. In particular make it read only.
* given a note id, delete a note from DB as well as its attached files.
* given a note id, return the note's last modification time.

