# WOPI Bridge

This is a proof-of-concept WOPI bridge server, currently only targeting CodiMD, to allow bridging it to a WOPI-enabled EFSS service like ownCloud or CERNBox. It uses the private REST API of CodiMD, which will be hopefully made public and complete in the future. The approach is generic to allow for extending the concept to other Office-like applications exposing a minimal load/save REST API.

## What works
* REST service with two endpoints:
  - `/open`   meant to be called by the EFSS with a WOPISrc and a WOPI access token, returns a file displayed in CodiMD
  - `/save`   auto-called by the CodiMD backend when some changes are detected on the open document
* Stateless server, all context stored in the WOPI lock or passed through arguments
* Readonly (publish or slide) mode vs. read/write mode
* Collaborative editing and locking of the file
* Transparent handling of uploads (i.e. pictures):
  * If a note has no pictures, it is handled as a `.md` text file
  * Once a picture is included, on close the save to WOPI is executed as a zipped bundle, with a `.zmd` extension, and the previous `.md` file is removed; similarly if all pictures are removed and the file is saved back as `.md`
  * Files ending as `.zmd` are equally treated as zipped bundles and expanded to CodiMD

### Required CodiMD APIs
* `/new`                    push a new file to a random `<noteid>`
* `/<noteid>`               display a file, or reserve a `<noteid>` if not existing
* `/<noteid>/publish`       display a file in readonly mode
* `/<noteid>/slide`         display a file in slide mode
* `/<noteid>/download`      get a raw file to store it back
* `/uploadimage`            upload a new picture
* `/uploads/upload_<hash>`  get an uploaded picture
* `/api/notes/<noteid>`     update a file via PUT

### Required WOPI APIs
* `GetFileInfo`: get all file metadata
* `GetFile`: get the file content
* `GetLock`: check if the file is locked
* `Lock`: lock a file on open for write
* `PutFile`: store a file's content
* `PutRelative`: store a file under a different name
* `Unlock`: unlock a file on close
* `Delete`: delete a previous edition of a file

## Changelog

[Available here](CHANGELOG.md)
