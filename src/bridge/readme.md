## WOPI server - bridge module

This module includes the code once prototyped at https://github.com/cs3org/wopibridge, to integrate collaborative editors such as CodiMD and Etherpad (partially supported for the time being). The approach is generic to allow for extending the concept to other Office-like applications exposing a minimal load/save REST API.

The module provides two endpoints:
- `/wopi/bridge/<docid>`  auto-called by the app backends when some changes are detected on the open document referenced as `<docid>`
- `/wopi/bridge/list`  for operators only, it returns a list of all currently opened files in bridge mode

The module implements a stateless server, as all context information is stored in WOPI locks or passed through arguments. Collaborative editing and locking of files is supported by means of the following WOPI APIs:
* `GetFileInfo`: get all file metadata
* `GetFile`: get the file content
* `GetLock`: check if the file is locked
* `Lock`: lock a file on open for write
* `PutFile`: store a file's content
* `PutRelative`: store a file under a different name
* `Unlock`: unlock a file on close
* `Delete`: delete a previous edition of a file


### CodiMD specifics
* Support for readonly (publish or slide) mode vs. read/write mode
* Inclusion of pictures supported according to file extension:
  * For plain `.md` files, directly incorporating pictures is disabled, but a cloud file-picker is enabled to allow incorporating links to external pictures
  * If a file is created as `.zmd` (for _zipped markdown_), it is possible to include pictures and the save to WOPI is executed as a zipped bundle, including all pictures (if any) in the bundle. On load, `.zmd` files are transparently expanded to CodiMD

#### Required CodiMD APIs
* `/new`                    push a new file to a random `<noteid>`
* `/<noteid>`               display a file, or reserve a `<noteid>` if not existing
* `/<noteid>/publish`       display a file in readonly mode
* `/<noteid>/slide`         display a file in slide mode
* `/<noteid>/download`      get a raw file to store it back
* `/uploadimage`            upload a new picture
* `/uploads/upload_<hash>`  get an uploaded picture
* `/api/notes/<noteid>`     update a file via PUT


### Etherpad specifics

This is still work in progress as the etherpad plugin is incomplete.
* Support for readonly and read/write files
* Automatic save via dedicated `ep_sciencemesh` plugin
