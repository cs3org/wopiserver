#!/usr/bin/env python3
'''
srv.py

Implementation of the core WOPI API
'''

import time
import os
import configparser
import json
import http.client
from urllib.parse import quote_plus as url_quote_plus
from urllib.parse import unquote as url_unquote
from more_itertools import peekable
import jwt
import flask
import core.wopiutils as utils


# convenience references to global entities
st = None
srv = None
log = None
enablerename = False

def checkFileInfo(fileid):
    '''Implements the CheckFileInfo WOPI call'''
    # cf. http://wopi.readthedocs.io/projects/wopirest/en/latest/files/CheckFileInfo.html
    srv.refreshconfig()
    try:
        acctok = jwt.decode(flask.request.args['access_token'], srv.wopisecret, algorithms=['HS256'])
        acctok['viewmode'] = utils.ViewMode(acctok['viewmode'])
        if acctok['exp'] < time.time():
            raise jwt.exceptions.ExpiredSignatureError
        log.info('msg="CheckFileInfo" user="%s" filename="%s" fileid="%s" token="%s"' %
                 (acctok['userid'][-20:], acctok['filename'], fileid, flask.request.args['access_token'][-20:]))
        statInfo = st.statx(acctok['endpoint'], acctok['filename'], acctok['userid'], versioninv=1)
        # compute some entities for the response
        wopiSrc = 'WOPISrc=%s&access_token=%s' % (utils.generateWopiSrc(fileid), flask.request.args['access_token'])
        # populate metadata for this file
        filemd = {}
        filemd['BaseFileName'] = filemd['BreadcrumbDocName'] = os.path.basename(acctok['filename'])
        furl = acctok['folderurl']
        # encode the path part as it is going to be an URL GET argument
        filemd['BreadcrumbFolderUrl'] = furl[:furl.find('=')+1] + url_quote_plus(furl[furl.find('=')+1:]) if furl != '/' else ''
        if acctok['username'] == '':
            filemd['UserFriendlyName'] = 'Guest ' + utils.randomString(3)
            if '?path' in furl and furl[-1] != '/' and furl[-1] != '=':
                # this is a subfolder of a public share, show it
                filemd['BreadcrumbFolderName'] = 'Back to ' + furl[furl.find('?path'):].split('/')[-1]
            else:
                # this is the top level public share, which is anonymous
                filemd['BreadcrumbFolderName'] = 'Back to the public share'
        else:
            filemd['UserFriendlyName'] = acctok['username']
            filemd['BreadcrumbFolderName'] = 'Back to ' + os.path.dirname(acctok['filename'])
        if furl == '/':    # if no target folder URL was given, override the above and completely hide it
            filemd['BreadcrumbFolderName'] = ''
        if acctok['viewmode'] in (utils.ViewMode.READ_ONLY, utils.ViewMode.READ_WRITE):
            filemd['DownloadUrl'] = '%s?access_token=%s' % \
                                    (srv.config.get('general', 'downloadurl'), flask.request.args['access_token'])
        filemd['OwnerId'] = statInfo['ownerid']
        filemd['UserId'] = acctok['wopiuser']     # typically same as OwnerId; different when accessing shared documents
        filemd['Size'] = statInfo['size']
        # TODO the version is generated like this in ownCloud: 'V' . $file->getEtag() . \md5($file->getChecksum());
        filemd['Version'] = statInfo['mtime']   # mtime is used as version here
        filemd['SupportsExtendedLockLength'] = filemd['SupportsGetLock'] = True
        filemd['SupportsUpdate'] = filemd['UserCanWrite'] = filemd['SupportsLocks'] = \
            filemd['SupportsDeleteFile'] = acctok['viewmode'] == utils.ViewMode.READ_WRITE
        filemd['UserCanNotWriteRelative'] = acctok['viewmode'] != utils.ViewMode.READ_WRITE
        filemd['HostViewUrl'] = '%s%s%s' % (acctok['appviewurl'], '&' if '?' in acctok['appviewurl'] else '?', wopiSrc)
        filemd['HostEditUrl'] = '%s%s%s' % (acctok['appediturl'], '&' if '?' in acctok['appediturl'] else '?', wopiSrc)
        filemd['SupportsRename'] = filemd['UserCanRename'] = enablerename and utils.ViewMode.READ_WRITE
        # populate app-specific metadata
        if acctok['appname'].find('Microsoft') > 0:
            # the following is to enable the 'Edit in Word/Excel/PowerPoint' (desktop) action (probably broken)
            try:
                filemd['ClientUrl'] = srv.config.get('general', 'webdavurl') + '/' + acctok['filename']
            except configparser.NoOptionError:
                # if no WebDAV URL is provided, ignore this setting
                pass
        # extensions for Collabora Online
        filemd['EnableOwnerTermination'] = True
        filemd['DisableExport'] = filemd['DisableCopy'] = filemd['DisablePrint'] = acctok['viewmode'] == utils.ViewMode.VIEW_ONLY
        #filemd['LastModifiedTime'] = datetime.fromtimestamp(int(statInfo['mtime'])).isoformat()   # this currently breaks

        log.info('msg="File metadata response" token="%s" metadata="%s"' % (flask.request.args['access_token'][-20:], filemd))
        return flask.Response(json.dumps(filemd), mimetype='application/json')
    except IOError as e:
        log.info('msg="Requested file not found" filename="%s" token="%s" error="%s"' %
                 (acctok['filename'], flask.request.args['access_token'][-20:], e))
        return 'File not found', http.client.NOT_FOUND
    except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError) as e:
        log.warning('msg="Signature verification failed" client="%s" requestedUrl="%s" token="%s"' %
                    (flask.request.remote_addr, flask.request.base_url, flask.request.args['access_token']))
        return 'Invalid access token', http.client.UNAUTHORIZED
    except KeyError as e:
        log.warning('msg="Invalid access token or request argument" error="%s" request="%s"' % (e, flask.request.__dict__))
        return 'Invalid request', http.client.UNAUTHORIZED


def getFile(fileid):
    '''Implements the GetFile WOPI call'''
    srv.refreshconfig()
    try:
        acctok = jwt.decode(flask.request.args['access_token'], srv.wopisecret, algorithms=['HS256'])
        if acctok['exp'] < time.time():
            raise jwt.exceptions.ExpiredSignatureError
        log.info('msg="GetFile" user="%s" filename="%s" fileid="%s" token="%s"' %
                 (acctok['userid'][-20:], acctok['filename'], fileid, flask.request.args['access_token'][-20:]))
        # get the file reader generator
        f = peekable(st.readfile(acctok['endpoint'], acctok['filename'], acctok['userid']))
        firstchunk = f.peek()
        if isinstance(firstchunk, IOError):
            return ('Failed to fetch file from storage: %s' % firstchunk), http.client.INTERNAL_SERVER_ERROR
        # stream file from storage to client
        resp = flask.Response(f, mimetype='application/octet-stream')
        resp.status_code = http.client.OK
        return resp
    except StopIteration as e:
        # File is empty, still return OK (strictly speaking, we should return 204 NO_CONTENT)
        return '', http.client.OK
    except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError) as e:
        log.warning('msg="Signature verification failed" client="%s" requestedUrl="%s" error="%s" token="%s"' %
                    (flask.request.remote_addr, flask.request.base_url, e, flask.request.args['access_token']))
        return 'Invalid access token', http.client.UNAUTHORIZED


#
# The following operations are all called on POST /wopi/files/<fileid>
#
def unlock(fileid, reqheaders, acctok, force=False):
    '''Implements the Unlock WOPI call'''
    lock = reqheaders['X-WOPI-Lock']
    retrievedLock = utils.retrieveWopiLock(fileid, 'UNLOCK', lock, acctok)
    if not force and not utils.compareWopiLocks(retrievedLock, lock):
        return utils.makeConflictResponse('UNLOCK', retrievedLock, lock, '', acctok['filename'])
    # OK, the lock matches. Remove any extended attribute related to locks and conflicts handling
    try:
        st.removefile(acctok['endpoint'], utils.getLockName(acctok['filename']), acctok['userid'], 1)
    except IOError:
        # ignore, it's not worth to report anything here
        pass
    try:
        st.rmxattr(acctok['endpoint'], acctok['filename'], acctok['userid'], utils.LASTSAVETIMEKEY)
    except IOError:
        # same as above
        pass
    try:
        # also remove the LibreOffice-compatible lock file when relevant
        if os.path.splitext(acctok['filename'])[1] not in srv.nonofficetypes:
            st.removefile(acctok['endpoint'], utils.getLibreOfficeLockName(acctok['filename']), acctok['userid'], 1)
    except IOError:
        # same as above
        pass
    # and update our internal list of opened files
    if not force:
        try:
            del srv.openfiles[acctok['filename']]
        except KeyError:
            # already removed?
            pass
    return 'OK', http.client.OK


def setLock(fileid, reqheaders, acctok):
    '''Implements the Lock, RefreshLock, and UnlockAndRelock WOPI calls'''
    # cf. http://wopi.readthedocs.io/projects/wopirest/en/latest/files/Lock.html
    op = reqheaders['X-WOPI-Override']
    lock = reqheaders['X-WOPI-Lock']
    oldLock = reqheaders.get('X-WOPI-OldLock')
    validateTarget = reqheaders.get('X-WOPI-Validate-Target')
    retrievedLock = utils.retrieveWopiLock(fileid, op, lock, acctok)

    # perform the required checks for the validity of the new lock
    if not retrievedLock and op == 'REFRESH_LOCK':
        if validateTarget:
            # this is an extension of the API: a REFRESH_LOCK without previous lock but with a Validate-Target header
            # is allowed provided that the target file was last saved by WOPI and not overwritten by external actions,
            # that is it must have a valid LASTSAVETIMEKEY xattr
            savetime = st.getxattr(acctok['endpoint'], acctok['filename'], acctok['userid'], utils.LASTSAVETIMEKEY)
        else:
            savetime = None
        if not savetime or not savetime.isdigit():
            return utils.makeConflictResponse(op, '', lock, oldLock, acctok['filename'],
                                              'The file was not locked' + ' and got modified' if validateTarget else '')
    if retrievedLock and not utils.compareWopiLocks(retrievedLock, (oldLock if oldLock else lock)):
        return utils.makeConflictResponse(op, retrievedLock, lock, oldLock, acctok['filename'], \
                                          'The file was locked by another online editor')

    # LOCK or REFRESH_LOCK: set the lock to the given one, including the expiration time
    try:
        utils.storeWopiLock(op, lock, acctok, os.path.splitext(acctok['filename'])[1] not in srv.nonofficetypes)
    except IOError as e:
        if utils.EXCL_ERROR in str(e):
            # this file was already locked externally: storeWopiLock looks at LibreOffice-compatible locks
            return utils.makeConflictResponse(op, 'External App', lock, oldLock, acctok['filename'], \
                                              'The file was locked by another application')
        if 'No such file or directory' in str(e):
            # the file got renamed/deleted: this is equivalent to a conflict
            return utils.makeConflictResponse(op, 'External App', lock, oldLock, acctok['filename'], \
                                              'The file got moved or deleted')
        # any other failure
        return str(e), http.client.INTERNAL_SERVER_ERROR
    if not retrievedLock:
        # on first lock, set an xattr with the current time for later conflicts checking
        try:
            st.setxattr(acctok['endpoint'], acctok['filename'], acctok['userid'], utils.LASTSAVETIMEKEY, int(time.time()))
        except IOError as e:
            # not fatal, but will generate a conflict file later on, so log a warning
            log.warning('msg="Unable to set lastwritetime xattr" user="%s" filename="%s" token="%s" reason="%s"' %
                        (acctok['userid'][-20:], acctok['filename'], flask.request.args['access_token'][-20:], e))
        # also, keep track of files that have been opened for write: this is for statistical purposes only
        # (cf. the GetLock WOPI call and the /wopi/cbox/open/list action)
        if acctok['filename'] not in srv.openfiles:
            srv.openfiles[acctok['filename']] = (time.asctime(), set([acctok['username']]))
        else:
            # the file was already opened but without lock: this happens on new files (cf. editnew action), just log
            log.info('msg="First lock for new file" user="%s" filename="%s" token="%s"' %
                     (acctok['userid'][-20:], acctok['filename'], flask.request.args['access_token'][-20:]))
    return 'OK', http.client.OK


def getLock(fileid, _reqheaders_unused, acctok):
    '''Implements the GetLock WOPI call'''
    resp = flask.Response()
    lock = utils.retrieveWopiLock(fileid, 'GETLOCK', '', acctok)
    resp.status_code = http.client.OK if lock else http.client.NOT_FOUND
    if lock:
        resp.headers['X-WOPI-Lock'] = lock
        # for statistical purposes, check whether a lock exists and update internal bookkeeping
        try:
            # the file was already opened for write, check whether this is a new user
            if not acctok['username'] in srv.openfiles[acctok['filename']][1]:
                # yes it's a new user
                srv.openfiles[acctok['filename']][1].add(acctok['username'])
                if len(srv.openfiles[acctok['filename']][1]) > 1:
                    # for later monitoring, explicitly log that this file is being edited by at least two users
                    log.info('msg="Collaborative editing detected" filename="%s" token="%s" users="%s"' %
                             (acctok['filename'], flask.request.args['access_token'][-20:],
                              list(srv.openfiles[acctok['filename']][1])))
        except KeyError:
            # existing lock but missing srv.openfiles[acctok['filename']] ?
            log.warning('msg="Repopulating missing metadata" filename="%s" token="%s" friendlyname="%s"' %
                        (acctok['filename'], flask.request.args['access_token'][-20:], acctok['username']))
            srv.openfiles[acctok['filename']] = (time.asctime(), set([acctok['username']]))
    # we might want to check if a non-WOPI lock exists for this file:
    #if os.path.splitext(acctok['filename'])[1] not in srv.nonofficetypes:
    #  try:
    #    lockstat = st.stat(acctok['endpoint'], utils.getLibreOfficeLockName(acctok['filename']), acctok['userid'])
    #    return utils.makeConflictResponse('GetLock', 'External App', '', '', acctok['filename'], \
    #                                      'The file was locked by LibreOffice for Desktop')
    #  except IOError:
    #    pass
    # however implications have to be properly understood as we've seen cases of locks left behind
    return resp


def putRelative(fileid, reqheaders, acctok):
    '''Implements the PutRelative WOPI call. Corresponds to the 'Save as...' menu entry.'''
    # cf. http://wopi.readthedocs.io/projects/wopirest/en/latest/files/PutRelativeFile.html
    suggTarget = reqheaders.get('X-WOPI-SuggestedTarget')
    relTarget = reqheaders.get('X-WOPI-RelativeTarget')
    overwriteTarget = bool(reqheaders.get('X-WOPI-OverwriteRelativeTarget'))
    log.info('msg="PutRelative" user="%s" filename="%s" fileid="%s" suggTarget="%s" relTarget="%s" '
             'overwrite="%r" token="%s"' %
             (acctok['userid'], acctok['filename'], fileid, \
              suggTarget, relTarget, overwriteTarget, flask.request.args['access_token'][-20:]))
    # either one xor the other must be present; note we can't use `^` as we have a mix of str and NoneType
    if (suggTarget and relTarget) or (not suggTarget and not relTarget):
        return 'Not supported', http.client.NOT_IMPLEMENTED
    if suggTarget:
        # the suggested target is a filename that can be changed to avoid collisions
        if suggTarget[0] == '.':    # we just have the extension here
            targetName = os.path.splitext(acctok['filename'])[0] + suggTarget
        else:
            targetName = os.path.dirname(acctok['filename']) + os.path.sep + suggTarget
        # check for existence of the target file and adjust until a non-existing one is obtained
        while True:
            try:
                st.stat(acctok['endpoint'], targetName, acctok['userid'])
                # the file exists: try a different name
                name, ext = os.path.splitext(targetName)
                targetName = name + '_copy' + ext
            except IOError as e:
                if 'No such file or directory' in str(e):
                    # OK, the targetName is good to go
                    break
                # we got another error with this file, fail
                log.info('msg="PutRelative" user="%s" filename="%s" token="%s" suggTarget="%s" error="%s"' %
                         (acctok['userid'][-20:], targetName, flask.request.args['access_token'][-20:], \
                          suggTarget, str(e)))
                return 'Illegal filename %s: %s' % (targetName, e), http.client.BAD_REQUEST
    else:
        # the relative target is a filename to be respected, and that may overwrite an existing file
        relTarget = os.path.dirname(acctok['filename']) + os.path.sep + relTarget    # make full path
        try:
            # check for file existence + lock
            fileExists = st.stat(acctok['endpoint'], relTarget, acctok['userid'])
            retrievedTargetLock = utils.retrieveWopiLock(fileid, 'PUT_RELATIVE', None, acctok, overridefilename=relTarget)
        except IOError:
            fileExists = False
        if fileExists and (not overwriteTarget or retrievedTargetLock):
            return utils.makeConflictResponse('PUT_RELATIVE', retrievedTargetLock, '', '', relTarget,
                                              'Target file already exists')
        # else we can use the relative target
        targetName = relTarget
    # either way, we now have a targetName to save the file: attempt to do so
    try:
        utils.storeWopiFile(flask.request, acctok, utils.LASTSAVETIMEKEY, targetName)
    except IOError as e:
        log.info('msg="Error writing file" filename="%s" token="%s" error="%s"' %
                 (targetName, flask.request.args['access_token'][-20:], e))
        return 'I/O Error', http.client.INTERNAL_SERVER_ERROR
    # generate an access token for the new file
    log.info('msg="PutRelative: generating new access token" user="%s" filename="%s" ' \
             'mode="ViewMode.READ_WRITE" friendlyname="%s"' %
             (acctok['userid'][-20:], targetName, acctok['username']))
    inode, newacctok = utils.generateAccessToken(acctok['userid'], targetName, utils.ViewMode.READ_WRITE,
                                                 (acctok['username'], acctok['wopiuser']), \
                                                 acctok['folderurl'], acctok['endpoint'], \
                                                 (acctok['appname'], acctok['appediturl'], acctok['appviewurl']))
    # prepare and send the response as JSON
    putrelmd = {}
    putrelmd['Name'] = os.path.basename(targetName)
    putrelmd['Url'] = '%s?access_token=%s' % (utils.generateWopiSrc(inode), newacctok)
    putrelmd['HostEditUrl'] = '%s%sWOPISrc=%s&access_token=%s' % \
                              (acctok['appediturl'], '&' if '?' in acctok['appediturl'] else '?',
                               utils.generateWopiSrc(inode), newacctok)
    log.debug('msg="PutRelative response" token="%s" metadata="%s"' % (newacctok[-20:], putrelmd))
    return flask.Response(json.dumps(putrelmd), mimetype='application/json')


def deleteFile(fileid, _reqheaders_unused, acctok):
    '''Implements the DeleteFile WOPI call'''
    retrievedLock = utils.retrieveWopiLock(fileid, 'DELETE', '', acctok)
    if retrievedLock is not None:
        # file is locked and cannot be deleted
        return utils.makeConflictResponse('DELETE', retrievedLock, '', '', acctok['filename'])
    try:
        st.removefile(acctok['endpoint'], acctok['filename'], acctok['userid'])
        return 'OK', http.client.OK
    except IOError as e:
        log.info('msg="DeleteFile" token="%s" error="%s"' % (flask.request.args['access_token'][-20:], e))
        return 'Internal error', http.client.INTERNAL_SERVER_ERROR


def renameFile(fileid, reqheaders, acctok):
    '''Implements the RenameFile WOPI call.'''
    targetName = reqheaders['X-WOPI-RequestedName']
    lock = reqheaders['X-WOPI-Lock'] if 'X-WOPI-Lock' in reqheaders else None
    retrievedLock = utils.retrieveWopiLock(fileid, 'RENAMEFILE', lock, acctok)
    if retrievedLock is not None and not utils.compareWopiLocks(retrievedLock, lock):
        return utils.makeConflictResponse('RENAMEFILE', retrievedLock, lock, '', acctok['filename'])
    try:
        # the destination name comes without base path and without extension
        targetName = os.path.dirname(acctok['filename']) + '/' + targetName + os.path.splitext(acctok['filename'])[1]
        log.info('msg="RenameFile" user="%s" filename="%s" token="%s" targetname="%s"' %
                 (acctok['userid'][-20:], acctok['filename'], flask.request.args['access_token'][-20:], targetName))
        st.renamefile(acctok['endpoint'], acctok['filename'], targetName, acctok['userid'])
        # also rename the locks
        st.renamefile(acctok['endpoint'], utils.getLockName(acctok['filename']), \
                      utils.getLockName(targetName), acctok['userid'])
        if os.path.splitext(acctok['filename'])[1] not in srv.nonofficetypes:
            st.renamefile(acctok['endpoint'], utils.getLibreOfficeLockName(acctok['filename']), \
                          utils.getLibreOfficeLockName(targetName), acctok['userid'])
        # prepare and send the response as JSON
        renamemd = {}
        renamemd['Name'] = reqheaders['X-WOPI-RequestedName']
        return flask.Response(json.dumps(renamemd), mimetype='application/json')
    except IOError as e:
        # assume the rename failed because of the destination filename and report the error
        log.info('msg="RenameFile" token="%s" error="%s"' % (flask.request.args['access_token'][-20:], e))
        resp = flask.Response()
        resp.headers['X-WOPI-InvalidFileNameError'] = 'Failed to rename: %s' % e
        resp.status_code = http.client.BAD_REQUEST
        return resp


def _createNewFile(fileid, acctok):
    '''Implements the editnew action as part of the PutFile WOPI call.'''
    log.info('msg="PutFile" user="%s" filename="%s" fileid="%s" action="editnew" token="%s"' %
             (acctok['userid'][-20:], acctok['filename'], fileid, flask.request.args['access_token'][-20:]))
    try:
        # try to stat the file and raise IOError if not there
        if st.stat(acctok['endpoint'], acctok['filename'], acctok['userid'])['size'] == 0:
            # a 0-size file is equivalent to not existing
            raise IOError
        log.warning('msg="PutFile" error="File exists but no WOPI lock provided" filename="%s" token="%s"' %
                    (acctok['filename'], flask.request.args['access_token']))
        return 'File exists', http.client.CONFLICT
    except IOError:
        # indeed the file did not exist, so we write it for the first time
        utils.storeWopiFile(flask.request, acctok, utils.LASTSAVETIMEKEY)
        log.info('msg="File stored successfully" action="editnew" user="%s" filename="%s" token="%s"' %
                 (acctok['userid'][-20:], acctok['filename'], flask.request.args['access_token'][-20:]))
        # and we keep track of it as an open file with timestamp = Epoch, despite not having any lock yet.
        # XXX this is to work around an issue with concurrent editing of newly created files (cf. iopOpen)
        srv.openfiles[acctok['filename']] = ('0', set([acctok['username']]))
        return 'OK', http.client.OK


def putFile(fileid):
    '''Implements the PutFile WOPI call'''
    srv.refreshconfig()
    try:
        acctok = jwt.decode(flask.request.args['access_token'], srv.wopisecret, algorithms=['HS256'])
        if acctok['exp'] < time.time():
            raise jwt.exceptions.ExpiredSignatureError
        if 'X-WOPI-Lock' not in flask.request.headers:
            # no lock given: assume we are in creation mode (cf. editnew WOPI action)
            return _createNewFile(fileid, acctok)
        # otherwise, check that the caller holds the current lock on the file
        lock = flask.request.headers['X-WOPI-Lock']
        retrievedLock = utils.retrieveWopiLock(fileid, 'PUTFILE', lock, acctok)
        if retrievedLock is None:
            return utils.makeConflictResponse('PUTFILE', retrievedLock, lock, '', acctok['filename'], \
                                              'Cannot overwrite unlocked file')
        if not utils.compareWopiLocks(retrievedLock, lock):
            return utils.makeConflictResponse('PUTFILE', retrievedLock, lock, '', acctok['filename'], \
                                              'Cannot overwrite file locked by another application')
        # OK, we can save the file now
        log.info('msg="PutFile" user="%s" filename="%s" fileid="%s" action="edit" token="%s"' %
                 (acctok['userid'][-20:], acctok['filename'], fileid, flask.request.args['access_token'][-20:]))
        try:
            # check now the destination file against conflicts
            savetime = st.getxattr(acctok['endpoint'], acctok['filename'], acctok['userid'], utils.LASTSAVETIMEKEY)
            mtime = None
            mtime = st.stat(acctok['endpoint'], acctok['filename'], acctok['userid'])['mtime']
            if savetime is None or not savetime.isdigit() or int(mtime) > int(savetime):
                # no xattr was there or we got our xattr but mtime is more recent: someone may have updated the file
                # from a different source (e.g. FUSE or SMB mount), therefore force conflict.
                # Note we can't get a time resolution better than one second!
                log.info('msg="Forcing conflict based on lastWopiSaveTime" user="%s" filename="%s" ' \
                         'savetime="%s" lastmtime="%s" token="%s"' %
                         (acctok['userid'][-20:], acctok['filename'], savetime, mtime, flask.request.args['access_token'][-20:]))
                raise IOError
            log.debug('msg="Got lastWopiSaveTime" user="%s" filename="%s" savetime="%s" lastmtime="%s" token="%s"' %
                      (acctok['userid'][-20:], acctok['filename'], savetime, mtime, flask.request.args['access_token'][-20:]))

        except IOError:
            # either the file was deleted or it was updated/overwritten by others: force conflict
            newname, ext = os.path.splitext(acctok['filename'])
            # !!! typical EFSS formats are like '<filename>_conflict-<date>-<time>', but they're not synchronized back !!!
            newname = '%s-webconflict-%s%s' % (newname, time.strftime('%Y%m%d-%H'), ext.strip())
            utils.storeWopiFile(flask.request, acctok, utils.LASTSAVETIMEKEY, newname)
            # keep track of this action in the original file's xattr, to avoid looping (see below)
            st.setxattr(acctok['endpoint'], acctok['filename'], acctok['userid'], utils.LASTSAVETIMEKEY, 0)
            log.info('msg="Conflicting copy created" user="%s" savetime="%s" lastmtime="%s" newfilename="%s" token="%s"' %
                     (acctok['userid'][-20:], savetime, mtime, newname, flask.request.args['access_token'][-20:]))
            # and report failure to the application: note we use a CONFLICT response as it is better handled by the app
            return utils.makeConflictResponse('PUTFILE', 'External', lock, '', acctok['filename'], \
                                              'The file being edited got moved or overwritten, conflict copy created')

        # Go for overwriting the file. Note that the entire check+write operation should be atomic,
        # but the previous check still gives the opportunity of a race condition. We just live with it.
        # Anyhow, the EFSS should support versioning for such cases.
        utils.storeWopiFile(flask.request, acctok, utils.LASTSAVETIMEKEY)
        log.info('msg="File stored successfully" action="edit" user="%s" filename="%s" token="%s"' %
                 (acctok['userid'][-20:], acctok['filename'], flask.request.args['access_token'][-20:]))
        return 'OK', http.client.OK

    except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError) as e:
        log.warning('msg="Signature verification failed" client="%s" requestedUrl="%s" token="%s"' %
                    (flask.request.remote_addr, flask.request.base_url, flask.request.args['access_token']))
        return 'Invalid access token', http.client.UNAUTHORIZED

    except IOError as e:
        log.error('msg="Error writing file" filename="%s" token="%s" error="%s"' %
                  (acctok['filename'], flask.request.args['access_token'], e))
        return 'I/O Error', http.client.INTERNAL_SERVER_ERROR
