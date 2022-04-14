#!/usr/bin/env python3
'''
srv.py

Implementation of the core WOPI API

Main author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

import time
import os
import configparser
import json
import http.client
from datetime import datetime
from more_itertools import peekable
import jwt
import flask
import core.wopiutils as utils
import core.commoniface as common

IO_ERROR = 'I/O Error, please contact support'

# convenience references to global entities
st = None
srv = None
log = None
enablerename = False


def checkFileInfo(fileid):
    '''Implements the CheckFileInfo WOPI call'''
    '''cf. http://wopi.readthedocs.io/projects/wopirest/en/latest/files/CheckFileInfo.html'''
    srv.refreshconfig()
    try:
        acctok = jwt.decode(flask.request.args['access_token'], srv.wopisecret, algorithms=['HS256'])
        if acctok['exp'] < time.time():
            raise jwt.exceptions.ExpiredSignatureError
        wopits = 'NA'
        if 'X-WOPI-TimeStamp' in flask.request.headers:
            # typically not present, but if it's there it must be checked for expiration (comes from WOPI validator tests)
            try:
                wopits = int(flask.request.headers['X-WOPI-Timestamp']) / 10000000   # convert .NET Ticks to seconds since AD 1
                if wopits < (datetime.utcnow() - datetime(1, 1, 1)).total_seconds() - 20 * 60:
                    # timestamps older than 20 minutes must be considered expired
                    raise ValueError
            except ValueError:
                raise KeyError('Invalid or expired X-WOPI-Timestamp header')
        log.info('msg="CheckFileInfo" user="%s" filename="%s" fileid="%s" token="%s" wopits="%s"' %
                 (acctok['userid'][-20:], acctok['filename'], fileid, flask.request.args['access_token'][-20:], wopits))
        acctok['viewmode'] = utils.ViewMode(acctok['viewmode'])
        statInfo = st.statx(acctok['endpoint'], acctok['filename'], acctok['userid'], versioninv=1)
        # compute some entities for the response
        wopiSrc = 'WOPISrc=%s&access_token=%s' % (utils.generateWopiSrc(fileid), flask.request.args['access_token'])
        # populate metadata for this file
        fmd = {}
        fmd['BaseFileName'] = fmd['BreadcrumbDocName'] = os.path.basename(acctok['filename'])
        furl = acctok['folderurl']
        fmd['BreadcrumbFolderUrl'] = furl if furl != '/' else ''
        if acctok['username'] == '':
            fmd['IsAnonymousUser'] = True
            fmd['UserFriendlyName'] = 'Guest ' + utils.randomString(3)
            if '?path' in furl and furl[-1] != '/' and furl[-1] != '=':
                # this is a subfolder of a public share, show it
                fmd['BreadcrumbFolderName'] = 'Back to ' + furl[furl.find('?path'):].split('/')[-1]
            else:
                # this is the top level public share, which is anonymous
                fmd['BreadcrumbFolderName'] = 'Back to the public share'
        else:
            fmd['UserFriendlyName'] = acctok['username']
            fmd['BreadcrumbFolderName'] = 'Back to ' + os.path.dirname(acctok['filename'])
        if furl == '/':    # if no target folder URL was given, override the above and completely hide it
            fmd['BreadcrumbFolderName'] = ''
        if acctok['viewmode'] in (utils.ViewMode.READ_ONLY, utils.ViewMode.READ_WRITE):
            fmd['DownloadUrl'] = '%s?access_token=%s' % \
                (srv.config.get('general', 'downloadurl'), flask.request.args['access_token'])
        fmd['OwnerId'] = statInfo['ownerid']
        fmd['UserId'] = acctok['wopiuser']     # typically same as OwnerId; different when accessing shared documents
        fmd['Size'] = statInfo['size']
        # TODO the version is generated like this in ownCloud: 'V' . $file->getEtag() . \md5($file->getChecksum());
        fmd['Version'] = 'v%d' % statInfo['mtime']   # mtime is used as version here
        fmd['SupportsExtendedLockLength'] = fmd['SupportsGetLock'] = True
        fmd['SupportsUpdate'] = fmd['UserCanWrite'] = fmd['SupportsLocks'] = \
            fmd['SupportsDeleteFile'] = acctok['viewmode'] == utils.ViewMode.READ_WRITE
        fmd['UserCanNotWriteRelative'] = acctok['viewmode'] != utils.ViewMode.READ_WRITE
        fmd['SupportsContainers'] = False    # TODO this is all to be implemented
        fmd['HostViewUrl'] = '%s%s%s' % (acctok['appviewurl'], '&' if '?' in acctok['appviewurl'] else '?', wopiSrc)
        fmd['HostEditUrl'] = '%s%s%s' % (acctok['appediturl'], '&' if '?' in acctok['appediturl'] else '?', wopiSrc)
        fmd['SupportsRename'] = fmd['UserCanRename'] = enablerename and (acctok['viewmode'] == utils.ViewMode.READ_WRITE)
        # populate app-specific metadata
        if acctok['appname'].find('Microsoft') > 0:
            # the following is to enable the 'Edit in Word/Excel/PowerPoint' (desktop) action (probably broken)
            try:
                fmd['ClientUrl'] = srv.config.get('general', 'webdavurl') + '/' + acctok['filename']
            except configparser.NoOptionError:
                # if no WebDAV URL is provided, ignore this setting
                pass
        # extensions for Collabora Online
        fmd['EnableOwnerTermination'] = True
        fmd['DisableExport'] = fmd['DisableCopy'] = fmd['DisablePrint'] = acctok['viewmode'] == utils.ViewMode.VIEW_ONLY
        # fmd['LastModifiedTime'] = datetime.fromtimestamp(int(statInfo['mtime'])).isoformat()   # this currently breaks

        res = flask.Response(json.dumps(fmd), mimetype='application/json')
        # amend sensitive metadata for the logs
        fmd['HostViewUrl'] = fmd['HostEditUrl'] = fmd['DownloadUrl'] = '_redacted_'
        log.info('msg="File metadata response" token="%s" session="%s" metadata="%s"' %
                 (flask.request.args['access_token'][-20:], flask.request.headers.get('X-WOPI-SessionId'), fmd))
        return res
    except IOError as e:
        log.info('msg="Requested file not found" filename="%s" token="%s" error="%s"' %
                 (acctok['filename'], flask.request.args['access_token'][-20:], e))
        return 'File not found', http.client.NOT_FOUND
    except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError):
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
        # TODO for the time being we do not look if the file is locked. Once exclusive locks are implemented in Reva,
        # the lock must be fetched prior to the following call in order to access the file.
        f = peekable(st.readfile(acctok['endpoint'], acctok['filename'], acctok['userid'], None))
        firstchunk = f.peek()
        if isinstance(firstchunk, IOError):
            return ('Failed to fetch file from storage: %s' % firstchunk), http.client.INTERNAL_SERVER_ERROR
        # stat the file to get the version, TODO this should be cached inside the access token
        statInfo = st.stat(acctok['endpoint'], acctok['filename'], acctok['userid'])
        # stream file from storage to client
        resp = flask.Response(f, mimetype='application/octet-stream')
        resp.status_code = http.client.OK
        resp.headers['X-WOPI-ItemVersion'] = 'v%d' % statInfo['mtime']
        return resp
    except StopIteration:
        # File is empty, still return OK (strictly speaking, we should return 204 NO_CONTENT)
        return '', http.client.OK
    except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError) as e:
        log.warning('msg="Signature verification failed" client="%s" requestedUrl="%s" error="%s" token="%s"' %
                    (flask.request.remote_addr, flask.request.base_url, e, flask.request.args['access_token']))
        return 'Invalid access token', http.client.UNAUTHORIZED


#
# The following operations are all called on POST /wopi/files/<fileid>
#
def setLock(fileid, reqheaders, acctok):
    '''Implements the Lock, RefreshLock, and UnlockAndRelock WOPI calls'''
    # cf. http://wopi.readthedocs.io/projects/wopirest/en/latest/files/Lock.html
    op = reqheaders['X-WOPI-Override']
    lock = reqheaders['X-WOPI-Lock']
    oldLock = reqheaders.get('X-WOPI-OldLock')
    validateTarget = reqheaders.get('X-WOPI-Validate-Target')
    retrievedLock, _ = utils.retrieveWopiLock(fileid, op, lock, acctok)

    # perform the required checks for the validity of the new lock
    if op == 'REFRESH_LOCK' and not retrievedLock:
        if validateTarget:
            # this is an extension of the API: a REFRESH_LOCK without previous lock but with a Validate-Target header
            # is allowed provided that the target file was last saved by WOPI and not overwritten by external actions,
            # that is it must have a valid LASTSAVETIMEKEY xattr
            savetime = st.getxattr(acctok['endpoint'], acctok['filename'], acctok['userid'], utils.LASTSAVETIMEKEY)
        else:
            savetime = None
        if not savetime or not savetime.isdigit():
            return utils.makeConflictResponse(op, None, lock, oldLock, acctok['filename'],
                                              'The file was not locked' + ' and got modified' if validateTarget else '')

    # LOCK or REFRESH_LOCK: atomically set the lock to the given one, including the expiration time,
    # and return conflict response if the file was already locked
    try:
        return utils.storeWopiLock(fileid, op, lock, oldLock, acctok)
    except IOError as e:
        # expected failures are handled in storeWopiLock
        log.error('msg="%s: unable to store WOPI lock" filename="%s" token="%s" lock="%s" reason="%s"' %
                  (op.title(), acctok['filename'], flask.request.args['access_token'][-20:], lock, e))
        return IO_ERROR, http.client.INTERNAL_SERVER_ERROR


def getLock(fileid, _reqheaders_unused, acctok):
    '''Implements the GetLock WOPI call'''
    resp = flask.Response()
    lock, _ = utils.retrieveWopiLock(fileid, 'GETLOCK', '', acctok)
    resp.status_code = http.client.OK if lock else http.client.NOT_FOUND
    resp.headers['X-WOPI-Lock'] = lock if lock else ''
    # for statistical purposes, check whether a lock exists and update internal bookkeeping
    if lock and lock != 'External':
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
    return resp


def unlock(fileid, reqheaders, acctok):
    '''Implements the Unlock WOPI call'''
    lock = reqheaders['X-WOPI-Lock']
    retrievedLock, _ = utils.retrieveWopiLock(fileid, 'UNLOCK', lock, acctok)
    if not utils.compareWopiLocks(retrievedLock, lock):
        return utils.makeConflictResponse('UNLOCK', retrievedLock, lock, 'NA', acctok['filename'], 'Lock mismatch')
    # OK, the lock matches. Remove the lock
    try:
        # validate that the underlying file is still there
        statInfo = st.stat(acctok['endpoint'], acctok['filename'], acctok['userid'])
        st.unlock(acctok['endpoint'], acctok['filename'], acctok['userid'], acctok['appname'], utils.encodeLock(lock))
    except IOError as e:
        if common.ENOENT_MSG in e:
            return 'File not found', http.client.NOT_FOUND
        return IO_ERROR, http.client.INTERNAL_SERVER_ERROR

    checkext = srv.config.get('general', 'detectexternallocks', fallback='True').upper() == 'TRUE'
    if checkext:
        try:
            # also remove the LibreOffice-compatible lock file when relevant
            if os.path.splitext(acctok['filename'])[1] not in srv.nonofficetypes:
                st.removefile(acctok['endpoint'], utils.getLibreOfficeLockName(acctok['filename']), acctok['userid'], True)
        except IOError:
            # ignore, it's not worth to report anything here
            pass

    # and update our internal list of opened files
    try:
        del srv.openfiles[acctok['filename']]
    except KeyError:
        # already removed?
        pass
    resp = flask.Response()
    resp.status_code = http.client.OK
    resp.headers['X-WOPI-ItemVersion'] = 'v%d' % statInfo['mtime']
    return resp


def putRelative(fileid, reqheaders, acctok):
    '''Implements the PutRelative WOPI call. Corresponds to the 'Save as...' menu entry.'''
    # cf. http://wopi.readthedocs.io/projects/wopirest/en/latest/files/PutRelativeFile.html
    suggTarget = reqheaders.get('X-WOPI-SuggestedTarget')
    relTarget = reqheaders.get('X-WOPI-RelativeTarget')
    overwriteTarget = bool(reqheaders.get('X-WOPI-OverwriteRelativeTarget'))
    log.info('msg="PutRelative" user="%s" filename="%s" fileid="%s" suggTarget="%s" relTarget="%s" '
             'overwrite="%r" token="%s"' %
             (acctok['userid'], acctok['filename'], fileid,
              suggTarget, relTarget, overwriteTarget, flask.request.args['access_token'][-20:]))
    # either one xor the other must be present; note we can't use `^` as we have a mix of str and NoneType
    if (suggTarget and relTarget) or (not suggTarget and not relTarget):
        return '', http.client.NOT_IMPLEMENTED
    if suggTarget:
        # the suggested target is a UTF7-encoded (!) filename that can be changed to avoid collisions
        suggTarget = suggTarget.encode().decode('utf-7')
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
                log.warning('msg="PutRelative" user="%s" filename="%s" token="%s" suggTarget="%s" error="%s"' %
                            (acctok['userid'][-20:], targetName, flask.request.args['access_token'][-20:],
                             suggTarget, str(e)))
                return '', http.client.BAD_REQUEST
    else:
        # the relative target is a UTF7-encoded filename to be respected, and that may overwrite an existing file
        relTarget = os.path.dirname(acctok['filename']) + os.path.sep + relTarget.encode().decode('utf-7')  # make full path
        try:
            # check for file existence + lock
            fileExists = st.stat(acctok['endpoint'], relTarget, acctok['userid'])
            retrievedTargetLock, _ = utils.retrieveWopiLock(fileid, 'PUT_RELATIVE', None, acctok, overridefilename=relTarget)
        except IOError:
            fileExists = False
        if fileExists and (not overwriteTarget or retrievedTargetLock):
            return utils.makeConflictResponse('PUT_RELATIVE', retrievedTargetLock, 'NA', 'NA', relTarget,
                                              {'message': 'Target file already exists',
                                               # specs (the WOPI validator) require these to be populated with valid values
                                               'Name': os.path.basename(relTarget),
                                               'Url': utils.generateWopiSrc('0'),
                                               })
        # else we can use the relative target
        targetName = relTarget
    # either way, we now have a targetName to save the file: attempt to do so
    try:
        utils.storeWopiFile(flask.request, None, acctok, utils.LASTSAVETIMEKEY, targetName)
    except IOError as e:
        utils.storeForRecovery(flask.request.get_data(), targetName, flask.request.args['access_token'][-20:], e)
        return '', http.client.INTERNAL_SERVER_ERROR
    # generate an access token for the new file
    log.info('msg="PutRelative: generating new access token" user="%s" filename="%s" '
             'mode="ViewMode.READ_WRITE" friendlyname="%s"' %
             (acctok['userid'][-20:], targetName, acctok['username']))
    inode, newacctok = utils.generateAccessToken(acctok['userid'], targetName, utils.ViewMode.READ_WRITE,
                                                 (acctok['username'], acctok['wopiuser']),
                                                 acctok['folderurl'], acctok['endpoint'],
                                                 (acctok['appname'], acctok['appediturl'], acctok['appviewurl']))
    # prepare and send the response as JSON
    putrelmd = {}
    putrelmd['Name'] = os.path.basename(targetName)
    putrelmd['Url'] = '%s?access_token=%s' % (utils.generateWopiSrc(inode), newacctok)
    putrelmd['HostEditUrl'] = '%s%sWOPISrc=%s&access_token=%s' % \
                              (acctok['appediturl'], '&' if '?' in acctok['appediturl'] else '?',
                               utils.generateWopiSrc(inode), newacctok)
    resp = flask.Response(json.dumps(putrelmd), mimetype='application/json')
    putrelmd['Url'] = putrelmd['HostEditUrl'] = '_redacted_'
    log.debug('msg="PutRelative response" token="%s" metadata="%s"' % (newacctok[-20:], putrelmd))
    return resp


def deleteFile(fileid, _reqheaders_unused, acctok):
    '''Implements the DeleteFile WOPI call'''
    retrievedLock, _ = utils.retrieveWopiLock(fileid, 'DELETE', '', acctok)
    if retrievedLock is not None:
        # file is locked and cannot be deleted
        return utils.makeConflictResponse('DELETE', retrievedLock, 'NA', 'NA', acctok['filename'],
                                          'Cannot delete a locked file')
    try:
        st.removefile(acctok['endpoint'], acctok['filename'], acctok['userid'])
        return 'OK', http.client.OK
    except IOError as e:
        log.info('msg="DeleteFile" token="%s" error="%s"' % (flask.request.args['access_token'][-20:], e))
        return IO_ERROR, http.client.INTERNAL_SERVER_ERROR


def renameFile(fileid, reqheaders, acctok):
    '''Implements the RenameFile WOPI call.'''
    targetName = reqheaders['X-WOPI-RequestedName']
    lock = reqheaders['X-WOPI-Lock'] if 'X-WOPI-Lock' in reqheaders else None
    retrievedLock, _ = utils.retrieveWopiLock(fileid, 'RENAMEFILE', lock, acctok)
    if retrievedLock is not None and not utils.compareWopiLocks(retrievedLock, lock):
        return utils.makeConflictResponse('RENAMEFILE', retrievedLock, lock, 'NA', acctok['filename'])
    try:
        # the destination name comes without base path and without extension
        targetName = os.path.dirname(acctok['filename']) + '/' + targetName + os.path.splitext(acctok['filename'])[1]
        log.info('msg="RenameFile" user="%s" filename="%s" token="%s" targetname="%s"' %
                 (acctok['userid'][-20:], acctok['filename'], flask.request.args['access_token'][-20:], targetName))
        st.renamefile(acctok['endpoint'], acctok['filename'], targetName, acctok['userid'], utils.encodeLock(retrievedLock))
        # also rename the locks
        if os.path.splitext(acctok['filename'])[1] not in srv.nonofficetypes:
            st.renamefile(acctok['endpoint'], utils.getLibreOfficeLockName(acctok['filename']),
                          utils.getLibreOfficeLockName(targetName), acctok['userid'], None)
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
        try:
            utils.storeWopiFile(flask.request, None, acctok, utils.LASTSAVETIMEKEY)
            log.info('msg="File stored successfully" action="editnew" user="%s" filename="%s" token="%s"' %
                     (acctok['userid'][-20:], acctok['filename'], flask.request.args['access_token'][-20:]))
            # and we keep track of it as an open file with timestamp = Epoch, despite not having any lock yet.
            # XXX this is to work around an issue with concurrent editing of newly created files (cf. iopOpen)
            srv.openfiles[acctok['filename']] = ('0', set([acctok['username']]))
            return 'OK', http.client.OK
        except IOError as e:
            utils.storeForRecovery(flask.request.get_data(), acctok['filename'],
                                   flask.request.args['access_token'][-20:], e)
            return IO_ERROR, http.client.INTERNAL_SERVER_ERROR


def putFile(fileid):
    '''Implements the PutFile WOPI call'''
    srv.refreshconfig()
    try:
        acctok = jwt.decode(flask.request.args['access_token'], srv.wopisecret, algorithms=['HS256'])
        if acctok['exp'] < time.time():
            raise jwt.exceptions.ExpiredSignatureError
    except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError):
        log.warning('msg="Signature verification failed" client="%s" requestedUrl="%s" token="%s"' %
                    (flask.request.remote_addr, flask.request.base_url, flask.request.args['access_token']))
        return 'Invalid access token', http.client.UNAUTHORIZED

    if 'X-WOPI-Lock' not in flask.request.headers:
        # no lock given: assume we are in creation mode (cf. editnew WOPI action)
        return _createNewFile(fileid, acctok)
    # otherwise, check that the caller holds the current lock on the file
    lock = flask.request.headers['X-WOPI-Lock']
    retrievedLock, lockHolder = utils.retrieveWopiLock(fileid, 'PUTFILE', lock, acctok)
    if retrievedLock is None:
        return utils.makeConflictResponse('PUTFILE', retrievedLock, lock, 'NA', acctok['filename'],
                                          'Cannot overwrite unlocked file')
    if not utils.compareWopiLocks(retrievedLock, lock):
        return utils.makeConflictResponse('PUTFILE', retrievedLock, lock, 'NA', acctok['filename'],
                                          'Cannot overwrite file locked by %s' %
                                          (lockHolder if lockHolder != 'wopi' else 'another application'))
    # OK, we can save the file now
    log.info('msg="PutFile" user="%s" filename="%s" fileid="%s" action="edit" token="%s"' %
             (acctok['userid'][-20:], acctok['filename'], fileid, flask.request.args['access_token'][-20:]))
    try:
        # check now the destination file against conflicts
        savetime = st.getxattr(acctok['endpoint'], acctok['filename'], acctok['userid'], utils.LASTSAVETIMEKEY)
        mtime = None
        mtime = st.stat(acctok['endpoint'], acctok['filename'], acctok['userid'])['mtime']
        if savetime and savetime.isdigit() and int(savetime) >= int(mtime):
            # Go for overwriting the file. Note that the entire check+write operation should be atomic,
            # but the previous checks still give the opportunity of a race condition. We just live with it.
            # Anyhow, the EFSS should support versioning for such cases.
            utils.storeWopiFile(flask.request, retrievedLock, acctok, utils.LASTSAVETIMEKEY)
            log.info('msg="File stored successfully" action="edit" user="%s" filename="%s" token="%s"' %
                     (acctok['userid'][-20:], acctok['filename'], flask.request.args['access_token'][-20:]))
            resp = flask.Response()
            resp.status_code = http.client.OK
            resp.headers['X-WOPI-ItemVersion'] = 'v%d' % mtime
            return resp

    except IOError as e:
        utils.storeForRecovery(flask.request.get_data(), acctok['filename'],
                               flask.request.args['access_token'][-20:], e)
        return IO_ERROR, http.client.INTERNAL_SERVER_ERROR

    # no xattr was there or we got our xattr but mtime is more recent: someone may have updated the file
    # from a different source (e.g. FUSE or SMB mount), therefore force conflict.
    # Note we can't get a time resolution better than one second!
    log.info('msg="Forcing conflict based on lastWopiSaveTime" user="%s" filename="%s" savetime="%s" lastmtime="%s" token="%s"' %
             (acctok['userid'][-20:], acctok['filename'], savetime, mtime, flask.request.args['access_token'][-20:]))
    newname, ext = os.path.splitext(acctok['filename'])
    # typical EFSS formats are like '<filename>_conflict-<date>-<time>', but they're not synchronized: use a similar format
    newname = '%s-webconflict-%s%s' % (newname, time.strftime('%Y%m%d-%H'), ext.strip())
    try:
        dorecovery = None
        utils.storeWopiFile(flask.request, retrievedLock, acctok, utils.LASTSAVETIMEKEY, newname)
    except IOError as e:
        if common.ACCESS_ERROR not in str(e):
            dorecovery = e
        else:
            # let's try the configured conflictpath instead of the current folder
            newname = utils.getConflictPath(acctok['username']) + os.path.sep + os.path.basename(newname)
            try:
                utils.storeWopiFile(flask.request, retrievedLock, acctok, utils.LASTSAVETIMEKEY, newname)
            except IOError as e:
                # even this path did not work
                dorecovery = e
    if dorecovery:
        log.error('msg="Failed to create conflicting copy" user="%s" savetime="%s" lastmtime="%s" newfilename="%s" token="%s"' %
                  (acctok['userid'][-20:], savetime, mtime, newname, flask.request.args['access_token'][-20:]))
        utils.storeForRecovery(flask.request.get_data(), newname, flask.request.args['access_token'][-20:], dorecovery)
        return utils.makeConflictResponse('PUTFILE', 'External', lock, 'NA', acctok['filename'],
                                          'The file being edited got moved or overwritten, please contact support to recover it')

    # keep track of this action in the original file's xattr
    st.setxattr(acctok['endpoint'], acctok['filename'], acctok['userid'], utils.LASTSAVETIMEKEY, 0, utils.encodeLock(retrievedLock))
    log.info('msg="Conflicting copy created" user="%s" savetime="%s" lastmtime="%s" newfilename="%s" token="%s"' %
             (acctok['userid'][-20:], savetime, mtime, newname, flask.request.args['access_token'][-20:]))
    # and report failure to the application: note we use a CONFLICT response as it is better handled by the app
    return utils.makeConflictResponse('PUTFILE', 'External', lock, 'NA', acctok['filename'],
                                      'The file being edited got moved or overwritten, conflict copy created')
