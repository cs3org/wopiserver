'''
wopi.py

Implementation of the core WOPI API

Main author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

import time
import os
import configparser
import json
import http.client
from datetime import datetime
from urllib.parse import unquote_plus as url_unquote
from more_itertools import peekable
import flask
import core.wopiutils as utils
import core.commoniface as common

IO_ERROR = 'I/O Error, please contact support'

# convenience references to global entities
st = None
srv = None
log = None
enablerename = False


def checkFileInfo(fileid, acctok):
    '''Implements the CheckFileInfo WOPI call'''
    try:
        acctok['viewmode'] = utils.ViewMode(acctok['viewmode'])
        statInfo = st.statx(acctok['endpoint'], acctok['filename'], acctok['userid'])
        # populate metadata for this file
        fmd = {}
        fmd['BaseFileName'] = fmd['BreadcrumbDocName'] = os.path.basename(acctok['filename'])
        wopiSrc = 'WOPISrc=%s&access_token=%s' % (utils.generateWopiSrc(fileid, acctok['appname'] == srv.proxiedappname),
                                                  flask.request.args['access_token'])
        hosteurl = srv.config.get('general', 'hostediturl', fallback=None)
        if hosteurl:
            fmd['HostEditUrl'] = utils.generateUrlFromTemplate(hosteurl, acctok)
        else:
            fmd['HostEditUrl'] = '%s%s%s' % (acctok['appediturl'], '&' if '?' in acctok['appediturl'] else '?', wopiSrc)
        hostvurl = srv.config.get('general', 'hostviewurl', fallback=None)
        if hostvurl:
            fmd['HostViewUrl'] = utils.generateUrlFromTemplate(hostvurl, acctok)
        else:
            fmd['HostViewUrl'] = '%s%s%s' % (acctok['appviewurl'], '&' if '?' in acctok['appviewurl'] else '?', wopiSrc)
        fsurl = srv.config.get('general', 'filesharingurl', fallback=None)
        if fsurl:
            fmd['FileSharingUrl'] = utils.generateUrlFromTemplate(fsurl, acctok)
        furl = acctok['folderurl']
        fmd['BreadcrumbFolderUrl'] = furl if furl != '/' else srv.wopiurl   # the WOPI URL is a placeholder
        if acctok['username'] == '':
            fmd['IsAnonymousUser'] = True
            fmd['UserFriendlyName'] = 'Guest ' + utils.randomString(3)
            if '?path' in furl and furl[-1] != '/' and furl[-1] != '=':
                # this is a subfolder of a public share, show it
                fmd['BreadcrumbFolderName'] = furl[furl.find('?path'):].split('/')[-1]
            else:
                # this is the top level public share, which is anonymous
                fmd['BreadcrumbFolderName'] = 'Public share'
        else:
            fmd['IsAnonymousUser'] = False
            fmd['UserFriendlyName'] = acctok['username']
            fmd['BreadcrumbFolderName'] = 'Back to ' + os.path.dirname(acctok['filename'])
        if furl == '/':    # if no target folder URL was given, override the above and completely hide it
            fmd['BreadcrumbFolderName'] = ''
        if acctok['viewmode'] in (utils.ViewMode.READ_ONLY, utils.ViewMode.READ_WRITE) \
           and srv.config.get('general', 'downloadurl', fallback=None):
            fmd['DownloadUrl'] = fmd['FileUrl'] = '%s?access_token=%s' % \
                (srv.config.get('general', 'downloadurl'), flask.request.args['access_token'])
        if srv.config.get('general', 'businessflow', fallback='False').upper() == 'TRUE':
            # enable the check for real users, not for public links
            fmd['LicenseCheckForEditIsEnabled'] = not fmd['IsAnonymousUser']
        fmd['BreadcrumbBrandName'] = srv.config.get('general', 'brandingname', fallback=None)
        fmd['BreadcrumbBrandUrl'] = srv.config.get('general', 'brandingurl', fallback=None)
        fmd['OwnerId'] = statInfo['ownerid']
        fmd['UserId'] = acctok['wopiuser']     # typically same as OwnerId; different when accessing shared documents
        fmd['Size'] = statInfo['size']
        # note that in ownCloud 10 the version is generated as: `'V' + etag + checksum`
        fmd['Version'] = 'v%s' % statInfo['etag']
        fmd['SupportsExtendedLockLength'] = fmd['SupportsGetLock'] = True
        fmd['SupportsUpdate'] = fmd['UserCanWrite'] = fmd['SupportsLocks'] = \
            fmd['SupportsDeleteFile'] = acctok['viewmode'] == utils.ViewMode.READ_WRITE
        # SaveAs functionality is enabled only for owners and in READ_WRITE mode. Anonymous and federated users
        # are never owners despite their wopiuser credentials may match the owner's. Federated/external accounts
        # are given by Reva with their network domain in parenthesis, that's why we match them.
        notOwner = fmd['OwnerId'] != fmd['UserId'] or fmd['IsAnonymousUser'] or \
            ('(' in acctok['username'] and acctok['username'][-1] == ')')
        fmd['UserCanNotWriteRelative'] = acctok['viewmode'] != utils.ViewMode.READ_WRITE or notOwner
        fmd['SupportsRename'] = fmd['UserCanRename'] = enablerename and (acctok['viewmode'] == utils.ViewMode.READ_WRITE)
        fmd['SupportsContainers'] = False    # TODO this is all to be implemented
        fmd['SupportsUserInfo'] = True
        uinfo = st.getxattr(acctok['endpoint'], acctok['filename'], statInfo['ownerid'], utils.USERINFOKEY)
        if uinfo:
            fmd['UserInfo'] = uinfo

        # populate app-specific metadata
        # the following is to enable the 'Edit in Word/Excel/PowerPoint' (desktop) action (probably broken)
        try:
            fmd['ClientUrl'] = srv.config.get('general', 'webdavurl') + '/' + acctok['filename']
        except configparser.NoOptionError:
            # if no WebDAV URL is provided, ignore this setting
            pass
        # extensions for Collabora Online
        if acctok['appname'].find('Collabora') >= 0 or acctok['appname'] == '':
            fmd['EnableOwnerTermination'] = True
            fmd['DisableExport'] = fmd['DisableCopy'] = fmd['DisablePrint'] = acctok['viewmode'] == utils.ViewMode.VIEW_ONLY
            # fmd['LastModifiedTime'] = datetime.fromtimestamp(int(statInfo['mtime'])).isoformat()   # this currently breaks

        res = flask.Response(json.dumps(fmd), mimetype='application/json')
        # amend sensitive metadata for the logs
        fmd['HostViewUrl'] = fmd['HostEditUrl'] = fmd['DownloadUrl'] = fmd['FileUrl'] = \
            fmd['BreadcrumbBrandUrl'] = fmd['FileSharingUrl'] = '_redacted_'
        log.info('msg="File metadata response" token="%s" metadata="%s"' %
                 (flask.request.args['access_token'][-20:], fmd))
        return res
    except IOError as e:
        log.info('msg="Requested file not found" filename="%s" token="%s" details="%s"' %
                 (acctok['filename'], flask.request.args['access_token'][-20:], e))
        return 'File not found', http.client.NOT_FOUND


def getFile(_fileid, acctok):
    '''Implements the GetFile WOPI call'''
    try:
        # TODO for the time being we do not look if the file is locked. Once exclusive locks are implemented in Reva,
        # the lock must be fetched prior to the following call in order to access the file.
        # get the file reader generator
        f = peekable(st.readfile(acctok['endpoint'], acctok['filename'], acctok['userid'], None))
        firstchunk = f.peek()
        if isinstance(firstchunk, IOError):
            log.error('msg="GetFile: download failed" filename="%s" token="%s" error="%s"' %
                      (acctok['filename'], flask.request.args['access_token'][-20:], firstchunk))
            return 'Failed to fetch file from storage', http.client.INTERNAL_SERVER_ERROR
        # stat the file to get the current version
        statInfo = st.statx(acctok['endpoint'], acctok['filename'], acctok['userid'])
        # stream file from storage to client
        resp = flask.Response(f, mimetype='application/octet-stream')
        resp.status_code = http.client.OK
        resp.headers['Content-Disposition'] = 'attachment; filename="%s"' % os.path.basename(acctok['filename'])
        resp.headers['X-Frame-Options'] = 'sameorigin'
        resp.headers['X-XSS-Protection'] = '1; mode=block'
        resp.headers['X-WOPI-ItemVersion'] = 'v%s' % statInfo['etag']
        return resp
    except StopIteration:
        # File is empty, still return OK (strictly speaking, we should return 204 NO_CONTENT)
        return '', http.client.OK
    except IOError as e:
        # File is readable but statx failed?
        log.error('msg="GetFile: failed to stat after read, possible race" filename="%s" token="%s" error="%s"' %
                  (acctok['filename'], flask.request.args['access_token'][-20:], e))
        return 'Failed to access file', http.client.INTERNAL_SERVER_ERROR


#
# The following operations are all called on POST /wopi/files/<fileid>
#
def setLock(fileid, reqheaders, acctok):
    '''Implements the Lock, RefreshLock, and UnlockAndRelock WOPI calls'''
    op = reqheaders['X-WOPI-Override']
    lock = reqheaders['X-WOPI-Lock']
    oldLock = reqheaders.get('X-WOPI-OldLock')
    validateTarget = reqheaders.get('X-WOPI-Validate-Target')
    retrievedLock, lockHolder = utils.retrieveWopiLock(fileid, op, lock, acctok)
    fn = acctok['filename']

    try:
        # validate that the underlying file is still there (it might have been moved/deleted)
        statInfo = st.statx(acctok['endpoint'], fn, acctok['userid'])
    except IOError as e:
        log.warning('msg="Error with target file" lockop="%s" filename="%s" token="%s" error="%s"' %
                    (op.title(), fn, flask.request.args['access_token'][-20:], e))
        if common.ENOENT_MSG in str(e):
            return 'File not found', http.client.NOT_FOUND
        return IO_ERROR, http.client.INTERNAL_SERVER_ERROR

    # perform the required checks for the validity of the new lock
    if op == 'REFRESH_LOCK' and not retrievedLock:
        if validateTarget:
            # this is an extension of the API: a REFRESH_LOCK without previous lock but with a Validate-Target header
            # is allowed provided that the target file was last saved by WOPI and not overwritten by external actions
            # (cf. PutFile logic)
            savetime = st.getxattr(acctok['endpoint'], fn, acctok['userid'], utils.LASTSAVETIMEKEY)
            if savetime and (not savetime.isdigit() or int(savetime) < int(statInfo['mtime'])):
                savetime = None
        else:
            savetime = None
        if not savetime:
            return utils.makeConflictResponse(op, acctok['userid'], None, lock, oldLock, acctok['endpoint'], fn,
                                              'The file was not locked' + ' and got modified' if validateTarget else '')

    # now check for and create an "external" lock if required
    if srv.config.get('general', 'detectexternallocks', fallback='True').upper() == 'TRUE' and \
       os.path.splitext(fn)[1] in srv.codetypes:
        try:
            if retrievedLock == 'External':
                return utils.makeConflictResponse(op, acctok['userid'], retrievedLock, lock, oldLock,
                                                  acctok['endpoint'], fn, 'The file is locked by ' + lockHolder)

            # create a LibreOffice-compatible lock file for interoperability purposes, making sure to
            # not overwrite any existing or being created lock
            lockcontent = ',Collaborative Online Editor,%s,%s,WOPIServer;' % \
                          (srv.wopiurl, time.strftime('%d.%m.%Y %H:%M', time.localtime(time.time())))
            st.writefile(acctok['endpoint'], utils.getLibreOfficeLockName(fn), acctok['userid'],
                         lockcontent, None, islock=True)
        except IOError as e:
            if common.EXCL_ERROR in str(e):
                # retrieve the LibreOffice-compatible lock just found
                try:
                    retrievedlolock = next(st.readfile(acctok['endpoint'], utils.getLibreOfficeLockName(fn),
                                                       acctok['userid'], None))
                    if isinstance(retrievedlolock, IOError):
                        raise retrievedlolock
                    retrievedlolock = retrievedlolock.decode()
                    # check that the lock is not stale
                    if datetime.strptime(retrievedlolock.split(',')[3], '%d.%m.%Y %H:%M').timestamp() + \
                       srv.config.getint('general', 'wopilockexpiration') < time.time():
                        retrievedlolock = 'WOPIServer'
                except (IOError, StopIteration, IndexError, ValueError):
                    retrievedlolock = 'WOPIServer'     # could not read the lock, assume it expired and take ownership
                if 'WOPIServer' not in retrievedlolock:
                    # the file was externally locked, make this call fail
                    lockholder = retrievedlolock.split(',')[1] if ',' in retrievedlolock else ''
                    log.warning('msg="Valid LibreOffice lock found, denying WOPI lock" lockop="%s" filename="%s" holder="%s"' %
                                (op.title(), fn, lockholder if lockholder else retrievedlolock))
                    reason = 'File locked by ' + ((lockholder + ' via LibreOffice') if lockholder else 'a LibreOffice user')
                    return utils.makeConflictResponse(op, acctok['userid'], 'External App', lock, oldLock,
                                                      acctok['endpoint'], fn, reason)
                # else it's our previous lock or it had expired: all right, move on
            else:
                # any other error is logged but not raised as this is optimistically not blocking WOPI operations
                # this includes the case of access denied (over)writing the LibreOffice lock because of accessing
                # a single-file share
                log.warning('msg="Failed to store LibreOffice-compatible lock" lockop="%s" filename="%s" token="%s" error="%s"' %
                            (op.title(), fn, flask.request.args['access_token'][-20:], e))

    try:
        # LOCK or REFRESH_LOCK: atomically set the lock to the given one, including the expiration time,
        # and return conflict response if the file was already locked
        st.setlock(acctok['endpoint'], fn, acctok['userid'], acctok['appname'], utils.encodeLock(lock))

        # on first lock, set an xattr with the current time for later conflicts checking
        try:
            st.setxattr(acctok['endpoint'], fn, acctok['userid'], utils.LASTSAVETIMEKEY,
                        int(time.time()), utils.encodeLock(lock))
        except IOError as e:
            # not fatal, but will generate a conflict file later on, so log a warning
            log.warning('msg="Unable to set lastwritetime xattr" lockop="%s" user="%s" filename="%s" token="%s" reason="%s"' %
                        (op.title(), acctok['userid'][-20:], fn, flask.request.args['access_token'][-20:], e))

        return utils.makeLockSuccessResponse(op, acctok, lock, 'v%s' % statInfo['etag'])

    except IOError as e:
        if common.EXCL_ERROR in str(e):
            # another session was faster than us, or the file was already WOPI-locked:
            # get the lock that was set
            if not retrievedLock:
                retrievedLock, lockHolder = utils.retrieveWopiLock(fileid, op, lock, acctok)
            # validate against either the given lock (RefreshLock case) or the given old lock (UnlockAndRelock case)
            if retrievedLock and not utils.compareWopiLocks(retrievedLock, (oldLock if oldLock else lock)):
                # lock mismatch, the WOPI client is supposed to acknowledge the existing lock
                # or deny write access to the file
                return utils.makeConflictResponse(op, acctok['userid'], retrievedLock, lock, oldLock, acctok['endpoint'], fn,
                                                  'The file is locked by %s' %
                                                  (lockHolder if lockHolder != 'wopi' else 'another online editor'))

            # else it's our own lock, refresh it (rechecking the oldLock if necessary, for atomicity) and return
            try:
                st.refreshlock(acctok['endpoint'], fn, acctok['userid'], acctok['appname'],
                               utils.encodeLock(lock), utils.encodeLock(oldLock) if oldLock else None)
                return utils.makeLockSuccessResponse(op, acctok, lock, 'v%s' % statInfo['etag'])
            except IOError as rle:
                # this is unexpected now
                log.error('msg="Failed to refresh lock" lockop="%s" filename="%s" token="%s" lock="%s" error="%s"' %
                          (op.title(), fn, flask.request.args['access_token'][-20:], lock, rle))

        # any other error is raised
        log.error('msg="Unable to store WOPI lock" lockop="%s" filename="%s" token="%s" lock="%s" error="%s"' %
                  (op.title(), fn, flask.request.args['access_token'][-20:], lock, e))
        return IO_ERROR, http.client.INTERNAL_SERVER_ERROR


def getLock(fileid, _reqheaders_unused, acctok):
    '''Implements the GetLock WOPI call'''
    resp = flask.Response()
    lock, _ = utils.retrieveWopiLock(fileid, 'GETLOCK', '', acctok)
    resp.status_code = http.client.OK if lock else http.client.NOT_FOUND
    resp.headers['X-WOPI-Lock'] = lock if lock else ''
    return resp


def unlock(fileid, reqheaders, acctok):
    '''Implements the Unlock WOPI call'''
    lock = reqheaders['X-WOPI-Lock']
    retrievedLock, _ = utils.retrieveWopiLock(fileid, 'UNLOCK', lock, acctok)
    if not utils.compareWopiLocks(retrievedLock, lock):
        return utils.makeConflictResponse('UNLOCK', acctok['userid'], retrievedLock, lock, 'NA',
                                          acctok['endpoint'], acctok['filename'], 'Lock mismatch')
    # OK, the lock matches, remove it
    try:
        # validate that the underlying file is still there
        statInfo = st.statx(acctok['endpoint'], acctok['filename'], acctok['userid'])
        st.unlock(acctok['endpoint'], acctok['filename'], acctok['userid'], acctok['appname'], utils.encodeLock(lock))
    except IOError as e:
        if common.ENOENT_MSG in str(e):
            return 'File not found', http.client.NOT_FOUND
        return IO_ERROR, http.client.INTERNAL_SERVER_ERROR

    if srv.config.get('general', 'detectexternallocks', fallback='True').upper() == 'TRUE':
        # and os.path.splitext(acctok['filename'])[1] in srv.codetypes:
        try:
            # also remove the LibreOffice-compatible lock file when relevant
            if os.path.splitext(acctok['filename'])[1] not in srv.nonofficetypes:
                st.removefile(acctok['endpoint'], utils.getLibreOfficeLockName(acctok['filename']), acctok['userid'], True)
        except IOError:
            # ignore, it's not worth to report anything here
            pass

    # and update our internal lists of opened files and conflicted sessions
    try:
        del srv.openfiles[acctok['filename']]
        session = flask.request.headers.get('X-WOPI-SessionId')
        if session in srv.conflictsessions['pending']:
            srv.conflictsessions['pending'].pop(session)
            srv.conflictsessions['resolved'][session] = time.asctime()
    except KeyError:
        # already removed?
        pass
    resp = flask.Response()
    resp.status_code = http.client.OK
    resp.headers['X-WOPI-ItemVersion'] = 'v%s' % statInfo['etag']
    return resp


def putRelative(fileid, reqheaders, acctok):
    '''Implements the PutRelative WOPI call. Corresponds to the 'Save as...' menu entry.'''
    suggTarget = reqheaders.get('X-WOPI-SuggestedTarget')
    relTarget = reqheaders.get('X-WOPI-RelativeTarget')
    overwriteTarget = str(reqheaders.get('X-WOPI-OverwriteRelativeTarget')).upper() == 'TRUE'
    log.info('msg="PutRelative" user="%s" filename="%s" fileid="%s" suggTarget="%s" relTarget="%s" '
             'overwrite="%r" wopitimestamp="%s" token="%s"' %
             (acctok['userid'], acctok['filename'], fileid, suggTarget, relTarget,
              overwriteTarget, reqheaders.get('X-WOPI-TimeStamp'), flask.request.args['access_token'][-20:]))
    # either one xor the other MUST be present; note we can't use `^` as we have a mix of str and NoneType
    if (suggTarget and relTarget) or (not suggTarget and not relTarget):
        return 'Conflicting headers given', http.client.BAD_REQUEST
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
                if common.ENOENT_MSG in str(e):
                    # OK, the targetName is good to go
                    break
                # we got another error with this file, fail
                log.error('msg="PutRelative" user="%s" filename="%s" token="%s" suggTarget="%s" error="%s"' %
                          (acctok['userid'][-20:], targetName, flask.request.args['access_token'][-20:],
                           suggTarget, str(e)))
                return 'Error with the given target', http.client.INTERNAL_SERVER_ERROR
    else:
        # the relative target is a UTF7-encoded filename to be respected, and that may overwrite an existing file
        relTarget = os.path.dirname(acctok['filename']) + os.path.sep + relTarget.encode().decode('utf-7')  # make full path
        try:
            # check for file existence
            statInfo = st.statx(acctok['endpoint'], relTarget, acctok['userid'])
            # the file exists, check lock
            retrievedTargetLock, _ = utils.retrieveWopiLock(fileid, 'PUT_RELATIVE', None, acctok, overridefn=relTarget)
            # deny if lock is valid or if overwriteTarget is False
            if not overwriteTarget or retrievedTargetLock:
                respmd = {
                    'message': 'Target file already exists',
                    # specs (the WOPI validator) require these to be populated with valid values
                    'Name': os.path.basename(relTarget),
                    'Url': utils.generateWopiSrc(statInfo['inode'], acctok['appname'] == srv.proxiedappname),
                }
                return utils.makeConflictResponse('PUT_RELATIVE', acctok['userid'], retrievedTargetLock, 'NA', 'NA',
                                                  acctok['endpoint'], relTarget, respmd)
        except IOError:
            # optimistically assume we're clear
            pass
        targetName = relTarget
    # either way, we now have a targetName to save the file: attempt to do so
    try:
        utils.storeWopiFile(acctok, None, utils.LASTSAVETIMEKEY, targetName)
        newstat = st.statx(acctok['endpoint'], targetName, acctok['userid'])
        _, newfileid = common.decodeinode(newstat['inode'])
    except IOError as e:
        if str(e) == common.ACCESS_ERROR:
            # BAD_REQUEST may seem better but the WOPI validator tests explicitly expect NOT_IMPLEMENTED
            return 'Unauthorized to perform PutRelative', http.client.NOT_IMPLEMENTED
        utils.storeForRecovery(flask.request.get_data(), acctok['username'], targetName,
                               flask.request.args['access_token'][-20:], e)
        return IO_ERROR, http.client.INTERNAL_SERVER_ERROR
    # generate an access token for the new file
    log.info('msg="PutRelative: generating new access token" user="%s" filename="%s" '
             'mode="ViewMode.READ_WRITE" friendlyname="%s"' %
             (acctok['userid'][-20:], targetName, acctok['username']))
    inode, newacctok, _ = utils.generateAccessToken(acctok['userid'], targetName, utils.ViewMode.READ_WRITE,
                                                    (acctok['username'], acctok['wopiuser']),
                                                    acctok['folderurl'], acctok['endpoint'],
                                                    (acctok['appname'], acctok['appediturl'], acctok['appviewurl']))
    # prepare and send the response as JSON
    mdforhosturls = {
        'appname': acctok['appname'],
        'filename': targetName,
        'endpoint': acctok['endpoint'],
        'fileid': newfileid,
    }
    newwopisrc = '%s&access_token=%s' % (utils.generateWopiSrc(inode, acctok['appname'] == srv.proxiedappname), newacctok)
    putrelmd = {
        'Name': os.path.basename(targetName),
        'Url': url_unquote(newwopisrc).replace('&access_token', '?access_token'),
    }
    hosteurl = srv.config.get('general', 'hostediturl', fallback=None)
    if hosteurl:
        putrelmd['HostEditUrl'] = utils.generateUrlFromTemplate(hosteurl, mdforhosturls)
    else:
        putrelmd['HostEditUrl'] = '%s%s%s' % (acctok['appediturl'], '&' if '?' in acctok['appediturl'] else '?', newwopisrc)
    hostvurl = srv.config.get('general', 'hostviewurl', fallback=None)
    if hostvurl:
        putrelmd['HostViewUrl'] = utils.generateUrlFromTemplate(hostvurl, mdforhosturls)
    else:
        putrelmd['HostViewUrl'] = '%s%s%s' % (acctok['appviewurl'], '&' if '?' in acctok['appviewurl'] else '?', newwopisrc)
    resp = flask.Response(json.dumps(putrelmd), mimetype='application/json')
    putrelmd['Url'] = putrelmd['HostEditUrl'] = putrelmd['HostViewUrl'] = '_redacted_'
    log.info('msg="PutRelative response" token="%s" metadata="%s"' % (newacctok[-20:], putrelmd))
    return resp


def deleteFile(fileid, _reqheaders_unused, acctok):
    '''Implements the DeleteFile WOPI call'''
    retrievedLock, _ = utils.retrieveWopiLock(fileid, 'DELETE', '', acctok)
    if retrievedLock is not None:
        # file is locked and cannot be deleted
        return utils.makeConflictResponse('DELETE', acctok['userid'], retrievedLock, 'NA', 'NA',
                                          acctok['endpoint'], acctok['filename'], 'Cannot delete a locked file')
    try:
        st.removefile(acctok['endpoint'], acctok['filename'], acctok['userid'])
        return 'OK', http.client.OK
    except IOError as e:
        if common.ENOENT_MSG in str(e):
            return 'File not found', http.client.NOT_FOUND
        log.error('msg="DeleteFile" token="%s" error="%s"' % (flask.request.args['access_token'][-20:], e))
        return IO_ERROR, http.client.INTERNAL_SERVER_ERROR


def renameFile(fileid, reqheaders, acctok):
    '''Implements the RenameFile WOPI call.'''
    try:
        renamemd = {}
        targetName = reqheaders['X-WOPI-RequestedName'].encode().decode('utf-7')
        renamemd['Name'] = os.path.splitext(targetName)[0]
    except KeyError as e:
        log.warning('msg="Missing argument" client="%s" requestedUrl="%s" error="%s" token="%s"' %
                    (flask.request.remote_addr, flask.request.base_url, e, flask.request.args.get('access_token')[-20:]))
        return 'Missing argument', http.client.BAD_REQUEST
    lock = reqheaders.get('X-WOPI-Lock')    # may not be specified
    retrievedLock, _ = utils.retrieveWopiLock(fileid, 'RENAMEFILE', lock, acctok)
    if retrievedLock is not None and not utils.compareWopiLocks(retrievedLock, lock):
        return utils.makeConflictResponse('RENAMEFILE', acctok['userid'], retrievedLock, lock, 'NA',
                                          acctok['endpoint'], acctok['filename'])
    try:
        # the destination name comes without base path and typically without extension
        targetName = os.path.dirname(acctok['filename']) + os.path.sep + targetName \
            + os.path.splitext(acctok['filename'])[1] if targetName.find('.') < 0 else ''
        log.info('msg="RenameFile" user="%s" filename="%s" token="%s" targetname="%s"' %
                 (acctok['userid'][-20:], acctok['filename'], flask.request.args['access_token'][-20:], targetName))

        # try to rename and pass the lock if present. Note that WOPI specs do not require files to be locked
        # on rename operations, but the backend may still fail as renames may be implemented as copy + delete,
        # which may require to pass a lock.
        st.renamefile(acctok['endpoint'], acctok['filename'], targetName, acctok['userid'],
                      utils.encodeLock(retrievedLock) if retrievedLock else None)
        # also rename the lock if applicable
        if os.path.splitext(acctok['filename'])[1] in srv.codetypes:
            st.renamefile(acctok['endpoint'], utils.getLibreOfficeLockName(acctok['filename']),
                          utils.getLibreOfficeLockName(targetName), acctok['userid'], None)
        # send the response as JSON
        return flask.Response(json.dumps(renamemd), mimetype='application/json')
    except IOError as e:
        log.warn('msg="RenameFile" token="%s" error="%s"' % (flask.request.args['access_token'][-20:], e))
        resp = flask.Response()
        if common.ENOENT_MSG in str(e):
            resp.headers['X-WOPI-InvalidFileNameError'] = 'File not found'
            resp.status_code = http.client.NOT_FOUND
        elif common.EXCL_ERROR in str(e):
            resp.headers['X-WOPI-InvalidFileNameError'] = 'Cannot rename/move unlocked file'
            resp.status_code = http.client.NOT_IMPLEMENTED
        else:
            resp.headers['X-WOPI-InvalidFileNameError'] = 'Failed to rename: %s' % e
            resp.status_code = http.client.INTERNAL_SERVER_ERROR
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
                    (acctok['filename'], flask.request.args['access_token'][-20:]))
        return 'File exists', http.client.CONFLICT
    except IOError:
        # indeed the file did not exist, so we write it for the first time
        try:
            utils.storeWopiFile(acctok, None, utils.LASTSAVETIMEKEY)
            log.info('msg="File stored successfully" action="editnew" user="%s" filename="%s" token="%s"' %
                     (acctok['userid'][-20:], acctok['filename'], flask.request.args['access_token'][-20:]))
            return 'OK', http.client.OK
        except IOError as e:
            utils.storeForRecovery(flask.request.get_data(), acctok['username'], acctok['filename'],
                                   flask.request.args['access_token'][-20:], e)
            return IO_ERROR, http.client.INTERNAL_SERVER_ERROR


def putFile(fileid, acctok):
    '''Implements the PutFile WOPI call'''
    if 'X-WOPI-Lock' not in flask.request.headers:
        # no lock given: assume we are in creation mode (cf. editnew WOPI action)
        return _createNewFile(fileid, acctok)
    # otherwise, check that the caller holds the current lock on the file
    lock = flask.request.headers['X-WOPI-Lock']
    retrievedLock, lockHolder = utils.retrieveWopiLock(fileid, 'PUTFILE', lock, acctok)
    if retrievedLock is None:
        return utils.makeConflictResponse('PUTFILE', acctok['userid'], retrievedLock, lock, 'NA',
                                          acctok['endpoint'], acctok['filename'], 'Cannot overwrite unlocked file')
    if not utils.compareWopiLocks(retrievedLock, lock):
        log.warning('msg="Forcing conflict based on external lock" user="%s" filename="%s" token="%s"' %
                    (acctok['userid'][-20:], acctok['filename'], flask.request.args['access_token'][-20:]))
        return utils.storeAfterConflict(acctok, retrievedLock, lock, 'Cannot overwrite file locked by %s' %
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
            # Also, note we can't get a time resolution better than one second!
            # Anyhow, the EFSS should support versioning for such cases.
            utils.storeWopiFile(acctok, retrievedLock, utils.LASTSAVETIMEKEY)
            statInfo = st.statx(acctok['endpoint'], acctok['filename'], acctok['userid'], versioninv=1)
            log.info('msg="File stored successfully" action="edit" user="%s" filename="%s" version="%s" token="%s"' %
                     (acctok['userid'][-20:], acctok['filename'], statInfo['etag'], flask.request.args['access_token'][-20:]))
            resp = flask.Response()
            resp.status_code = http.client.OK
            resp.headers['X-WOPI-ItemVersion'] = 'v%s' % statInfo['etag']
            return resp

    except IOError as e:
        utils.storeForRecovery(flask.request.get_data(), acctok['username'], acctok['filename'],
                               flask.request.args['access_token'][-20:], e)
        return IO_ERROR, http.client.INTERNAL_SERVER_ERROR

    # no xattr was there or we got our xattr but mtime is more recent: someone may have updated the file
    # from a different source (e.g. FUSE or SMB mount), therefore force conflict and return failure to the application
    log.warning('msg="Forcing conflict based on save time" user="%s" filename="%s" savetime="%s" lastmtime="%s" token="%s"' %
                (acctok['userid'][-20:], acctok['filename'], savetime, mtime, flask.request.args['access_token'][-20:]))
    return utils.storeAfterConflict(acctok, 'External', lock, 'The file being edited got moved or overwritten')


def putUserInfo(_fileid, reqbody, acctok):
    '''Implements the PutUserInfo WOPI call'''
    try:
        statInfo = st.statx(acctok['endpoint'], acctok['filename'], acctok['userid'])
        lock = st.getlock(acctok['endpoint'], acctok['filename'], acctok['userid'])
        st.setxattr(acctok['endpoint'], acctok['filename'], statInfo['ownerid'], utils.USERINFOKEY, reqbody.decode(),
                    utils.encodeLock(lock) if lock else None)
        return 'OK', http.client.OK
    except IOError as e:
        log.error('msg="PutUserInfo" token="%s" error="%s"' % (flask.request.args['access_token'][-20:], e))
        return IO_ERROR, http.client.INTERNAL_SERVER_ERROR
