'''
wopiutils.py

General low-level functions to support the WOPI server.

Main author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

import sys
import os
import time
import traceback
import json
from enum import Enum
from random import choice
from string import ascii_lowercase
from datetime import datetime
from base64 import b64encode, b64decode
from binascii import Error as B64Error
from urllib.parse import quote_plus as url_quote_plus
import http.client
import flask
import jwt
from werkzeug.utils import secure_filename
import core.commoniface as common

# this is the xattr key used for conflicts resolution on the remote storage
LASTSAVETIMEKEY = 'iop.wopi.lastwritetime'

# this is the xattr key used to store user info data from WOPI apps
USERINFOKEY = 'iop.wopi.userinfo'

# header used by reverse proxies such as traefik to pass the real remote IP address
REALIPHEADER = 'X-Real-IP'

# conventional string representing an external, non-WOPI lock
EXTERNALLOCK = 'External'

# convenience references to global entities
st = None
srv = None
log = None
WOPIVER = None


class ViewMode(Enum):
    '''File view mode: reference is `ViewMode` at
    https://github.com/cs3org/cs3apis/blob/master/cs3/app/provider/v1beta1/provider_api.proto
    '''
    # The file can be opened but not downloaded
    VIEW_ONLY = "VIEW_MODE_VIEW_ONLY"
    # The file can be downloaded
    READ_ONLY = "VIEW_MODE_READ_ONLY"
    # The file can be downloaded and updated, and the app should be shown in edit mode
    READ_WRITE = "VIEW_MODE_READ_WRITE"
    # The file can be downloaded and updated, and the app should be shown in preview mode
    PREVIEW = "VIEW_MODE_PREVIEW"


class UserType(Enum):
    '''App user types as given by
    https://github.com/cs3org/reva/blob/master/pkg/app/provider/wopi/wopi.go
    '''
    INVALID = "invalid"
    # regular user, logged in the local ID provider
    REGULAR = "regular"
    # federated/external user, logged in the local ID provider but with no home space
    FEDERATED = "federated"
    # OCM user, logged in a remote ID provider
    OCM = "ocm"
    # anonymous user, accessing a public link
    ANONYMOUS = "anonymous"


class JsonLogger:
    '''A wrapper class in front of a logger, based on the facade pattern'''
    def __init__(self, logger):
        '''Initialization'''
        self.logger = logger

    def __getattr__(self, name):
        '''Facade method'''
        def facade(*args, **kwargs):
            '''internal method returned by __getattr__ and wrapping the original one'''
            if not hasattr(self.logger, name):
                raise NotImplementedError
            if name in ['debug', 'info', 'warning', 'error', 'fatal']:
                # resolve the current module
                f = traceback.extract_stack()[-2].filename
                m = f[f.rfind('/') + 1:f.rfind('.')]
                if m == '__init__':
                    # take 'module' out of '/path/to/module/__init__.py'
                    f = f[:f.rfind('/')]
                    m = f[f.rfind('/') + 1:]
                try:
                    # as we use a `key="value" ...` format in all logs, we only have args[0]
                    payload = f'module="{m}" {args[0]} '
                    # now convert the payload to a dictionary assuming no `="` nor `" ` is present inside any key or value!
                    # the added trailing space matches the `" ` split, so we remove the last element of that list
                    payload = dict([tuple(kv.split('="')) for kv in payload.split('" ')[:-1]])
                    # then convert dict -> json -> str + strip `{` and `}`
                    payload = str(json.dumps(payload))[1:-1]
                except Exception:    # pylint: disable=broad-except
                    # if the above assumptions do not hold, just json-escape the original log
                    payload = f'"module": "{m}", "payload": "{json.dumps(args[0])}"'
                args = (payload,)
            # pass-through facade
            return getattr(self.logger, name)(*args, **kwargs)
        return facade


def logGeneralExceptionAndReturn(ex, req):
    '''Convenience function to log a stack trace and return HTTP 500'''
    ex_type, ex_value, ex_traceback = sys.exc_info()
    log.critical('msg="Unexpected exception caught" exception="%s" type="%s" traceback="%s" client="%s" requestedUrl="%s"' %
                 (ex, ex_type, traceback.format_exception(ex_type, ex_value, ex_traceback),
                  flask.request.headers.get(REALIPHEADER, flask.request.remote_addr), req.url))
    return 'Internal error, please contact support', http.client.INTERNAL_SERVER_ERROR


def validateAndLogHeaders(op):
    '''Convenience function to validate the headers and the access_token, and log some additional header in the request'''
    srv.refreshconfig()
    # validate the access token
    try:
        acctok = jwt.decode(flask.request.args['access_token'], srv.wopisecret, algorithms=['HS256'])
        if acctok['exp'] < time.time() or 'cs3org:wopiserver' not in acctok['iss']:
            raise jwt.exceptions.ExpiredSignatureError
    except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError, KeyError) as e:
        log.info('msg="Expired or malformed token" client="%s" requestedUrl="%s" details="%s" token="%s"' %
                 (flask.request.headers.get(REALIPHEADER, flask.request.remote_addr), flask.request.base_url,
                  str(type(e)) + ': ' + str(e), flask.request.args.get('access_token')))
        return 'Invalid access token', http.client.UNAUTHORIZED

    # validate the WOPI timestamp: this is typically not present, but if it is we must check its expiration
    # (cf. the WOPI validator tests)
    wopits = 'None'
    if 'X-WOPI-TimeStamp' in flask.request.headers:
        try:
            wopits = int(flask.request.headers['X-WOPI-Timestamp']) / 10000000   # convert .NET Ticks to seconds since AD 1
            if wopits < (datetime.utcnow() - datetime(1, 1, 1)).total_seconds() - 20 * 60:
                # timestamps older than 20 minutes must be considered expired
                raise ValueError
        except ValueError:
            log.warning('msg="%s: invalid X-WOPI-Timestamp" user="%s" token="%s" client="%s"' %
                        (op, acctok['userid'][-20:], flask.request.args['access_token'][-20:],
                         flask.request.headers.get(REALIPHEADER, flask.request.remote_addr)))
            # UNAUTHORIZED would seem more appropriate here, but the ProofKeys part of the MS test suite explicitly requires this
            return 'Invalid or expired X-WOPI-Timestamp header', http.client.INTERNAL_SERVER_ERROR

    # log all relevant headers to help debugging
    session = flask.request.headers.get('X-WOPI-SessionId')
    log.debug('msg="%s: client context" user="%s" filename="%s" token="%s" client="%s" deviceId="%s" reqId="%s" sessionId="%s" '
              'app="%s" appEndpoint="%s" correlationId="%s" wopits="%s"' %
              (op.title(), acctok['userid'][-20:], acctok['filename'],
               flask.request.args['access_token'][-20:], flask.request.headers.get(REALIPHEADER, flask.request.remote_addr),
               flask.request.headers.get('X-WOPI-DeviceId'), flask.request.headers.get('X-Request-Id'),
               session, flask.request.headers.get('X-WOPI-RequestingApplication'),
               flask.request.headers.get('X-WOPI-AppEndpoint'), flask.request.headers.get('X-WOPI-CorrelationId'), wopits))

    # update bookkeeping of pending sessions
    if op.title() == 'Checkfileinfo' and session in srv.conflictsessions['pending'] and \
       int(srv.conflictsessions['pending'][session]['time']) < time.time() - 30:
        # a previously conflicted session is still around executing Checkfileinfo after some time, assume it got resolved
        _resolveSession(session, acctok['filename'])
    return acctok, None


def generateWopiSrc(fileid, proxy=False):
    '''Returns a URL-encoded WOPISrc for the given fileid, proxied if required.'''
    if not proxy or not srv.wopiproxy:
        return url_quote_plus(f'{srv.wopiurl}/wopi/files/{fileid}').replace('-', '%2D')
    # proxy the WOPI request through an external WOPI proxy service, but only if it was not already proxied
    if len(fileid) < 90:   # heuristically, proxied fileids are (much) longer than that
        log.debug(f'msg="Generating proxied fileid" fileid="{fileid}" proxy="{srv.wopiproxy}"')
        fileid = jwt.encode({'u': srv.wopiurl + '/wopi/files/', 'f': fileid}, srv.wopiproxykey, algorithm='HS256')
    else:
        log.debug(f'msg="Proxied fileid already created" fileid="{fileid}" proxy="{srv.wopiproxy}"')
    return url_quote_plus(f'{srv.wopiproxy}/wopi/files/{fileid}').replace('-', '%2D')


def generateUrlFromTemplate(url, acctok):
    '''One-liner to parse an URL template and return it with actualised placeholders'''
    return url.replace('<path>', acctok['filename']). \
               replace('<endpoint>', acctok['endpoint']). \
               replace('<fileid>', acctok['fileid']). \
               replace('<app>', acctok['appname'])


def getLibreOfficeLockName(filename):
    '''Returns the filename of a LibreOffice-compatible lock file.
    This enables interoperability between Online and Desktop applications'''
    return os.path.dirname(filename) + os.path.sep + '.~lock.' + os.path.basename(filename) + '#'


def getMicrosoftOfficeLockName(filename):
    '''Returns the filename of a lock file as created by Microsoft Office'''
    if os.path.splitext(filename)[1] != '.docx' or len(os.path.basename(filename)) <= 6 + 1 + 4:
        return os.path.dirname(filename) + os.path.sep + '~$' + os.path.basename(filename)
    # MS Word has a really weird algorithm for the lock file name...
    if len(os.path.basename(filename)) >= 8 + 1 + 4:
        return os.path.dirname(filename) + os.path.sep + '~$' + os.path.basename(filename)[2:]
    # elif len(os.path.basename(filename)) == 7+1+4:
    return os.path.dirname(filename) + os.path.sep + '~$' + os.path.basename(filename)[1:]


def randomString(size):
    '''One liner to get a random string of letters'''
    return ''.join([choice(ascii_lowercase) for _ in range(size)])


def generateAccessToken(userid, fileid, viewmode, user, folderurl, endpoint, app):
    '''Generates an access token for a given file and a given user, and returns a tuple with
    the file's inode and the URL-encoded access token.'''
    appname, appediturl, appviewurl = app
    friendlyname, wopiuser, usertype = user    # wopiuser has the form `username!userid_in_stat_format`
    log.debug('msg="Generating token" userid="%s" fileid="%s" endpoint="%s" app="%s"' %
              (userid[-20:], fileid, endpoint, appname))
    try:
        # stat the file to check for existence and get a version-invariant inode:
        # the inode serves as fileid (and must not change across save operations)
        statinfo = st.statx(endpoint, fileid, userid)
    except IOError as e:
        log.info(f'msg="Requested file not found or not a file" fileid="{fileid}" error="{e}"')
        raise
    exptime = int(time.time()) + srv.config.getint('general', 'tokenvalidity')
    fext = os.path.splitext(statinfo['filepath'])[1].lower()
    if srv.config.get('general', 'disablemswriteodf', fallback='False').upper() == 'TRUE' and \
       fext[1:3] in ('od', 'ot') and appname not in ('Collabora', '') and viewmode == ViewMode.READ_WRITE:
        # we're opening an ODF (`.o[d|t]?`) file and the app is not Collabora (the appname may be empty because the legacy
        # endpoint does not set appname when the app is not proxied, so we optimistically assume it's Collabora and let it go)
        log.info(f"msg=\"Forcing read-only access to ODF file\" filename=\"{statinfo['filepath']}\"")
        viewmode = ViewMode.READ_ONLY
    tokmd = {
        'userid': userid, 'wopiuser': wopiuser, 'usertype': usertype.value, 'filename': statinfo['filepath'], 'fileid': fileid,
        'username': friendlyname, 'viewmode': viewmode.value, 'folderurl': folderurl, 'endpoint': endpoint,
        'appname': appname, 'appediturl': appediturl, 'appviewurl': appviewurl,
        'exp': exptime, 'iss': f'cs3org:wopiserver:{WOPIVER}'    # standard claims
    }
    if viewmode == ViewMode.PREVIEW:
        # preview mode assumes read/write privileges for the acctok
        tokmd['viewmode'] = ViewMode.READ_WRITE.value
        if statinfo['size'] == 0:
            # override preview mode when a new file is being created
            viewmode = ViewMode.READ_WRITE
    acctok = jwt.encode(tokmd, srv.wopisecret, algorithm='HS256')
    if 'MS 365' in appname:
        srv.allusers.add(userid)
    log.info('msg="Access token generated" userid="%s" wopiuser="%s" friendlyname="%s" usertype="%s" mode="%s" '
             'endpoint="%s" filename="%s" inode="%s" mtime="%s" folderurl="%s" appname="%s" expiration="%d" token="%s"' %
             (userid[-20:], wopiuser, friendlyname, usertype, viewmode, endpoint, statinfo['filepath'], statinfo['inode'],
              statinfo['mtime'], folderurl, appname, exptime, acctok[-20:]))
    return statinfo['inode'], acctok, viewmode


def encodeLock(lock):
    '''Generates the lock payload for the storage given the raw metadata'''
    if lock:
        return common.WEBDAV_LOCK_PREFIX + ' ' + b64encode(lock.encode()).decode()
    return None


def _decodeLock(storedlock):
    '''Restores the lock payload reverting the `encodeLock` format. May raise IOError'''
    try:
        if storedlock and storedlock.find(common.WEBDAV_LOCK_PREFIX) == 0:
            return b64decode(storedlock[len(common.WEBDAV_LOCK_PREFIX) + 1:].encode()).decode()
        raise IOError('Non-WOPI lock found')     # it's not our lock, though it's likely valid
    except B64Error as e:
        raise IOError(e)


def retrieveWopiLock(fileid, operation, lockforlog, acctok, overridefn=None):
    '''Retrieves and logs a lock for a given file: returns the lock and its holder, or (None, None) if no lock found'''
    encacctok = flask.request.args['access_token'][-20:] if 'access_token' in flask.request.args else 'NA'

    # if required, check if a non-WOPI office lock exists for this file
    checkext = srv.config.get('general', 'detectexternallocks', fallback='True').upper() == 'TRUE'
    lolock = lolockstat = None
    if checkext and os.path.splitext(acctok['filename'])[1] not in srv.nonofficetypes:
        try:
            # first try to look for a MS Office lock
            mslockstat = st.stat(acctok['endpoint'], getMicrosoftOfficeLockName(acctok['filename']), acctok['userid'])
            log.info('msg="Found existing MS Office lock" lockop="%s" user="%s" filename="%s" token="%s" lockmtime="%ld"' %
                     (operation.title(), acctok['userid'][-20:], acctok['filename'], encacctok, mslockstat['mtime']))
            return EXTERNALLOCK, 'Microsoft Office for Desktop'
        except IOError:
            pass
        try:
            # then try to read a LibreOffice lock
            lolockstat = st.statx(acctok['endpoint'], getLibreOfficeLockName(acctok['filename']), acctok['userid'], versioninv=0)
            lolock = next(st.readfile(acctok['endpoint'], getLibreOfficeLockName(acctok['filename']), acctok['userid'], None))
            if isinstance(lolock, IOError):
                # this might be an access error, optimistically move on
                raise lolock
            lolock = lolock.decode()
            if 'WOPIServer' not in lolock:
                lolockholder = lolock.split(',')[1] if ',' in lolock else lolockstat['ownerid']
                log.info('msg="Found existing LibreOffice lock" lockop="%s" user="%s" filename="%s" token="%s" '
                         'lockmtime="%ld" holder="%s"' %
                         (operation.title(), acctok['userid'][-20:], acctok['filename'], encacctok,
                          lolockstat['mtime'], lolockholder))
                return EXTERNALLOCK, 'LibreOffice for Desktop'
        except (IOError, StopIteration):
            pass

    try:
        # fetch and decode the lock
        lockcontent = st.getlock(acctok['endpoint'], overridefn if overridefn else acctok['filename'], acctok['userid'])
        # here we used to check the last save time to "extend" the validity of an otherwise expired lock:
        # however, this goes against isolating the lock expiration logic in the storage interfaces and ultimately
        # violates the WOPI specifications, therefore it was dropped
        if not lockcontent:
            log.info('msg="No lock found" lockop="%s" user="%s" filename="%s" token="%s"' %
                     (operation.title(), acctok['userid'][-20:], acctok['filename'], encacctok))
            # lazily remove the LibreOffice-compatible lock file, if it was detected and has
            # the expected signature - cf. setLock()
            try:
                if lolock:
                    st.removefile(acctok['endpoint'], getLibreOfficeLockName(acctok['filename']), acctok['userid'], True)
            except IOError as e:
                log.warning('msg="Unable to delete stale LibreOffice-compatible lock file" lockop="%s" user="%s" filename="%s" '
                            'fileid="%s" error="%s"' %
                            (operation.title(), acctok['userid'][-20:], acctok['filename'], fileid, e))
            return None, None
        storedlock = lockcontent['lock_id']
        lockcontent['lock_id'] = _decodeLock(storedlock)
    except IOError as e:
        log.info('msg="Found non-compatible or unreadable lock" lockop="%s" user="%s" filename="%s" token="%s" error="%s"' %
                 (operation.title(), acctok['userid'][-20:], acctok['filename'], encacctok, e))
        return EXTERNALLOCK, 'Another app or user'

    log.info('msg="Retrieved lock" lockop="%s" user="%s" filename="%s" fileid="%s" lock="%s" '
             'retrievedlock="%s" expTime="%s" token="%s"' %
             (operation.title(), acctok['userid'][-20:], acctok['filename'], fileid, lockforlog, lockcontent['lock_id'],
              time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(lockcontent['expiration']['seconds'])), encacctok))
    return lockcontent['lock_id'], lockcontent['app_name']


def compareWopiLocks(lock1, lock2):
    '''Compares two locks and returns True if they represent the same WOPI lock.
    Officially, the comparison must be based on the locks' string representations. But because of
    a bug in early versions of Word Online, the internal format of the WOPI locks may be looked at,
    based on heuristics. Note that this format is subject to change and is not documented!'''
    if lock1 == lock2:
        log.debug(f'msg="compareLocks" lock1="{lock1}" lock2="{lock2}" result="True"')
        return True
    if srv.config.get('general', 'wopilockstrictcheck', fallback='True').upper() == 'TRUE':
        log.debug(f'msg="compareLocks" lock1="{lock1}" lock2="{lock2}" strict="True" result="False"')
        return False

    # before giving up, attempt to parse the lock as a JSON dictionary if allowed by the config
    try:
        l1 = json.loads(lock1)
        try:
            l2 = json.loads(lock2)
            if 'S' in l1 and 'S' in l2:
                log.debug('msg="compareLocks" lock1="%s" lock2="%s" strict="False" result="%r"' %
                          (lock1, lock2, l1['S'] == l2['S']))
                return l1['S'] == l2['S']         # used by Word
        except (TypeError, ValueError):
            # lock2 is not a JSON dictionary
            if 'S' in l1:
                log.debug('msg="compareLocks" lock1="%s" lock2="%s" strict="False" result="%r"' %
                          (lock1, lock2, l1['S'] == lock2))
                return l1['S'] == lock2                    # also used by Word
    except (TypeError, ValueError):
        # lock1 is not a JSON dictionary: log the lock values and fail the comparison
        pass
    log.debug(f'msg="compareLocks" lock1="{lock1}" lock2="{lock2}" strict="False" result="False"')
    return False


def makeConflictResponse(operation, user, retrievedlock, lock, oldlock, filename, reason, savetime=None):
    '''Generates and logs an HTTP 409 response in case of locks conflict'''
    resp = flask.Response(mimetype='application/json')
    resp.headers['X-WOPI-Lock'] = retrievedlock if retrievedlock else ''
    resp.status_code = http.client.CONFLICT
    if isinstance(reason, str):
        # transform the given message in a dict to be JSON-ified
        reason = {'message': reason}
    resp.headers['X-WOPI-LockFailureReason'] = reason['message']
    resp.data = json.dumps(reason)

    session = flask.request.headers.get('X-WOPI-SessionId')
    if session and retrievedlock != EXTERNALLOCK and \
       session not in srv.conflictsessions['pending'] and session not in srv.conflictsessions['resolved']:
        srv.conflictsessions['pending'][session] = {
            'user': user,
            'time': int(time.time()),
            'heldby': retrievedlock,
            'type': os.path.splitext(filename)[1],
        }
    if savetime:
        fileage = f'{time.time() - int(savetime):1.1f}'
    else:
        fileage = 'NA'
    log.warning('msg="Returning conflict" lockop="%s" user="%s" filename="%s" token="%s" sessionId="%s" lock="%s" '
                'oldlock="%s" retrievedlock="%s" fileage="%s" reason="%s"' %
                (('UnlockAndRelock' if oldlock and operation != 'PUTFILE' else operation.title()), user, filename,
                 flask.request.args['access_token'][-20:], session, lock, oldlock, retrievedlock, fileage,
                 (reason['message'] if reason else 'NA')))
    return resp


def _resolveSession(session, filename):
    '''Mark a session as resolved and account the given filename in the openfiles map.
    This is only used for bookkeeping, no functionality is associated to those maps'''
    if session in srv.conflictsessions['pending']:
        s = srv.conflictsessions['pending'].pop(session)
        srv.conflictsessions['resolved'][session] = {
            'user': s['user'],
            'restime': int(time.time() - int(s['time'])),
            'type': s['type'],
        }
    # keep some accounting of the open files
    if filename not in srv.openfiles:
        srv.openfiles[filename] = (time.asctime(), set())
    if session not in srv.openfiles[filename][1]:
        srv.openfiles[filename][1].add(session)


def makeLockSuccessResponse(operation, acctok, lock, oldlock, version):
    '''Generates and logs an HTTP 200 response with appropriate headers for Lock/RefreshLock operations'''
    session = flask.request.headers.get('X-WOPI-SessionId')
    if not session:
        session = acctok['wopiuser'].split('!')[0]
    _resolveSession(session, acctok['filename'])

    log.info('msg="Successfully locked" lockop="%s" filename="%s" token="%s" sessionId="%s" '
             'lock="%s" oldlock="%s" version="%s"' %
             (('UnlockAndRelock' if oldlock else operation.title()), acctok['filename'],
              flask.request.args['access_token'][-20:], session, lock, oldlock, version))
    resp = flask.Response()
    resp.status_code = http.client.OK
    resp.headers['X-WOPI-ItemVersion'] = version
    return resp


def storeWopiFile(acctok, retrievedlock, xakey, targetname=''):
    '''Saves a file from an HTTP request to the given target filename (defaulting to the access token's one),
    and stores the save time as an xattr. Throws IOError in case of any failure'''
    if not targetname:
        targetname = acctok['filename']
    session = flask.request.headers.get('X-WOPI-SessionId')
    if not session:
        session = acctok['wopiuser'].split('!')[0]
    _resolveSession(session, targetname)

    writeerror = None
    try:
        st.writefile(acctok['endpoint'], targetname, acctok['userid'], flask.request.get_data(),
                     (acctok['appname'], encodeLock(retrievedlock)))
    except IOError as e:
        if str(e) == common.ACCESS_ERROR:
            raise
        # something went wrong on write: we still want to setxattr but report this error to the caller
        writeerror = e
    # in all cases save the current time for later conflict checking: this is never older than the mtime of the file
    st.setxattr(acctok['endpoint'], targetname, acctok['userid'], xakey, int(time.time()),
                (acctok['appname'], encodeLock(retrievedlock)))
    if writeerror:
        raise writeerror


def storeAfterConflict(acctok, retrievedlock, lock, reason):
    '''Saves a conflict file in case the original file was externally locked or overwritten.
    The conflicted copy follows the format `<filename>-webconflict-<time>` and might be stored
    next to the original one, or to the user's home, or to the recovery path.'''
    newname, ext = os.path.splitext(acctok['filename'])
    # typical EFSS formats are like '<filename>_conflict-<date>-<time>', but they're not synchronized: use a similar format
    newname = f"{newname}-webconflict-{time.strftime('%Y%m%d-%H')}{ext.strip()}"
    try:
        dorecovery = None
        storeWopiFile(acctok, retrievedlock, LASTSAVETIMEKEY, newname)
    except IOError as e:
        if common.ACCESS_ERROR not in str(e):
            dorecovery = e
        else:
            # let's try the configured user's (or owner's) homepath instead of the current folder
            newname = srv.homepath.replace('user_initial', acctok['wopiuser'][0]). \
                                   replace('username', acctok['wopiuser'].split('!')[0]) \
                      + os.path.sep + os.path.basename(newname)     # noqa: E131
            try:
                storeWopiFile(acctok, retrievedlock, LASTSAVETIMEKEY, newname)
            except IOError as e:
                # even this path did not work
                dorecovery = e

    if dorecovery:
        storeForRecovery(acctok['wopiuser'], newname, flask.request.args['access_token'][-20:], dorecovery)
        # conflict file was stored on recovery space, tell user (but reason is advisory...)
        reason += ', please contact support to recover it'
    else:
        # otherwise, conflict file was saved to user space
        reason += ', conflict copy created'

    # use a CONFLICT response as it is better handled by the app to signal the issue to the user
    return makeConflictResponse('PUTFILE', acctok['userid'], retrievedlock, lock, 'NA',
                                acctok['filename'], reason)


def storeForRecovery(wopiuser, filename, acctokforlog, exception, content=None):
    if not content:
        content = flask.request.get_data()
    try:
        filepath = srv.recoverypath + os.sep + time.strftime('%Y%m%dT%H%M%S') + '_editedby_' \
                   + secure_filename(wopiuser.split('!')[0]) + '_origat_' + secure_filename(filename)
        with open(filepath, mode='wb') as f:
            written = f.write(content)
        if written != len(content):
            raise IOError('Size mismatch')
        log.error('msg="Error writing file, a copy was stored locally for later recovery" '
                  + 'filename="%s" recoveredpath="%s" token="%s" error="%s"' %
                  (filename, filepath, acctokforlog, exception))
    except (OSError, IOError) as e:
        log.critical('msg="Error writing file and failed to recover it to local storage, data is LOST" '
                     + 'filename="%s" token="%s" originalerror="%s" recoveryerror="%s"' %
                     (filename, acctokforlog, exception, e))


# Creates a Flask response object with a JSON-encoded body, the given status code,
# and the specified headers (or an empty dictionary if none are provided).
def createJsonResponse(response_body, status_code, headers=None):
    # Set default headers and include Content-Type: application/json
    headers = headers or {}
    headers['Content-Type'] = 'application/json'
    # Create the response object with the JSON-encoded body and the specified status code and headers
    return flask.Response(response=json.dumps(response_body), status=status_code, headers=headers)
