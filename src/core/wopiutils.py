'''
wopiutils.py

General Low-level functions to support the WOPI server
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
import http.client
import flask
import jwt

# this is the xattr key used for conflicts resolution on the remote storage
LASTSAVETIMEKEY = 'iop.wopi.lastwritetime'

# standard error thrown when attempting to overwrite a file in O_EXCL mode
EXCL_ERROR = 'File exists and islock flag requested'

# standard error thrown when attempting an operation without the required access rights
ACCESS_ERROR = 'Operation not permitted'

# convenience references to global entities
st = None
srv = None
log = None
endpoints = {}

class ViewMode(Enum):
    '''File view mode: reference is `ViewMode` at
    https://github.com/cs3org/cs3apis/blob/master/cs3/app/provider/v1beta1/provider_api.proto
    '''
    # The file can be opened but not downloaded
    VIEW_ONLY = "VIEW_MODE_VIEW_ONLY"
    # The file can be downloaded
    READ_ONLY = "VIEW_MODE_READ_ONLY"
    # The file can be downloaded and updated
    READ_WRITE = "VIEW_MODE_READ_WRITE"


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
                m = f[f.rfind('/')+1:f.rfind('.')]
                if m == '__init__':
                    # take 'module' out of '/path/to/module/__init__.py'
                    f = f[:f.rfind('/')]
                    m = f[f.rfind('/')+1:]
                try:
                    # as we use a `key="value" ...` format in all logs, we only have args[0]
                    payload = 'module="%s" %s ' % (m, args[0])
                    # now convert the payload to a dictionary assuming no `="` nor `" ` is present inside any key or value!
                    # the added trailing space matches the `" ` split, so we remove the last element of that list
                    payload = dict([tuple(kv.split('="')) for kv in payload.split('" ')[:-1]])
                    # then convert dict -> json -> str + strip `{` and `}`
                    payload = str(json.dumps(payload))[1:-1]
                except Exception:    # pylint: disable=broad-except
                    # if the above assumptions do not hold, just json-escape the original log
                    payload = '"module": "%s", "payload": "%s"' % (m, json.dumps(args[0]))
                args = (payload,)
            # pass-through facade
            return getattr(self.logger, name)(*args, **kwargs)
        return facade


def logGeneralExceptionAndReturn(ex, req):
    '''Convenience function to log a stack trace and return HTTP 500'''
    ex_type, ex_value, ex_traceback = sys.exc_info()
    log.critical('msg="Unexpected exception caught" exception="%s" type="%s" traceback="%s" client="%s" requestedUrl="%s"' %
                 (ex, ex_type, traceback.format_exception(ex_type, ex_value, ex_traceback), req.remote_addr, req.url))
    return 'Internal error, please contact support', http.client.INTERNAL_SERVER_ERROR


def generateWopiSrc(fileid, proxy=False):
    '''Returns a WOPISrc for the given fileid.
    Note we'd need to URL-encode it per spec (including `-` to `%2D`), but it turns out that MS Office breaks
    with URL-encoded WOPISrc values via GET (it works via POST), whereas it works with plain WOPISrc values.
    And luckily enough, other known apps (Collabora and OnlyOffice) also work with non-encoded URLs.'''
    #return urllib.parse.quote_plus('%s/wopi/files/%s' % (srv.wopiurl, fileid)).replace('-', '%2D')
    if not proxy or not srv.wopiproxy:
        return '%s/wopi/files/%s' % (srv.wopiurl, fileid)
    # proxy the WOPI request through an external WOPI proxy service
    proxied_fileid = jwt.encode({'u': srv.wopiurl + '/wopi/files/', 'f': fileid}, srv.wopiproxykey, algorithm='HS256')
    log.debug('msg="Generated proxied WOPISrc" fileid="%s" proxiedfileid="%s"' % (fileid, proxied_fileid))
    return '%s/wopi/files/%s' % (srv.wopiproxy, proxied_fileid)


def getLibreOfficeLockName(filename):
    '''Returns the filename of a LibreOffice-compatible lock file.
    This enables interoperability between Online and Desktop applications'''
    return os.path.dirname(filename) + os.path.sep + '.~lock.' + os.path.basename(filename) + '#'


def getMicrosoftOfficeLockName(filename):
    '''Returns the filename of a lock file as created by Microsoft Office'''
    if os.path.splitext(filename)[1] != '.docx' or len(os.path.basename(filename)) <= 6+1+4:
        return os.path.dirname(filename) + os.path.sep + '~$' + os.path.basename(filename)
    # MS Word has a really weird algorithm for the lock file name...
    if len(os.path.basename(filename)) >= 8+1+4:
        return os.path.dirname(filename) + os.path.sep + '~$' + os.path.basename(filename)[2:]
    #elif len(os.path.basename(filename)) == 7+1+4:
    return os.path.dirname(filename) + os.path.sep + '~$' + os.path.basename(filename)[1:]


def randomString(size):
    '''One liner to get a random string of letters'''
    return ''.join([choice(ascii_lowercase) for _ in range(size)])


def generateAccessToken(userid, fileid, viewmode, user, folderurl, endpoint, app):
    '''Generates an access token for a given file and a given user, and returns a tuple with
    the file's inode and the URL-encoded access token.'''
    appname, appediturl, appviewurl = app
    username, wopiuser = user
    try:
        # stat the file to check for existence and get a version-invariant inode and modification time:
        # the inode serves as fileid (and must not change across save operations), the mtime is used for version information.
        statinfo = st.statx(endpoint, fileid, userid, versioninv=1)
    except IOError as e:
        log.info('msg="Requested file not found or not a file" fileid="%s" error="%s"' % (fileid, e))
        raise
    # if write access is requested, probe whether there's already a lock file coming from Desktop applications
    exptime = int(time.time()) + srv.tokenvalidity
    if not appediturl:
        # deprecated: for backwards compatibility, work out the URLs from the discovered app endpoints
        fext = os.path.splitext(statinfo['filepath'])[1]
        try:
            appediturl = endpoints[fext]['edit']
            appviewurl = endpoints[fext]['view']
        except KeyError as e:
            log.critical('msg="No app URLs registered for the given file type" fileext="%s" mimetypescount="%d"' %
                         (fext, len(endpoints) if endpoints else 0))
            raise IOError
    acctok = jwt.encode({'userid': userid, 'wopiuser': wopiuser, 'filename': statinfo['filepath'], 'username': username,
                         'viewmode': viewmode.value, 'folderurl': folderurl, 'endpoint': endpoint,
                         'appname': appname, 'appediturl': appediturl, 'appviewurl': appviewurl, 'exp': exptime},
                        srv.wopisecret, algorithm='HS256')
    log.info('msg="Access token generated" userid="%s" wopiuser="%s" mode="%s" endpoint="%s" filename="%s" inode="%s" ' \
             'mtime="%s" folderurl="%s" appname="%s" expiration="%d" token="%s"' %
             (userid[-20:], wopiuser if wopiuser != userid else username, viewmode, endpoint, \
              statinfo['filepath'], statinfo['inode'], statinfo['mtime'], \
              folderurl, appname, exptime, acctok[-20:]))
    # return the inode == fileid, the filepath and the access token
    return statinfo['inode'], acctok


def retrieveWopiLock(fileid, operation, lock, acctok, overridefilename=None):
    '''Retrieves and logs an existing lock for a given file'''
    encacctok = flask.request.args['access_token'][-20:] if 'access_token' in flask.request.args else 'N/A'
    lockcontent = st.getlock(acctok['endpoint'], overridefilename if overridefilename else acctok['filename'], acctok['userid'])
    if not lockcontent:
        log.warning('msg="%s" user="%s" filename="%s" token="%s" error="WOPI lock not found, ignoring"' %
                    (operation.title(), acctok['userid'][-20:], acctok['filename'], encacctok))
        return None         # no pre-existing lock found, or error attempting to read it: assume it does not exist
    try:
        # check validity: a lock is deemed expired if the most recent between its expiration time and the last
        # save time by WOPI has passed
        retrievedLock = jwt.decode(lockcontent, srv.wopisecret, algorithms=['HS256'])
        savetime = st.getxattr(acctok['endpoint'], acctok['filename'], acctok['userid'], LASTSAVETIMEKEY)
        if max(0 if 'exp' not in retrievedLock else retrievedLock['exp'],
               0 if not savetime else int(savetime) + srv.config.getint('general', 'wopilockexpiration')) < time.time():
            # we got a malformed or expired lock, reject. Note that we may get an ExpiredSignatureError
            # by jwt.decode() as we had stored it with a timed signature.
            raise jwt.exceptions.ExpiredSignatureError
    except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError) as e:
        log.warning('msg="%s" user="%s" filename="%s" token="%s" error="WOPI lock expired or invalid, ignoring" ' \
                    'exception="%s"' % (operation.title(), acctok['userid'][-20:], acctok['filename'], encacctok, type(e)))
        # the retrieved lock is not valid any longer, discard and remove it from the backend
        try:
            st.unlock(acctok['endpoint'], acctok['filename'], acctok['userid'])
        except IOError:
            # ignore, it's not worth to report anything here
            pass
        # also remove the LibreOffice-compatible lock file, if it has the expected signature - cf. storeWopiLock()
        try:
            lolock = next(st.readfile(acctok['endpoint'], getLibreOfficeLockName(acctok['filename']), acctok['userid']))
            if isinstance(lolock, IOError):
                raise lolock
            if 'WOPIServer' in lolock.decode('UTF-8'):
                st.removefile(acctok['endpoint'], getLibreOfficeLockName(acctok['filename']), acctok['userid'], 1)
        except (IOError, StopIteration) as e:
            log.warning('msg="Unable to delete the LibreOffice-compatible lock file" error="%s"' %
                        ('empty lock' if isinstance(e, StopIteration) else str(e)))
        return None
    log.info('msg="%s" user="%s" filename="%s" fileid="%s" lock="%s" retrievedlock="%s" expTime="%s" token="%s"' %
             (operation.title(), acctok['userid'][-20:], acctok['filename'], fileid, lock, retrievedLock['wopilock'],
              time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(retrievedLock['exp'])), encacctok))
    return retrievedLock['wopilock']


def _makeLock(lock):
    '''Generates the lock payload given the raw data'''
    lockcontent = {}
    lockcontent['wopilock'] = lock
    # append or overwrite the expiration time
    lockcontent['exp'] = int(time.time()) + srv.config.getint('general', 'wopilockexpiration')
    return jwt.encode(lockcontent, srv.wopisecret, algorithm='HS256')


def storeWopiLock(fileid, operation, lock, oldlock, acctok, isoffice):
    '''Stores the lock for a given file in the form of an encoded JSON string'''
    try:
        # validate that the underlying file is still there (it might have been moved/deleted)
        st.stat(acctok['endpoint'], acctok['filename'], acctok['userid'])
    except IOError as e:
        log.warning('msg="%s: target file not found any longer" filename="%s" token="%s" reason="%s"' %
                    (operation.title(), acctok['filename'], flask.request.args['access_token'][-20:], e))
        return makeConflictResponse(operation, 'External App', lock, oldlock, acctok['filename'], \
                                    'The file got moved or deleted')

    if isoffice:
        try:
            # first try to look for a MS Office lock
            lockstat = st.stat(acctok['endpoint'], getMicrosoftOfficeLockName(acctok['filename']), acctok['userid'])
            log.info('msg="WOPI lock denied because of an existing Microsoft Office lock" filename="%s" fileid="%s" mtime="%ld"' %
                     (acctok['filename'], fileid, lockstat['mtime']))
            return makeConflictResponse(operation, 'External App', lock, oldlock, acctok['filename'], \
                                        'The file was locked by a Microsoft Office user')    # TODO resolve lockstat['ownerid']
        except IOError:
            pass      # any other error is ignored here, move on

        try:
            # then create a LibreOffice-compatible lock file for interoperability purposes, making sure to
            # not overwrite any existing or being created lock
            lockcontent = ',Collaborative Online Editor,%s,%s,WOPIServer;' % \
                          (srv.wopiurl, time.strftime('%d.%m.%Y %H:%M', time.localtime(time.time())))
            st.writefile(acctok['endpoint'], getLibreOfficeLockName(acctok['filename']), acctok['userid'], \
                         lockcontent, islock=True)
        except IOError as e:
            if EXCL_ERROR in str(e):
                # retrieve the LibreOffice-compatible lock just found
                try:
                    retrievedlolock = next(st.readfile(acctok['endpoint'], \
                                           getLibreOfficeLockName(acctok['filename']), acctok['userid']))
                    if isinstance(retrievedlolock, IOError):
                        raise retrievedlolock
                    retrievedlolock = retrievedlolock.decode('UTF-8')
                    # check that the lock is not stale
                    if datetime.strptime(retrievedlolock.split(',')[3], '%d.%m.%Y %H:%M').timestamp() + \
                                         srv.config.getint('general', 'wopilockexpiration') < time.time():
                        retrievedlolock = 'WOPIServer'
                except (IOError, StopIteration, IndexError, ValueError) as e:
                    retrievedlolock = 'WOPIServer'     # could not read the lock, assume it expired and take ownership
                if 'WOPIServer' not in retrievedlolock:
                    # the file was externally locked, make this call fail
                    lockholder = retrievedlolock.split(',')[1] if ',' in retrievedlolock else ''
                    log.warning('msg="WOPI lock denied because of an existing LibreOffice lock" filename="%s" holder="%s"' %
                                (acctok['filename'], lockholder if lockholder else retrievedlolock))
                    return makeConflictResponse(operation, 'External App', lock, oldlock, acctok['filename'], \
                        'The file was locked by ' + ((lockholder + ' via LibreOffice') if lockholder else 'a LibreOffice user'))
                #else it's our previous lock or it had expired: all right, move on
            elif ACCESS_ERROR in str(e):
                # user has no access to the lock file, typically because of accessing a single-file share:
                # in this case, stat the lock and if it exists assume it is valid (i.e. raise error)
                try:
                    lockstat = st.stat(acctok['endpoint'], getLibreOfficeLockName(acctok['filename']), acctok['userid'])
                    log.info('msg="WOPI lock denied because of an existing LibreOffice lock" filename="%s" mtime="%ld"' %
                             (acctok['filename'], lockstat['mtime']))
                    return makeConflictResponse(operation, 'External App', lock, oldlock, acctok['filename'], \
                                                'The file was locked by a LibreOffice user')   # TODO resolve lockstat['ownerid']
                except IOError as e:
                    pass      # lock not found, assume we're clear
            else:
                # any other error is logged but not raised as this is optimistically not blocking WOPI operations
                log.warning('msg="%s: unable to store LibreOffice-compatible lock" filename="%s" token="%s" lock="%s" reason="%s"' %
                            (operation.title(), acctok['filename'], flask.request.args['access_token'][-20:], lock, e))

    try:
        # now atomically store the lock as encoded JWT
        st.setlock(acctok['endpoint'], acctok['filename'], acctok['userid'], _makeLock(lock))
        log.info('msg="%s" filename="%s" token="%s" lock="%s" result="success"' %
                 (operation.title(), acctok['filename'], flask.request.args['access_token'][-20:], lock))

        # on first lock, set an xattr with the current time for later conflicts checking
        try:
            st.setxattr(acctok['endpoint'], acctok['filename'], acctok['userid'], LASTSAVETIMEKEY, int(time.time()))
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

    except IOError as e:
        if EXCL_ERROR in str(e):
            # another session was faster than us, or the file was already WOPI-locked:
            # get the lock that was set
            retrievedLock = retrieveWopiLock(fileid, operation, lock, acctok)
            if retrievedLock and not compareWopiLocks(retrievedLock, (oldlock if oldlock else lock)):
                return makeConflictResponse(operation, retrievedLock, lock, oldlock, acctok['filename'], \
                                            'The file was locked by another online editor')
            # else it's our lock or it had expired, refresh it and return
            st.refreshlock(acctok['endpoint'], acctok['filename'], acctok['userid'], _makeLock(lock))
            log.info('msg="%s" filename="%s" token="%s" lock="%s" result="refreshed"' %
                     (operation.title(), acctok['filename'], flask.request.args['access_token'][-20:], lock))
            return 'OK', http.client.OK
        # any other error is logged and raised
        log.error('msg="%s: unable to store WOPI lock" filename="%s" token="%s" lock="%s" reason="%s"' %
                  (operation.title(), acctok['filename'], flask.request.args['access_token'][-20:], lock, e))
        raise


def compareWopiLocks(lock1, lock2):
    '''Compares two locks and returns True if they represent the same WOPI lock.
    Officially, the comparison must be based on the locks' string representations, but because of
    a bug in Word Online, currently the internal format of the WOPI locks is looked at, based
    on heuristics. Note that this format is subject to change and is not documented!'''
    if lock1 == lock2:
        log.debug('msg="compareLocks" lock1="%s" lock2="%s" result="True"' % (lock1, lock2))
        return True
    if srv.config.get('general', 'wopilockstrictcheck', fallback='False').upper() == 'TRUE':
        log.debug('msg="compareLocks" lock1="%s" lock2="%s" strict="True" result="False"' % (lock1, lock2))
        return False

    # before giving up, attempt to parse the lock as a JSON dictionary if allowed by the config
    try:
        l1 = json.loads(lock1)
        try:
            l2 = json.loads(lock2)
            if 'S' in l1 and 'S' in l2:
                log.debug('msg="compareLocks" lock1="%s" lock2="%s" strict="False" result="%r"' % (lock1, lock2, l1['S'] == l2['S']))
                return l1['S'] == l2['S']         # used by Word
            log.debug('msg="compareLocks" lock1="%s" lock2="%s" strict="False" result="False"' % (lock1, lock2))
            return False
        except (TypeError, ValueError):
            # lock2 is not a JSON dictionary
            if 'S' in l1:
                log.debug('msg="compareLocks" lock1="%s" lock2="%s" strict="False" result="%r"' % (lock1, lock2, l1['S'] == lock2))
                return l1['S'] == lock2                    # also used by Word (BUG!)
    except (TypeError, ValueError):
        # lock1 is not a JSON dictionary: log the lock values and fail the comparison
        log.debug('msg="compareLocks" lock1="%s" lock2="%s" strict="False" result="False"' % (lock1, lock2))
        return False


def makeConflictResponse(operation, retrievedlock, lock, oldlock, filename, reason=None):
    '''Generates and logs an HTTP 409 response in case of locks conflict'''
    resp = flask.Response()
    resp.headers['X-WOPI-Lock'] = retrievedlock if retrievedlock is not None else 'missing'
    if reason:
        resp.headers['X-WOPI-LockFailureReason'] = resp.data = reason
    resp.status_code = http.client.CONFLICT
    log.warning('msg="%s: returning conflict" filename="%s" token="%s" lock="%s" oldlock="%s" retrievedlock="%s" reason="%s"' %
                (operation.title(), filename, flask.request.args['access_token'][-20:], \
                 lock, oldlock, retrievedlock, (reason if reason else 'N/A')))
    return resp


def storeWopiFile(request, retrievedlock, acctok, xakey, targetname=''):
    '''Saves a file from an HTTP request to the given target filename (defaulting to the access token's one),
         and stores the save time as an xattr. Throws IOError in case of any failure'''
    if not targetname:
        targetname = acctok['filename']
    st.writefile(acctok['endpoint'], targetname, acctok['userid'], request.get_data())
    # save the current time for later conflict checking: this is never older than the mtime of the file
    st.setxattr(acctok['endpoint'], targetname, acctok['userid'], xakey, int(time.time()))
    # and reinstate the lock if existing
    if retrievedlock:
        st.setlock(acctok['endpoint'], targetname, acctok['userid'], _makeLock(retrievedlock))