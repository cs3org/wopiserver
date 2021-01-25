'''
wopiutils.py

General Low-level functions to support the WOPI server
'''

import sys
import os
import time
import traceback
import hashlib
import json
from urllib.parse import quote_plus as url_quote_plus
from enum import Enum
from random import choice
from string import ascii_lowercase
import http.client
import flask
import jwt


# standard error thrown when attemtping to overwrite a file in O_EXCL mode
EXCL_ERROR = 'File exists and islock flag requested'

# convenience references to global entities
st = None
wopi = None
log = None

class ViewMode(Enum):
  '''File view mode: reference is
  https://github.com/cs3org/cs3apis/blob/master/cs3/app/provider/v1beta1/provider_api.proto#L79
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
      '''internal method returned by getattr and wrapping the original one'''
      if name in ['debug', 'info', 'warning', 'error', 'fatal']:
        # as we use a `key="value" ...` format in all logs, we only have args[0]
        msg = args[0] + ' '
        try:
          # now convert that to a dictionary assuming no `="` nor `" ` is present inside any key or value!
          # the added trailing space matches the `" ` split, so we remove the last element of that list
          msg = dict([tuple(kv.split('="')) for kv in msg.split('" ')[:-1]])
          # then convert dict -> json -> str + strip `{` and `}`
          return getattr(self.logger, name)(str(json.dumps(msg))[1:-1], **kwargs)
        except Exception:
          # if the above assumptions do not hold, keep the log in its original format
          return getattr(self.logger, name)(*args, **kwargs)
      elif hasattr(self.logger, name):
        # pass-through facade
        return getattr(self.logger, name)(*args, **kwargs)
      else:
        return lambda: NotImplemented
    return facade


def logGeneralExceptionAndReturn(ex, req):
  '''Convenience function to log a stack trace and return HTTP 500'''
  ex_type, ex_value, ex_traceback = sys.exc_info()
  log.error('msg="Unexpected exception caught" exception="%s" type="%s" traceback="%s" client="%s" ' \
            'requestedUrl="%s" token="%s"' % \
            (ex, ex_type, traceback.format_exception(ex_type, ex_value, ex_traceback), req.remote_addr,
             req.url, req.args['access_token'][-20:] if 'access_token' in req.args else 'N/A'))
  return 'Internal error, please contact support', http.client.INTERNAL_SERVER_ERROR


def generateWopiSrc(fileid):
  '''Returns a valid URL-encoded WOPISrc for the given fileid'''
  return url_quote_plus('%s/wopi/files/%s' % (wopi.wopiurl, fileid))


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


def generateAccessToken(userid, fileid, viewmode, username, folderurl, endpoint):
  '''Generates an access token for a given file and a given user, and returns a tuple with
  the file's inode and the URL-encoded access token.'''
  try:
    # stat the file to check for existence and get a version-invariant inode and modification time:
    # the inode serves as fileid (and must not change across save operations), the mtime is used for version information.
    statInfo = st.statx(endpoint, fileid, userid, versioninv=1)
  except IOError as e:
    log.info('msg="Requested file not found or not a file" fileid="%s" error="%s"' % (fileid, e))
    raise
  # if write access is requested, probe whether there's already a lock file coming from Desktop applications
  exptime = int(time.time()) + wopi.tokenvalidity
  acctok = jwt.encode({'userid': userid, 'filename': statInfo['filepath'], 'username': username, 'viewmode': viewmode.value,
                       'folderurl': folderurl, 'exp': exptime, 'endpoint': endpoint}, wopi.wopisecret, algorithm='HS256')
  log.info('msg="Access token generated" userid="%s" mode="%s" filename="%s" inode="%s" ' \
           'mtime="%s" folderurl="%s" expiration="%d" token="%s"' % \
           (userid, viewmode, statInfo['filepath'], statInfo['inode'], statInfo['mtime'], \
            folderurl, exptime, acctok[-20:]))
  # return the inode == fileid and the access token
  return statInfo['inode'], acctok


def getLockName(filename):
  '''Generates a hidden filename used to store the WOPI locks'''
  if wopi.lockpath:
    lockfile = filename.split("/files/", 1)[0] + wopi.lockpath + 'wopilock.' + \
               hashlib.sha1(filename).hexdigest() + '.' + os.path.basename(filename)
  else:
    lockfile = os.path.dirname(filename) + os.path.sep + '.sys.wopilock.' + os.path.basename(filename) + '.'
  return lockfile


def retrieveWopiLock(fileid, operation, lock, acctok):
  '''Retrieves and logs an existing lock for a given file'''
  encacctok = flask.request.args['access_token'][-20:] if 'access_token' in flask.request.args else 'N/A'
  lockcontent = b''
  for line in st.readfile(acctok['endpoint'], getLockName(acctok['filename']), acctok['userid']):
    if isinstance(line, IOError):
      return None     # no pre-existing lock found, or error attempting to read it: assume it does not exist
    # the following check is necessary as it happens to get a str instead of bytes
    lockcontent += line if isinstance(line, type(lockcontent)) else line.encode()
  try:
    # check validity
    retrievedLock = jwt.decode(lockcontent, wopi.wopisecret, algorithms=['HS256'])
    if 'exp' not in retrievedLock or retrievedLock['exp'] < time.time():
      # we got a malformed or expired lock, reject. Note that we may get an ExpiredSignatureError
      # by jwt.decode() as we had stored it with a timed signature.
      raise jwt.exceptions.ExpiredSignatureError
  except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError) as e:
    log.warning('msg="%s" user="%s" filename="%s" token="%s" error="WOPI lock expired or invalid, ignoring" ' \
                'exception="%s"' % (operation.title(), acctok['userid'], acctok['filename'], encacctok, type(e)))
    # the retrieved lock is not valid any longer, discard and remove it from the backend
    try:
      st.removefile(acctok['endpoint'], getLockName(acctok['filename']), acctok['userid'], 1)
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
      log.warning('msg="Unable to delete the LibreOffice-compatible lock file" error="%s"' % \
                  ('empty lock' if isinstance(e, StopIteration) else str(e)))
    return None
  log.info('msg="%s" user="%s" filename="%s" fileid="%s" lock="%s" retrievedLock="%s" expTime="%s" token="%s"' % \
           (operation.title(), acctok['userid'], acctok['filename'], fileid, lock, retrievedLock['wopilock'],
            time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(retrievedLock['exp'])), encacctok))
  return retrievedLock['wopilock']


def storeWopiLock(operation, lock, acctok, isnotoffice):
  '''Stores the lock for a given file in the form of an encoded JSON string (cf. the access token)'''
  try:
    # validate that the underlying file is still there (it might have been moved/deleted)
    st.stat(acctok['endpoint'], acctok['filename'], acctok['userid'])
  except IOError as e:
    log.warning('msg="%s: target file not found any longer" filename="%s" token="%s" reason="%s"' % \
                (operation.title(), acctok['filename'], flask.request.args['access_token'][-20:], e))
    raise

  if not isnotoffice:
    try:
      # first try to look for a MS Office lock
      lockstat = st.stat(acctok['endpoint'], getMicrosoftOfficeLockName(acctok['filename']), acctok['userid'])
      log.info('msg="WOPI lock denied because of an existing Microsoft Office lock" filename="%s" mtime="%ld"' % \
               (acctok['filename'], lockstat['mtime']))
      raise IOError(EXCL_ERROR)
    except IOError as e:
      if EXCL_ERROR in str(e):
        raise
      #else any other error is ignored here, move on

    try:
      # then create a LibreOffice-compatible lock file for interoperability purposes, making sure to
      # not overwrite any existing or being created lock
      lockcontent = ',Collaborative Online Editor,%s,%s,WOPIServer;' % \
                    (wopi.wopiurl, time.strftime('%d.%m.%Y %H:%M', time.localtime(time.time())))
      st.writefile(acctok['endpoint'], getLibreOfficeLockName(acctok['filename']), acctok['userid'], \
                   lockcontent, islock=True)
    except IOError as e:
      if EXCL_ERROR in str(e):
        # retrieve the LibreOffice-compatible lock just found
        try:
          retrievedlock = next(st.readfile(acctok['endpoint'], \
                                           getLibreOfficeLockName(acctok['filename']), acctok['userid']))
          if isinstance(retrievedlock, IOError):
            raise retrievedlock
          retrievedlock = retrievedlock.decode('UTF-8')
        except (IOError, StopIteration) as e:
          retrievedlock = ''   # could not read the lock, maybe it's empty: still, deny WOPI lock
        if 'WOPIServer' not in retrievedlock:
          # the file was externally locked, make this call fail
          log.info('msg="WOPI lock denied because of an existing LibreOffice lock" filename="%s" holder="%s"' % \
                   (acctok['filename'], retrievedlock.split(',')[1] if ',' in retrievedlock else retrievedlock))
          raise
        #else it's our previous lock: all right, move on
      else:
        # any other error is logged and raised
        log.error('msg="%s: unable to store LibreOffice-compatible lock" filename="%s" token="%s" lock="%s" reason="%s"' % \
                  (operation.title(), acctok['filename'], flask.request.args['access_token'][-20:], lock, e))
        raise

  try:
    # now store the lock as encoded JWT: note that we do not use islock=True, because the WOPI specs require
    # this operation to be essentially idempotent, so it should not fail if the lock was there or is being
    # created by another thread.
    lockcontent = {}
    lockcontent['wopilock'] = lock
    # append or overwrite the expiration time
    lockcontent['exp'] = int(time.time()) + wopi.config.getint('general', 'wopilockexpiration')
    st.writefile(acctok['endpoint'], getLockName(acctok['filename']), acctok['userid'], \
                 jwt.encode(lockcontent, wopi.wopisecret, algorithm='HS256'))
    log.info('msg="%s" filename="%s" token="%s" lock="%s" result="success"' % \
             (operation.title(), acctok['filename'], flask.request.args['access_token'][-20:], lock))
  except IOError as e:
    # any other error is logged and raised
    log.error('msg="%s: unable to store WOPI lock" filename="%s" token="%s" lock="%s" reason="%s"' % \
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
  # XXX before giving up, attempt to parse the lock as a JSON dictionary
  try:
    l1 = json.loads(lock1)
    try:
      l2 = json.loads(lock2)
      if 'S' in l1 and 'S' in l2:
        log.debug('msg="compareLocks" lock1="%s" lock2="%s" result="%r"' % (lock1, lock2, l1['S'] == l2['S']))
        return l1['S'] == l2['S']     # used by Word
      log.debug('msg="compareLocks" lock1="%s" lock2="%s" result="False"' % (lock1, lock2))
      return False
    except (TypeError, ValueError):
      # lock2 is not a JSON dictionary
      if 'S' in l1:
        log.debug('msg="compareLocks" lock1="%s" lock2="%s" result="%r"' % (lock1, lock2, l1['S'] == lock2))
        return l1['S'] == lock2          # also used by Word (BUG!)
  except (TypeError, ValueError):
    # lock1 is not a JSON dictionary: log the lock values and fail the comparison
    log.debug('msg="compareLocks" lock1="%s" lock2="%s" result="False"' % (lock1, lock2))
    return False


def makeConflictResponse(operation, retrievedlock, lock, oldlock, filename, reason=None):
  '''Generates and logs an HTTP 401 response in case of locks conflict'''
  resp = flask.Response()
  resp.headers['X-WOPI-Lock'] = retrievedlock if retrievedlock else ''
  if reason:
    resp.headers['X-WOPI-LockFailureReason'] = resp.data = reason
  resp.status_code = http.client.CONFLICT
  log.info('msg="%s" filename="%s" token="%s" lock="%s" oldLock="%s" retrievedLock="%s" %s' % \
           (operation.title(), filename, flask.request.args['access_token'][-20:], \
            lock, oldlock, retrievedlock, ('reason="%s"' % reason if reason else 'result="conflict"')))
  return resp


def storeWopiFile(request, acctok, xakey, targetname=''):
  '''Saves a file from an HTTP request to the given target filename (defaulting to the access token's one),
     and stores the save time as an xattr. Throws IOError in case of any failure'''
  if not targetname:
    targetname = acctok['filename']
  st.writefile(acctok['endpoint'], targetname, acctok['userid'], request.get_data())
  # save the current time for later conflict checking: this is never older than the mtime of the file
  st.setxattr(acctok['endpoint'], targetname, acctok['userid'], xakey, int(time.time()))
