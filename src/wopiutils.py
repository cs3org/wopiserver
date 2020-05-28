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
import urllib.parse
import http.client
import flask
import jwt


# Convenience dictionary to store some context and avoid globals
_ctx = {}

credentials = {}


def init(storage, wopi):
  '''Convenience method to iniialise this module'''
  _ctx['st'] = storage
  _ctx['wopi'] = wopi
  _ctx['log'] = _ctx['wopi'].log


def logGeneralExceptionAndReturn(ex, req):
  '''Convenience function to log a stack trace and return HTTP 500'''
  ex_type, ex_value, ex_traceback = sys.exc_info()
  _ctx['log'].error('msg="Unexpected exception caught" exception="%s" type="%s" traceback="%s" client="%s" ' \
                    'requestedUrl="%s" token="%s"' % \
                    (ex, ex_type, traceback.format_exception(ex_type, ex_value, ex_traceback), req.remote_addr,
                     req.url, req.args['access_token'][-20:] if 'access_token' in req.args else 'N/A'))
  return 'Internal error', http.client.INTERNAL_SERVER_ERROR


def generateWopiSrc(fileid):
  '''Returns a valid WOPISrc for the given fileid'''
  return urllib.parse.quote_plus('%s/wopi/files/%s' % (_ctx['wopi'].wopiurl, fileid))


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



def generateAccessToken(userid, fileid, canedit, username, folderurl, endpoint):
  '''Generates an access token for a given file and a given user, and returns a tuple with
  the file's inode and the URL-encoded access token.
  Access to this function is protected by source IP address.'''
  try:
    # stat now the file to check for existence and get inode and modification time
    # the inode serves as fileid, the mtime can be used for version information
    statInfo = _ctx['st'].statx(endpoint, fileid, userid)
  except IOError as e:
    _ctx['log'].info('msg="Requested file not found" fileid="%s" error="%s"' % (fileid, e))
    raise
  # if write access is requested, probe whether there's already a lock file coming from Desktop applications
  locked = False
  filename = statInfo['filepath']
  if canedit:
    try:
      # probe LibreOffice
      lock = next(_ctx['st'].readfile(endpoint, getLibreOfficeLockName(filename), userid))
      if isinstance(lock, IOError) or 'WOPIServer' in str(lock):
        # in case of read error, be optimistic and let it go (ENOENT would be fine, other cases have been
        # observed in production and likely are false positives)
        # also if a lock file is found but it is held by a WOPI Server, let it go: it will be sorted out
        # by the collaborative editor via WOPI Lock calls
        raise IOError
      canedit = False
      locked = True
      lock = str(lock)
      _ctx['log'].warning('msg="Access downgraded to read-only because of an existing LibreOffice lock" ' \
                          'filename="%s" holder="%s"' % (filename, lock.split(',')[1] if ',' in lock else lock))
    except IOError:
      try:
        # same for MS Office, but don't try to go beyond stat
        lockInfo = _ctx['st'].stat(endpoint, getMicrosoftOfficeLockName(filename), userid)
        canedit = False
        locked = True
        _ctx['log'].warning('msg="Access downgraded to read-only because of an existing Microsoft Office lock" ' \
        	                  'filename="%s" mtime="%ld"' % (filename, lockInfo['mtime']))
      except IOError:
        pass
  exptime = int(time.time()) + _ctx['wopi'].tokenvalidity
  acctok = jwt.encode({'userid': userid, 'filename': filename, 'username': username, 'canedit': canedit,
                       'extlock': locked, 'folderurl': folderurl, 'exp': exptime, 'endpoint': endpoint}, \
                      _ctx['wopi'].wopisecret, algorithm='HS256').decode('UTF-8')
  _ctx['log'].info('msg="Access token generated" userid="%s" canedit="%r" filename="%s" inode="%s" ' \
                   'mtime="%s" folderurl="%s" expiration="%d" token="%s"' % \
                   (userid, canedit, filename, statInfo['inode'], statInfo['mtime'], folderurl, exptime, acctok[-20:]))
  # return the inode == fileid and the access token
  return statInfo['inode'], acctok


def getLockName(filename):
  '''Generates a hidden filename used to store the WOPI locks'''
  if _ctx['wopi'].lockpath:
    lockfile = filename.split("/files/", 1)[0] + _ctx['wopi'].lockpath + 'wopilock.' + \
               hashlib.sha1(filename).hexdigest() + '.' + os.path.basename(filename)
  else:
    lockfile = os.path.dirname(filename) + os.path.sep + '.sys.wopilock.' + os.path.basename(filename) + '.'
  return lockfile


def retrieveWopiLock(fileid, operation, lock, acctok):
  '''Retrieves and logs an existing lock for a given file'''
  encacctok = flask.request.args['access_token'][-20:] if 'access_token' in flask.request.args else 'N/A'
  lockcontent = b''
  for line in _ctx['st'].readfile(acctok['endpoint'], getLockName(acctok['filename']), acctok['userid']):
    if isinstance(line, IOError):
      return None     # no pre-existing lock found, or error attempting to read it: assume it does not exist
    # the following check is necessary as it happens to get a str instead of bytes
    lockcontent += line if isinstance(line, type(l)) else line.encode()
  try:
    # check validity
    retrievedLock = jwt.decode(l, _ctx['wopi'].wopisecret, algorithms=['HS256'])
    if retrievedLock['exp'] < time.time():
      # we got an expired lock, reject. Note that we may get an ExpiredSignatureError
      # by jwt.decode() as we had stored it with a timed signature.
      raise jwt.exceptions.ExpiredSignatureError
  except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError) as e:
    _ctx['log'].warning('msg="%s" user="%s" filename="%s" token="%s" error="WOPI lock expired or invalid, ignoring" ' \
                        'exception="%s"' % (operation.title(), acctok['userid'], acctok['filename'], encacctok, type(e)))
    # the retrieved lock is not valid any longer, discard and remove it from the backend
    try:
      _ctx['st'].removefile(acctok['endpoint'], getLockName(acctok['filename']), acctok['userid'], 1)
    except IOError:
      # ignore, it's not worth to report anything here
      pass
    # also remove the LibreOffice-compatible lock file, if it has the expected signature - cf. _storeWopiLock()
    try:
      lock = str(next(_ctx['st'].readfile(acctok['endpoint'], getLibreOfficeLockName(acctok['filename']), acctok['userid'])))
      if 'WOPIServer' in lock:
        _ctx['st'].removefile(acctok['endpoint'], getLibreOfficeLockName(acctok['filename']), acctok['userid'], 1)
    except IOError as e:
      _ctx['log'].warning('msg="Unable to delete the LibreOffice-compatible lock file" error="%s"' % e)
    return None
  _ctx['log'].info('msg="%s" user="%s" filename="%s" fileid="%s" lock="%s" retrievedLock="%s" expTime="%s" token="%s"' % \
                   (operation.title(), acctok['userid'], acctok['filename'], fileid, lock,
                    retrievedLock['wopilock'], time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(retrievedLock['exp'])),
                    encacctok))
  return retrievedLock['wopilock']


def storeWopiLock(operation, lock, acctok):
  '''Stores the lock for a given file in the form of an encoded JSON string (cf. the access token)'''
  lockcontent = {}
  lockcontent['wopilock'] = lock
  # append or overwrite the expiration time
  lockcontent['exp'] = int(time.time()) + _ctx['wopi'].config.getint('general', 'wopilockexpiration')
  try:
    # store the lock as encoded JWT
    s = jwt.encode(l, _ctx['wopi'].wopisecret, algorithm='HS256')
    _ctx['st'].writefile(acctok['endpoint'], getLockName(acctok['filename']), acctok['userid'], s, 1)
    _ctx['log'].info('msg="%s" filename="%s" token="%s" lock="%s" result="success"' % \
                     (operation.title(), acctok['filename'], flask.request.args['access_token'][-20:], lock))
    # also create a LibreOffice-compatible lock file for interoperability purposes
    locontent = ',Collaborative Online Editor,%s,%s,WOPIServer;' % \
            (_ctx['wopi'].wopiurl, time.strftime('%d.%m.%Y %H:%M', time.localtime(time.time())))
    _ctx['st'].writefile(acctok['endpoint'], getLibreOfficeLockName(acctok['filename']), acctok['userid'], locontent, 1)
  except IOError as e:
    _ctx['log'].warning('msg="%s" filename="%s" token="%s" lock="%s" result="unable to store lock" reason="%s"' % \
                        (operation.title(), acctok['filename'], flask.request.args['access_token'][-20:], lock, e))


def compareWopiLocks(lock1, lock2):
  '''Compares two locks and returns True if they represent the same WOPI lock.
     Officially, the comparison must be based on the locks' string representations, but because of
     a bug in Word Online, currently the internal format of the WOPI locks is looked at, based
     on heuristics. Note that this format is subject to change and is not documented!'''
  if lock1 == lock2:
    _ctx['log'].debug('msg="compareLocks" lock1="%s" lock2="%s" result="True"' % (lock1, lock2))
    return True
  # before giving up, attempt to parse the lock as a JSON dictionary
  try:
    l1 = json.loads(lock1)
    try:
      l2 = json.loads(lock2)
      if 'S' in l1 and 'S' in l2:
        _ctx['log'].debug('msg="compareLocks" lock1="%s" lock2="%s" result="%r"' % (lock1, lock2, l1['S'] == l2['S']))
        return l1['S'] == l2['S']     # used by Word
      #elif 'L' in lock1 and 'L' in lock2:
      #  _ctx['log'].debug('msg="compareLocks" lock1="%s" lock2="%s" result="%r"' % (lock1, lock2, lock1['L'] == lock2['L']))
      #  return lock1['L'] == lock2['L']     # used by Excel and PowerPoint
      _ctx['log'].debug('msg="compareLocks" lock1="%s" lock2="%s" result="False"' % (lock1, lock2))
      return False
    except (TypeError, ValueError):
      # lock2 is not a JSON dictionary
      if 'S' in l1:
        _ctx['log'].debug('msg="compareLocks" lock1="%s" lock2="%s" result="%r"' % (lock1, lock2, l1['S'] == lock2))
        return l1['S'] == lock2          # also used by Word (BUG!)
  except (TypeError, ValueError):
    # lock1 is not a JSON dictionary: log the lock values and fail the comparison
    _ctx['log'].debug('msg="compareLocks" lock1="%s" lock2="%s" result="False"' % (lock1, lock2))
    return False


def makeConflictResponse(operation, retrievedlock, lock, oldlock, filename):
  '''Generates and logs an HTTP 401 response in case of locks conflict'''
  resp = flask.Response()
  resp.headers['X-WOPI-Lock'] = retrievedlock if retrievedlock else ''
  resp.status_code = http.client.CONFLICT
  _ctx['log'].info('msg="%s" filename="%s" token="%s", lock="%s" oldLock="%s" retrievedLock="%s" result="conflict"' % \
                   (operation.title(), filename, flask.request.args['access_token'][-20:], lock, oldlock, retrievedlock))
  return resp


def storeWopiFile(request, acctok, xakey, targetname=''):
  '''Saves a file from an HTTP request to the given target filename (defaulting to the access token's one),
     and stores the save time as an xattr. Throws IOError in case of any failure'''
  if not targetname:
    targetname = acctok['filename']
  _ctx['st'].writefile(acctok['endpoint'], targetname, acctok['userid'], request.get_data())
  # save the current time for later conflict checking: this is never older than the mtime of the file
  _ctx['st'].setxattr(acctok['endpoint'], targetname, acctok['userid'], xakey, int(time.time()))
