'''
utils.py

General Low-level functions to support the WOPI server
'''

import sys
import os
import time
import traceback
import urllib.parse
import http.client
try:
  import jwt                     # PyJWT JSON Web Token, python3-jwt-1.6.1 or above
except ImportError:
  print("Missing modules, please install JWT with `pip3 install PyJWT pyOpenSSL`")
  raise

_ctx = {}

def init(storage, wopi):
  '''Convenience method to iniialise this module'''
  _ctx['st'] = storage
  _ctx['wopi'] = wopi
  _ctx['log'] = wopi.log


def logGeneralExceptionAndReturn(ex, req):
  '''Convenience function to log a stack trace and return HTTP 500'''
  ex_type, ex_value, ex_traceback = sys.exc_info()
  _ctx['log'].error('msg="Unexpected exception caught" exception="%s" type="%s" traceback="%s" client="%s" requestedUrl="%s" token="%s"' % \
                    (ex, ex_type, traceback.format_exception(ex_type, ex_value, ex_traceback), req.remote_addr, req.url, \
                     req.args['access_token'][-20:] if 'access_token' in req.args else 'N/A'))
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
  if os.path.splitext(filename)[1] == '.docx':
    return os.path.dirname(filename) + os.path.sep + '~$' + os.path.basename(filename)[2:]
  else:
    return os.path.dirname(filename) + os.path.sep + '~$' + os.path.basename(filename)


def generateAccessToken(ruid, rgid, filename, canedit, username, folderurl, endpoint):
  '''Generate an access token for a given file of a given user, and returns a tuple with
  the file's inode and the URL-encoded access token.
  Access to this function is protected by source IP address.'''
  try:
    # stat now the file to check for existence and get inode and modification time
    # the inode serves as fileid, the mtime can be used for version information
    statInfo = _ctx['st'].statx(endpoint, filename, ruid, rgid)
  except IOError as e:
    _ctx['log'].info('msg="Requested file not found" filename="%s" error="%s"' % (filename, e))
    raise
  # if write access is requested, probe whether there's already a lock file coming from Desktop applications
  if canedit:
    locked = False
    try:
      # probe LibreOffice
      line = str(next(_ctx['st'].readfile(endpoint, getLibreOfficeLockName(filename), _ctx['wopi'].lockruid, _ctx['wopi'].lockrgid)))
      if 'ERROR on read' in line or 'WOPIServer' in line:
        # in case of read error, be optimistic and let it go (ENOENT would be fine, other cases have been
        # observed in production and likely are false positives)
        # also if a lock file is found but it is held by a WOPI Server, let it go: it will be sorted out
        # by the collaborative editor via WOPI Lock calls
        raise IOError
      canedit = False
      locked = True
      _ctx['log'].warning('msg="Access downgraded to read-only because of an existing LibreOffice lock" filename="%s" holder="%s"' % \
                          (filename, line.split(',')[1]))
    except IOError:
      try:
        # same for MS Office, but don't try to go beyond stat
        lockInfo = _ctx['st'].stat(endpoint, getMicrosoftOfficeLockName(filename), _ctx['wopi'].lockruid, _ctx['wopi'].lockrgid)
        canedit = False
        locked = True
        _ctx['log'].warning('msg="Access downgraded to read-only because of an existing Microsoft Office lock" ' \
        	                'filename="%s" mtime="%ld"' % (filename, lockInfo['mtime']))
      except IOError:
        pass
  exptime = int(time.time()) + _ctx['wopi'].tokenvalidity
  acctok = jwt.encode({'ruid': ruid, 'rgid': rgid, 'filename': filename, 'username': username,
                       'canedit': canedit, 'extlock': locked, 'folderurl': folderurl, 'exp': exptime, 'endpoint': endpoint},
                       _ctx['wopi'].wopisecret, algorithm='HS256').decode('UTF-8')
  _ctx['log'].info('msg="Access token generated" ruid="%s" rgid="%s" canedit="%r" filename="%s" inode="%s" ' \
                   'mtime="%s" folderurl="%s" expiration="%d" token="%s"' % \
                   (ruid, rgid, canedit, filename, statInfo['inode'], statInfo['mtime'], folderurl, exptime, acctok[-20:]))
  # return the inode == fileid and the access token
  return statInfo['inode'], acctok
