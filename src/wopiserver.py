#!/bin/python
'''
wopiserver.py

The Web-application Open Platform Interface (WOPI) gateway for CERNBox

Author: Giuseppe.LoPresti@cern.ch
CERN/IT-ST
'''

import sys, os, time, socket, traceback, ConfigParser
from platform import python_version
import logging
import logging.handlers
import urllib, httplib, json
try:
  import flask                 # Flask app server, python-flask-0.10.1-4.el7.noarch.rpm + pyOpenSSL-0.13.1-3.el7.x86_64.rpm
  import jwt                   # PyJWT JSON Web Token, python-jwt-1.4.0-2.el7.noarch.rpm
  import xrootiface as xrdcl   # a wrapper around the xrootd python bindings, xrootd-python-4.4.x.el7.x86_64.rpm
except ImportError:
  print "Missing modules, please install xrootd-python, python-flask, python-jwt"
  sys.exit(-1)

# the following constant is replaced on the fly when generating the RPM (cf. spec file)
WOPISERVERVERSION = 'git'

# this is the xattr key used for conflicts resolution on the remote storage
LASTSAVETIMEKEY = 'oc.wopi.lastwritetime'

# Initialization
try:
  _loglevels = {"Critical": logging.CRITICAL,  # 50
                "Error":    logging.ERROR,     # 40
                "Warning":  logging.WARNING,   # 30
                "Info":     logging.INFO,      # 20
                "Debug":    logging.DEBUG      # 10
               }
  lastConfigReadTime = time.time()
  # read the configuration
  config = ConfigParser.SafeConfigParser()
  config.readfp(open('/etc/wopi/wopiserver.defaults.conf'))    # fails if the file does not exist
  config.read('/etc/wopi/wopiserver.conf')
  # prepare the Flask web app
  app = flask.Flask("WOPIServer")
  log = app.logger
  log.setLevel(_loglevels[config.get('general', 'loglevel')])
  loghandler = logging.FileHandler('/var/log/cernbox/wopiserver.log')
  loghandler.setFormatter(logging.Formatter(fmt='%(asctime)s %(name)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%dT%H:%M:%S'))
  log.addHandler(loghandler)
  wopisecret = open(config.get('security', 'wopisecretfile')).read().strip('\n')
  ocsecret = open(config.get('security', 'ocsecretfile')).read().strip('\n')
  tokenvalidity = config.getint('general', 'tokenvalidity')
  xrdcl.init(config, log)                          # initialize the xroot client module
  config.get('general', 'allowedclients')          # read this to make sure it is configured
  useHttps = config.get('security', 'usehttps').lower() == 'yes'
  if useHttps:
    log.info('msg="WOPI Server starting in secure mode"')
  else:
    log.warning('msg="WOPI Server starting in plain http, use for testing purposes only"')
except Exception, e:
  # any error we get here with the configuration is fatal
  print "Failed to initialize the service, bailing out:", e
  sys.exit(-1)


#
# General utilities
#
def _ourHostName():
  '''Returns the WOPI web address taking into account whether it's http or https'''
  if useHttps:
    return 'https://%s' % socket.gethostname()
  else:
    return 'http://%s:8080' % socket.gethostname()


def _generateAccessToken(ruid, rgid, filename, canedit, username):
  '''Generate an access token for a given file of a given user, and returns a URL-encoded string
  suitable to be passed as a WOPISrc value to a Microsoft Office Online server.
  Access to this function is protected by source IP address.'''
  try:
    # stat now the file to check for existence and get inode and modification time
    # the inode serves as fileid, the mtime can be used for version information
    statx = xrdcl.statx(filename, ruid, rgid)
    inode = statx[2]
    mtime = statx[12]
  except IOError, e:
    log.info('msg="Requested file not found" filename="%s" error="%s"' % (filename, e))
    raise
  exptime = int(time.time()) + tokenvalidity
  acctok = jwt.encode({'ruid': ruid, 'rgid': rgid, 'filename': filename, 'canedit': canedit, 'username': username,
                       'mtime': mtime, 'exp': exptime}, wopisecret, algorithm='HS256')
  log.info('msg="Access token generated" ruid="%s" rgid="%s" canedit="%r" filename="%s" inode="%s" ' \
           'mtime="%s" expiration="%d" acctok="%s"' % \
           (ruid, rgid, canedit, filename, inode, mtime, exptime, acctok[-20:]))
  # return the inode == fileid and the access token
  return inode, acctok


def _refreshConfig():
  '''Re-read the configuration file every 300 secs to catch any runtime parameter change'''
  global lastConfigReadTime
  global tokenvalidity
  if time.time() > lastConfigReadTime + 300:
    lastConfigReadTime = time.time()
    config.read('/etc/wopi/wopiserver.conf')
    # refresh some general parameters
    tokenvalidity = config.getint('general', 'tokenvalidity')
    log.setLevel(_loglevels[config.get('general', 'loglevel')])


def _logGeneralExceptionAndReturn(ex):
  '''Convenience function to log a stack trace and return HTTP 500'''
  ex_type, ex_value, ex_traceback = sys.exc_info()
  log.error('msg="Unexpected exception caught" exception="%s" type="%s" traceback="%s"' % \
            (ex, ex_type, traceback.format_exception(ex_type, ex_value, ex_traceback)))
  return 'Internal error', httplib.INTERNAL_SERVER_ERROR


#
# Utilities for the POST-related file actions
#
def _getLockName(filename):
  '''Generates a hidden filename used to store the WOPI locks'''
  return os.path.dirname(filename) + os.path.sep + '.sys.wopilock.' + os.path.basename(filename) + '.'


def _retrieveWopiLock(fileid, operation, lock, acctok):
  '''Retrieves and logs an existing lock for a given file'''
  try:
    for l in xrdcl.readfile(_getLockName(acctok['filename']), '0', '0'):
      retrievedLock = l         # one iteration is largely sufficient to hit EOF
    retrievedLock = jwt.decode(retrievedLock, wopisecret, algorithms=['HS256'])
  except IOError:
    return None     # no pre-existing lock found
  except jwt.exceptions.DecodeError:
    log.warning('msg="%s" user="%s:%s" filename="%s" error="WOPI lock corrupted, ignoring"' % \
                (operation.title(), acctok['ruid'], acctok['rgid'], acctok['filename']))
    return None
  log.info('msg="%s" user="%s:%s" filename="%s" fileid="%s" lock="%s" retrievedLock="%s" expTime="%s"' % \
           (operation.title(), acctok['ruid'], acctok['rgid'], acctok['filename'], fileid, lock, retrievedLock, \
            time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(retrievedLock['exp']))))
  if retrievedLock['exp'] < time.time():
    # the retrieved lock is not valid any longer, discard
    return None
  return retrievedLock


def _storeWopiLock(operation, lock, acctok):
  '''Stores the lock for a given file in the form of an encoded JSON string (cf. the access token)'''
  # append the expiration time
  lock['exp'] = int(time.time()) + config.getint('general', 'wopilockexpiration')
  try:
    xrdcl.writefile(_getLockName(acctok['filename']), '0', '0', jwt.encode(lock, wopisecret, algorithm='HS256'))
    log.info('msg="%s" filename="%s" lock="%s" result="success"' % (operation.title(), acctok['filename'], lock))
  except IOError, e:
    log.warning('msg="%s" filename="%s" lock="%s" result="unable to store lock" reason="%s"' % \
                (operation.title(), acctok['filename'], lock, e))


def _compareWopiLocks(lock1, lock2):
  '''Compares two dictionaries and returns True if they represent the same WOPI lock.
     Note that there's no documentation about the internal format of the WOPI locks and
     the comparison is purely based on heuristics!'''
  if 'L' in lock1 and 'L' in lock2:
    log.debug('msg="compareLocks" lock1="%s" lock2="%s" result="%r"' % (lock1, lock2, lock1['L'] == lock2['L']))
    return lock1['L'] == lock2['L']     # used by Excel and PowerPoint
  elif 'S' in lock1 and 'S' in lock2:
    log.debug('msg="compareLocks" lock1="%s" lock2="%s" result="%r"' % (lock1, lock2, lock1['S'] == lock2['S']))
    return lock1['S'] == lock2['S']     # used by Word
  else:
    # not sure this makes sense
    log.debug('msg="compareLocks" lock1="%s" lock2="%s" result="%r"' % (lock1, lock2, lock1 == lock2))
    return lock1 == lock2


def _makeConflictResponse(operation, retrievedlock, lock, oldlock, filename):
  '''Generates and logs an HTTP 401 response in case of locks conflict'''
  resp = flask.Response()
  resp.headers['X-WOPI-Lock'] = json.dumps(retrievedlock)
  resp.status_code = httplib.CONFLICT
  log.info('msg="%s" filename="%s" lock="%s" oldLock="%s" retrievedLock="%s" result="conflict"' % \
           (operation.title(), filename, lock, oldlock, retrievedlock))
  return resp


def _storeWopiFile(request, acctok, targetname=''):
  '''Saves a file from an HTTP request to the given target filename (defaulting to the access token's one),
     and stores the save time as an xattr. Throws IOError in case of any failure'''
  if not targetname:
    targetname = acctok['filename']
  xrdcl.writefile(targetname, acctok['ruid'], acctok['rgid'], request.get_data())
  # save the current time for later conflict checking: this is never lesser than the mtime of the file
  xrdcl.setxattr(targetname, acctok['ruid'], acctok['rgid'], LASTSAVETIMEKEY, int(time.time()))


#############################################################################################################
#
# The Web Application starts here
#
#############################################################################################################

@app.route("/")
def index():
  '''Return a default index page with some user-friendly information about this service'''
  log.info('msg="Accessed index page" client="%s"' % flask.request.remote_addr)
  return """
    <div align="center" style="color:#000080; padding-top:50px; font-family:Verdana; size:11">
    This is the CERNBox <a href=http://wopi.readthedocs.io>WOPI</a> server for Microsoft Office Online.<br>
    To use this service, please log in to your <a href=https://cernbox.cern.ch>CERNBox</a> account
    and click on the View/Edit buttons next to your Microsoft Office documents.</div>
    <br><br><br><br><br><br><br><br><br><br><hr>
    <i>CERNBox WOPI Server %s. Powered by Flask %s for Python %s</i>.
    """ % (WOPISERVERVERSION, flask.__version__, python_version())


@app.route("/cbox/open", methods=['GET'])
def cboxOpen():
  '''Returns a WOPISrc target and an access token to be passed to Microsoft Office online for
  accessing a given file for a given user. This is the most sensitive call as it provides direct
  access to any user's file, therefore it is protected both by IP and a shared secret. The shared
  secret protection is disabled when running in plain http mode for testing purposes.'''
  _refreshConfig()
  req = flask.request
  # if running in https mode, first check if the shared secret matches ours
  if useHttps and ('Authorization' not in req.headers or req.headers['Authorization'] != 'Bearer ' + ocsecret):
    log.info('msg="cboxOpen: unauthorized access attempt, missing authorization token" client="%s"' % req.remote_addr)
    return 'Client not authorized', httplib.UNAUTHORIZED
  # now validate the user identity and deny root access
  try:
    ruid = int(req.args['ruid'])
    rgid = int(req.args['rgid'])
    if ruid == 0 or rgid == 0:
      raise ValueError
  except ValueError:
    log.info('msg="cboxOpen: invalid user/group in request" client="%s" user="%s:%s"' % \
             req.remote_addr, req.args['ruid'], req.args['rgid'])
    return 'Client not authorized', httplib.UNAUTHORIZED
  # then resolve the client: only our OwnCloud servers shall use this API
  allowedclients = config.get('general', 'allowedclients').split()
  for c in allowedclients:
    try:
      for ip in socket.getaddrinfo(c, None):
        if ip[4][0] == req.remote_addr:
          # we got a match, generate the access token
          filename = urllib.unquote(req.args['filename'])
          canedit = 'canedit' in req.args and req.args['canedit'].lower() == 'true'
          username = req.args['username'] if 'username' in req.args else 'Anonymous'
          try:
            log.info('msg="cboxOpen: access granted, generating token" client="%s" user="%d:%d" friendlyname="%s"' % \
                     (req.remote_addr, ruid, rgid, username))
            inode, acctok = _generateAccessToken(str(ruid), str(rgid), filename, canedit, username)
            # return an URL-encoded WOPISrc URL for the Office Online server
            return urllib.quote_plus('%s/wopi/files/%s' % (_ourHostName(), inode)) + \
                   '&access_token=%s' % acctok      # no need to URL-encode the JWT token
          except IOError:
            return 'Remote error or file not found', httplib.NOT_FOUND
    except socket.gaierror:
      log.warning('msg="cboxOpen: %s found in configured allowed clients but unknown by DNS resolution, ignoring"' % c)
  # no match found, fail
  log.info('msg="cboxOpen: unauthorized access attempt, client IP not whitelisted" client="%s"' % req.remote_addr)
  return 'Client not authorized', httplib.UNAUTHORIZED


@app.route("/cbox/download", methods=['GET'])
def cboxDownload():
  '''Returns the file's content for a given valid access token. Used as a download URL,
     so that the file's path is never explicitly visible.'''
  try:
    acctok = jwt.decode(flask.request.args['access_token'], wopisecret, algorithms=['HS256'])
    if acctok['exp'] < time.time():
      raise jwt.exceptions.ExpiredSignatureError
    resp = flask.Response(xrdcl.readfile(acctok['filename'], acctok['ruid'], acctok['rgid']), mimetype='application/octet-stream')
    resp.headers['Content-Disposition'] = 'attachment; filename="%s"' % os.path.basename(acctok['filename'])
    resp.status_code = httplib.OK
    log.info('msg="cboxDownload: direct download succeeded" filename="%s" user="%s:%s" acctok="%s"' % \
             (acctok['filename'], acctok['ruid'], acctok['rgid'], flask.request.args['access_token'][-20:]))
    return resp
  except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError) as e:
    log.warning('msg="Signature verification failed" token="%s"' % flask.request.args['access_token'])
    return 'Invalid access token', httplib.NOT_FOUND
  except IOError, e:
    log.info('msg="Requested file not found" filename="%s" error="%s"' % (acctok['filename'], e))
    return 'File not found', httplib.NOT_FOUND
  except KeyError, e:
    log.error('msg="Invalid access token or request argument" error="%s"' % e)
    return 'Invalid access token', httplib.UNAUTHORIZED
  except Exception, e:
    return _logGeneralExceptionAndReturn(e)


#
# The WOPI protocol implementation starts here
#
@app.route("/wopi/files/<fileid>", methods=['GET'])
def wopiCheckFileInfo(fileid):
  '''Implements the CheckFileInfo WOPI call'''
  # cf. http://wopi.readthedocs.io/projects/wopirest/en/latest/files/CheckFileInfo.html
  _refreshConfig()
  try:
    acctok = jwt.decode(flask.request.args['access_token'], wopisecret, algorithms=['HS256'])
    if acctok['exp'] < time.time():
      raise jwt.exceptions.ExpiredSignatureError
    log.info('msg="CheckFileInfo" user="%s:%s" filename"%s" fileid="%s" acctok="%s"' % \
             (acctok['ruid'], acctok['rgid'], acctok['filename'], fileid, flask.request.args['access_token'][-20:]))
    statInfo = xrdcl.statx(acctok['filename'], acctok['ruid'], acctok['rgid'])
    # populate metadata for this file
    filemd = {}
    filemd['BaseFileName'] = os.path.basename(acctok['filename'])
    filemd['OwnerId'] = statInfo[5] + ':' + statInfo[6]
    filemd['UserId'] = acctok['ruid'] + ':' + acctok['rgid']    # typically same as OwnerId
    filemd['UserFriendlyName'] = acctok['username']
    filemd['Size'] = long(statInfo[8])
    filemd['Version'] = acctok['mtime']
    filemd['SupportsUpdate'] = filemd['UserCanWrite'] = filemd['SupportsLocks'] = \
        filemd['SupportsRename'] = filemd['UserCanRename'] = acctok['canedit']
    #filemd['UserCanPresent'] = True   # what about the broadcasting feature in Office Online?
    filemd['DownloadUrl'] = '%s?access_token=%s' % \
                            (config.get('general', 'downloadurl'), flask.request.args['access_token'])
    log.debug('msg="File metadata response" metadata="%s"' % filemd)
    # send in JSON format
    return flask.Response(json.dumps(filemd), mimetype='application/json')
  except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError) as e:
    log.warning('msg="Signature verification failed" token="%s"' % flask.request.args['access_token'])
    return 'Invalid access token', httplib.NOT_FOUND
  except IOError, e:
    log.info('msg="Requested file not found" filename="%s" error="%s"' % (acctok['filename'], e))
    return 'File not found', httplib.NOT_FOUND
  except KeyError, e:
    log.error('msg="Invalid access token or request argument" error="%s"' % e)
    return 'Invalid access token', httplib.UNAUTHORIZED
  except Exception, e:
    return _logGeneralExceptionAndReturn(e)


@app.route("/wopi/files/<fileid>/contents", methods=['GET'])
def wopiGetFile(fileid):
  '''Implements the GetFile WOPI call'''
  _refreshConfig()
  try:
    acctok = jwt.decode(flask.request.args['access_token'], wopisecret, algorithms=['HS256'])
    if acctok['exp'] < time.time():
      raise jwt.exceptions.ExpiredSignatureError
    log.info('msg="GetFile" user="%s:%s" filename="%s" fileid="%s" acctok="%s"' % \
             (acctok['ruid'], acctok['rgid'], acctok['filename'], fileid, flask.request.args['access_token'][-20:]))
    # stream file from storage to client
    resp = flask.Response(xrdcl.readfile(acctok['filename'], acctok['ruid'], acctok['rgid']), mimetype='application/octet-stream')
    resp.headers['X-WOPI-ItemVersion'] = acctok['mtime']
    resp.status_code = httplib.OK
    return resp
  except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError) as e:
    log.warning('msg="Signature verification failed" token="%s"' % flask.request.args['access_token'])
    return 'Invalid access token', httplib.UNAUTHORIZED
  except Exception, e:
    return _logGeneralExceptionAndReturn(e)


#
# The following operations are all called on POST /wopi/files/<fileid>
#
def wopiLock(fileid, reqheaders, acctok):
  '''Implements the Lock and RefreshLock WOPI calls'''
  # cf. http://wopi.readthedocs.io/projects/wopirest/en/latest/files/Lock.html
  op = reqheaders['X-WOPI-Override']
  lock = reqheaders['X-WOPI-Lock']
  try:
    lock = json.loads(lock)
  except ValueError:
    log.warning('msg="%s" filename="%s" lock="%s" result="invalid format"' % (op.title(), acctok['filename'], lock))
    return 'Invalid JSON-formatted lock', httplib.BAD_REQUEST
  oldLock = json.loads(reqheaders['X-WOPI-OldLock']) if 'X-WOPI-OldLock' in reqheaders else None
  retrievedLock = _retrieveWopiLock(fileid, op, lock, acctok)
  # perform the required checks for the validity of the new lock
  if (oldLock is None and retrievedLock != None and not _compareWopiLocks(retrievedLock, lock)) or \
     (oldLock != None and not _compareWopiLocks(retrievedLock, oldLock)):
    return _makeConflictResponse(op, retrievedLock, lock, oldLock, acctok['filename'])
  # LOCK or REFRESH_LOCK: set the lock to the given one, including the expiration time
  _storeWopiLock(op, lock, acctok)
  if not retrievedLock:
    # on first lock, set an xattr with the current time for later conflicts checking
    try:
      xrdcl.setxattr(acctok['filename'], acctok['ruid'], acctok['rgid'], LASTSAVETIMEKEY, int(time.time()))
    except IOError, e:
      # not fatal, but will generate a conflict file later on, so log a warning
      log.warning('msg="Unable to set lastwritetime xattr" user="%s:%s" filename="%s" reason="%s"' % \
                  (acctok['ruid'], acctok['rgid'], acctok['filename'], e))
  return 'OK', httplib.OK


def wopiUnlock(fileid, reqheaders, acctok):
  '''Implements the Unlock WOPI call'''
  lock = reqheaders['X-WOPI-Lock']
  try:
    lock = json.loads(lock)
  except ValueError:
    log.warning('msg="Unlock" filename="%s" lock="%s" result="invalid format"' % (acctok['filename'], lock))
    return 'Invalid JSON-formatted lock', httplib.BAD_REQUEST
  retrievedLock = _retrieveWopiLock(fileid, 'UNLOCK', lock, acctok)
  if retrievedLock and not _compareWopiLocks(retrievedLock, lock):
    return _makeConflictResponse('UNLOCK', retrievedLock, lock, '', acctok['filename'])
  if not retrievedLock:
    # there was no lock, do nothing and return success
    return 'OK', httplib.OK
  # OK, the lock matches. Remove any extended attribute related to locks and conflicts handling
  try:
    xrdcl.removefile(_getLockName(acctok['filename']), '0', '0')
  except IOError:
    # ignore, it's not worth to report anything here
    pass
  try:
    xrdcl.rmxattr(acctok['filename'], acctok['ruid'], acctok['rgid'], LASTSAVETIMEKEY)
  except IOError:
    # same as above
    pass
  return 'OK', httplib.OK


def wopiGetLock(fileid, reqheaders_unused, acctok):
  '''Implements the GetLock WOPI call'''
  resp = flask.Response()
  resp.headers['X-WOPI-Lock'] = json.dumps(_retrieveWopiLock(fileid, 'GETLOCK', '', acctok))
  resp.status_code = httplib.OK
  return resp


def wopiPutRelative(fileid, reqheaders, acctok):
  '''Implements the PutRelative WOPI call. Corresponds to the 'Save as...' menu entry.'''
  # cf. http://wopi.readthedocs.io/projects/wopirest/en/latest/files/PutRelativeFile.html
  suggTarget = reqheaders['X-WOPI-SuggestedTarget'] if 'X-WOPI-SuggestedTarget' in reqheaders else ''
  relTarget = reqheaders['X-WOPI-RelativeTarget'] if 'X-WOPI-RelativeTarget' in reqheaders else ''
  overwriteTarget = 'X-WOPI-OverwriteRelativeTarget' in reqheaders and bool(reqheaders['X-WOPI-OverwriteRelativeTarget'])
  log.info('msg="PutRelative" user="%s:%s" filename="%s" fileid="%s" suggTarget="%s" relTarget="%s" overwrite="%r" acctok="%s"' % \
           (acctok['ruid'], acctok['rgid'], acctok['filename'], fileid, \
            suggTarget, relTarget, overwriteTarget, flask.request.args['access_token'][-20:]))
  # either one xor the other must be present
  if (suggTarget and relTarget) or (not suggTarget and not relTarget):
    return 'Not supported', httplib.NOT_IMPLEMENTED
  if suggTarget:
    # the suggested target is a filename that can be changed to avoid collisions
    if suggTarget[0] == '.':    # we just have the extension here
      targetName = os.path.splitext(acctok['filename'])[0] + suggTarget
    else:
      targetName = os.path.dirname(acctok['filename']) + os.path.sep + suggTarget
    # check for existence of the target file and adjust until a non-existing one is obtained
    while True:
      try:
        xrdcl.stat(targetName, acctok['ruid'], acctok['rgid'])
        # the file exists: try a different name
        name, ext = os.path.splitext(targetName)
        targetName = name + '_copy' + ext
      except IOError, e:
        if 'No such file or directory' in str(e):
          # OK, the targetName is good to go
          break
        else:
          log.info('msg="PutRelative" user="%s:%s" filename="%s" suggTarget="%s" error="%s"' % \
                   (acctok['ruid'], acctok['rgid'], targetName, suggTarget, str(e)))
          return 'Illegal filename %s: %s' % (targetName, e), httplib.BAD_REQUEST
  else:
    # the relative target is a filename to be respected, and that may overwrite an existing file
    relTarget = os.path.dirname(acctok['filename']) + os.path.sep + relTarget    # make full path
    try:
      # check for file existence + lock
      fileExists = retrievedLock = False
      fileExists = xrdcl.stat(relTarget, acctok['ruid'], acctok['rgid'])
      retrievedLock = xrdcl.stat(_getLockName(relTarget), '0', '0')
    except IOError:
      pass
    if fileExists and (not overwriteTarget or retrievedLock):
      return _makeConflictResponse('PUTRELATIVE', retrievedLock, '', '', relTarget)
    # else we can use the relative target
    targetName = relTarget
  # either way, we now have a targetName to save the file: attempt to do so
  try:
    _storeWopiFile(flask.request, acctok, targetName)
  except IOError, e:
    log.info('msg="Error writing file" filename="%s" error="%s"' % (targetName, e))
    return 'I/O Error', httplib.INTERNAL_SERVER_ERROR
  # generate an access token for the new file
  log.info('msg="PutRelative: generating new access token" user="%s:%s" filename="%s" canedit="True" friendlyname="%s"' % \
           (acctok['ruid'], acctok['rgid'], targetName, acctok['username']))
  inode, newacctok = _generateAccessToken(acctok['ruid'], acctok['rgid'], targetName, True, acctok['username'])
  # prepare and send the response as JSON
  putrelmd = {}
  putrelmd['Name'] = os.path.basename(targetName)
  putrelmd['Url'] = urllib.quote_plus('%s/wopi/files/%s' % (_ourHostName(), inode)) + '&access_token=' + newacctok
  return flask.Response(json.dumps(putrelmd), mimetype='application/json')


def wopiDeleteFile(fileid, reqheaders_unused, acctok):
  '''Implements the DeleteFile WOPI call'''
  retrievedLock = _retrieveWopiLock(fileid, 'DELETEFILE', '', acctok)
  if retrievedLock != None:
    # file is locked and cannot be deleted
    return _makeConflictResponse('DELETEFILE', retrievedLock, '', '', acctok['filename'])
  try:
    xrdcl.removefile(acctok['filename'], acctok['ruid'], acctok['rgid'])
    return 'OK', httplib.OK
  except IOError, e:
    log.info('msg="DeleteFile" error="%s"' % e)
    return 'Internal error', httplib.INTERNAL_SERVER_ERROR


def wopiRenameFile(fileid, reqheaders, acctok):
  '''Implements the RenameFile WOPI call'''
  targetName = reqheaders['X-WOPI-RequestedName']
  lock = reqheaders['X-WOPI-Lock']
  try:
    lock = json.loads(lock)
  except ValueError:
    log.warning('msg="RenameFile" filename="%s" lock="%s" result="invalid format"' % (acctok['filename'], lock))
    return 'Invalid JSON-formatted lock', httplib.BAD_REQUEST
  retrievedLock = _retrieveWopiLock(fileid, 'RENAMEFILE', lock, acctok)
  if retrievedLock != None and not _compareWopiLocks(retrievedLock, lock):
    return _makeConflictResponse('RENAMEFILE', retrievedLock, lock, '', acctok['filename'])
  try:
    targetName += os.path.splitext(acctok['filename'])[1]    # the destination name comes without extension
    log.info('msg="RenameFile" user="%s:%s" filename="%s" fileid="%s" targetname="%s"' % \
             (acctok['ruid'], acctok['rgid'], acctok['filename'], fileid, targetName))
    xrdcl.renamefile(acctok['filename'], targetName, acctok['ruid'], acctok['rgid'])
    # prepare and send the response as JSON
    renamemd = {}
    renamemd['Name'] = os.path.basename(targetName)
    return flask.Response(json.dumps(renamemd), mimetype='application/json')
  except IOError, e:
    # assume the rename failed because of the destination filename and report the error
    resp = flask.Response()
    resp.headers['X-WOPI-InvalidFileNameError'] = 'Failed to rename: %s' % e
    resp.status_code = httplib.BAD_REQUEST
    return resp


@app.route("/wopi/files/<fileid>", methods=['POST'])
def wopiFilesPost(fileid):
  '''A dispatcher metod for all POST operations on files'''
  _refreshConfig()
  try:
    acctok = jwt.decode(flask.request.args['access_token'], wopisecret, algorithms=['HS256'])
    if acctok['exp'] < time.time():
      raise jwt.exceptions.ExpiredSignatureError
    headers = flask.request.headers
    op = headers['X-WOPI-Override']       # must be one of the following strings, throws KeyError if missing
    if op in ('LOCK', 'REFRESH_LOCK'):
      return wopiLock(fileid, headers, acctok)
    elif op == 'UNLOCK':
      return wopiUnlock(fileid, headers, acctok)
    elif op == 'GET_LOCK':
      return wopiGetLock(fileid, headers, acctok)
    elif op == 'PUT_RELATIVE':
      return wopiPutRelative(fileid, headers, acctok)
    elif op == 'DELETE_FILE':
      return wopiDeleteFile(fileid, headers, acctok)
    elif op == 'RENAME_FILE':
      return wopiRenameFile(fileid, headers, acctok)
    #elif op == 'PUT_USER_INFO':   https://wopirest.readthedocs.io/en/latest/files/PutUserInfo.html
    else:
      log.warning('msg="Unknown/unsupported operation" operation="%s"' % op)
      return 'Not supported operation found in header', httplib.NOT_IMPLEMENTED
  except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError) as e:
    log.warning('msg="Signature verification failed" token="%s"' % flask.request.args['access_token'])
    return 'Invalid access token', httplib.NOT_FOUND
  except KeyError, e:
    log.error('msg="Invalid access token or request argument" error="%s"' % e)
    return 'Missing header %s in POST request' % e, httplib.BAD_REQUEST
  except Exception, e:
    return _logGeneralExceptionAndReturn(e)


@app.route("/wopi/files/<fileid>/contents", methods=['POST'])
def wopiPutFile(fileid):
  '''Implements the PutFile WOPI call'''
  _refreshConfig()
  try:
    acctok = jwt.decode(flask.request.args['access_token'], wopisecret, algorithms=['HS256'])
    if acctok['exp'] < time.time():
      raise jwt.exceptions.ExpiredSignatureError
    # check that the caller holds the current lock on the file
    lock = json.loads(flask.request.headers['X-WOPI-Lock'])
    retrievedLock = _retrieveWopiLock(fileid, 'PUTFILE', lock, acctok)
    if retrievedLock != None and not _compareWopiLocks(retrievedLock, lock):
      return _makeConflictResponse('PUTFILE', retrievedLock, lock, '', acctok['filename'])
    # OK, we can save the file now
    log.info('msg="PutFile" user="%s:%s" filename="%s" fileid="%s" acctok="%s"' % \
             (acctok['ruid'], acctok['rgid'], acctok['filename'], fileid, flask.request.args['access_token'][-20:]))
    try:
      # check now the destination file against conflicts
      savetime = int(xrdcl.getxattr(acctok['filename'], acctok['ruid'], acctok['rgid'], LASTSAVETIMEKEY))
      # we got our xattr: if mtime is greater, someone may have updated the file from a FUSE or SMB mount
      mtime = xrdcl.stat(acctok['filename'], acctok['ruid'], acctok['rgid']).modtime
      log.debug('msg="Got lastWopiSaveTime" user="%s:%s" filename="%s" savetime="%ld" lastmtime="%ld"' % \
                (acctok['ruid'], acctok['rgid'], acctok['filename'], savetime, mtime))
      if mtime > savetime:
        # this is the case, force conflict
        raise IOError
    except IOError:
      # either the file was deleted or it was updated/overwritten by others: force conflict
      newname, ext = os.path.splitext(acctok['filename'])
      # XXX note the OwnCloud format is '<filename>_conflict-<date>-<time>', but it is not synchronized back !!
      newname = '%s-conflict-%s%s' % (newname, time.strftime('%Y%m%d-%H%M%S'), ext.strip())
      _storeWopiFile(flask.request, acctok, newname)
      # keep track of this action in the original file's xattr, to avoid looping (see below)
      xrdcl.setxattr(acctok['filename'], acctok['ruid'], acctok['rgid'], LASTSAVETIMEKEY, 'conflict')
      log.info('msg="Conflicting copy created" user="%s:%s" newFilename="%s"' % (acctok['ruid'], acctok['rgid'], newname))
      # and report failure to Office Online: it will retry a couple of times and eventually it will notify the user
      return 'Conflicting copy created', httplib.INTERNAL_SERVER_ERROR
    except ValueError:
      # the xattr was not an integer: assume Office Online is looping on an already conflicting file,
      # therefore do nothing and keep reporting internal error. Of course if the attribute was modified by hand,
      # this mechanism fails.
      log.info('msg="Conflicting copy already created" user="%s:%s" filename="%s"' % \
               (acctok['ruid'], acctok['rgid'], acctok['filename']))
      return 'Conflicting copy already created', httplib.INTERNAL_SERVER_ERROR
    # Go for overwriting the file. Note that the entire check+write operation should be atomic,
    # but the previous check still gives the opportunity of a race condition. We just live with it
    # as OwnCloud does not seem to provide anything better...
    # Anyhow, previous versions are all stored and recoverable by the user.
    _storeWopiFile(flask.request, acctok)
    log.info('msg="File successfully written" user="%s:%s" filename="%s"' % (acctok['ruid'], acctok['rgid'], acctok['filename']))
    return 'OK', httplib.OK
  except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError) as e:
    log.warning('msg="Signature verification failed" token="%s"' % flask.request.args['access_token'])
    return 'Invalid access token', httplib.NOT_FOUND
  except IOError, e:
    log.info('msg="Error writing file" filename="%s" error="%s"' % (acctok['filename'], e))
    return 'I/O Error', httplib.INTERNAL_SERVER_ERROR
  except Exception, e:
    return _logGeneralExceptionAndReturn(e)


#
# Start the Flask endless listening loop
#
if useHttps:
  app.run(host='0.0.0.0', port=443, threaded=True, debug=(config.get('general', 'loglevel') == 'Debug'),
          ssl_context=(config.get('security', 'wopicert'), config.get('security', 'wopikey')))
else:
  app.run(host='0.0.0.0', port=8080, threaded=True, debug=(config.get('general', 'loglevel') == 'Debug'))
