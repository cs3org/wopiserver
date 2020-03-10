#!/usr/bin/python3
'''
wopiserver.py

The Web-application Open Platform Interface (WOPI) gateway for CERNBox

Author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
Contributions: Michael.DSilva@aarnet.edu.au
'''

import sys
import os
import time
import traceback
import socket
import configparser
from platform import python_version
import logging
import logging.handlers
import urllib.request, urllib.parse, urllib.error
import http.client
import json
import hashlib
try:
  import flask                   # Flask app server, python3-flask-0.12.2 + python3-pyOpenSSL-17.3.0
  import jwt                     # PyJWT JSON Web Token, python3-jwt-1.6.1 or above
except ImportError:
  print("Missing modules, please install Flask and JWT with `pip3 install flask PyJWT pyOpenSSL`")
  raise

# the following constant is replaced on the fly when generating the RPM (cf. spec file)
WOPISERVERVERSION = 'git'

# this is the xattr key used for conflicts resolution on the remote storage
LASTSAVETIMEKEY = 'oc.wopi.lastwritetime'

# alias of the storage layer module, see function below
storage = None

def storage_layer_import(storagetype):
  '''A convenience function to import the storage layer module specified in the config and make it globally available'''
  global storage        # pylint: disable=global-statement
  if storagetype in ['local', 'xroot', 'cs3']:
    storagetype += 'iface'
  else:
    raise ImportError('Unsupported/Unknown storage type %s' % storagetype)
  try:
    storage = __import__(storagetype, globals(), locals())
  except ImportError:
    print("Missing module when attempting to import {}. Please make sure dependencies are met.", storagetype)
    raise


class Wopi:
  '''A singleton container for all state information of the WOPI server'''
  app = flask.Flask("WOPIServer")
  port = 0
  lastConfigReadTime = time.time()
  loglevels = {"Critical": logging.CRITICAL,  # 50
               "Error":    logging.ERROR,     # 40
               "Warning":  logging.WARNING,   # 30
               "Info":     logging.INFO,      # 20
               "Debug":    logging.DEBUG      # 10
              }
  log = app.logger
  openfiles = {}

  @classmethod
  def init(cls):
    '''Initialises the application, bails out in case of failures. Note this is not a __init__ method'''
    try:
      # configure the logging
      loghandler = logging.FileHandler('/var/log/wopi/wopiserver.log')
      loghandler.setFormatter(logging.Formatter(fmt='%(asctime)s %(name)s[%(process)d] %(levelname)-8s %(message)s',
                                                datefmt='%Y-%m-%dT%H:%M:%S'))
      cls.log.addHandler(loghandler)
      # read the configuration
      cls.config = configparser.ConfigParser()
      cls.config.read_file(open('/etc/wopi/wopiserver.defaults.conf'))
      cls.config.read('/etc/wopi/wopiserver.conf')
      # load the requested storage layer
      storage_layer_import(cls.config.get('general', 'storagetype'))
      # prepare the Flask web app
      cls.port = int(cls.config.get('general', 'port'))
      cls.log.setLevel(cls.loglevels[cls.config.get('general', 'loglevel')])
      cls.wopisecret = open(cls.config.get('security', 'wopisecretfile')).read().strip('\n')
      cls.ocsecret = open(cls.config.get('security', 'ocsecretfile')).read().strip('\n')
      cls.tokenvalidity = cls.config.getint('general', 'tokenvalidity')
      storage.init(cls.config, cls.log)                          # initialize the xroot client module
      cls.config.get('general', 'allowedclients')          # read this to make sure it is configured
      cls.useHttps = cls.config.get('security', 'usehttps').lower() == 'yes'
      cls.repeatedLockRequests = {}               # cf. the wopiLock() function below
      cls.wopiurl = cls.config.get('general', 'wopiurl')
      if urllib.parse.urlparse(cls.wopiurl).port is None:
        cls.wopiurl += ':%d' % cls.port
      cls.lockruid = cls.config.get('general', 'lockruid')
      cls.lockrgid = cls.config.get('general', 'lockrgid')
      if cls.config.has_option('general', 'lockpath'):
        cls.lockpath = cls.config.get('general', 'lockpath')
      else:
        cls.lockpath = ''
    except Exception as e:
      # any error we get here with the configuration is fatal
      cls.log.fatal('msg="Failed to initialize the service, aborting" error="%s"' % e)
      sys.exit(-22)

  @classmethod
  def initAppsRegistry(cls):
    '''Initializes the CERNBoxOffice-like Apps Registry'''
    # TODO all this is supposed to be moved to the CERNBox Apps Registry microservice at some stage in the future
    cls.ENDPOINTS = {}

    oos = cls.config.get('general', 'oosurl', fallback=None)
    if oos is not None:
      # The supported Microsoft Office Online end-points
      cls.ENDPOINTS['.docx'] = {}
      cls.ENDPOINTS['.docx']['view'] = oos + '/wv/wordviewerframe.aspx?edit=0'
      cls.ENDPOINTS['.docx']['edit'] = oos + '/we/wordeditorframe.aspx?edit=1'
      cls.ENDPOINTS['.docx']['new']  = oos + '/we/wordeditorframe.aspx?new=1'                          # pylint: disable=bad-whitespace
      cls.ENDPOINTS['.xlsx'] = {}
      cls.ENDPOINTS['.xlsx']['view'] = oos + '/x/_layouts/xlviewerinternal.aspx?edit=0'
      cls.ENDPOINTS['.xlsx']['edit'] = oos + '/x/_layouts/xlviewerinternal.aspx?edit=1'
      cls.ENDPOINTS['.xlsx']['new']  = oos + '/x/_layouts/xlviewerinternal.aspx?edit=1&new=1'          # pylint: disable=bad-whitespace
      cls.ENDPOINTS['.pptx'] = {}
      cls.ENDPOINTS['.pptx']['view'] = oos + '/p/PowerPointFrame.aspx?PowerPointView=ReadingView'
      cls.ENDPOINTS['.pptx']['edit'] = oos + '/p/PowerPointFrame.aspx?PowerPointView=EditView'
      cls.ENDPOINTS['.pptx']['new']  = oos + '/p/PowerPointFrame.aspx?PowerPointView=EditView&New=1'   # pylint: disable=bad-whitespace
      cls.ENDPOINTS['.one'] = {}
      cls.ENDPOINTS['.one']['view']  = oos + '/o/onenoteframe.aspx?edit=0'                             # pylint: disable=bad-whitespace
      cls.ENDPOINTS['.one']['edit']  = oos + '/o/onenoteframe.aspx?edit=1'                             # pylint: disable=bad-whitespace
      cls.ENDPOINTS['.one']['new']   = oos + '/o/onenoteframe.aspx?edit=1&new=1'                       # pylint: disable=bad-whitespace
      cls.log.info('msg="Microsoft Office Online endpoints successfully configured"')

    code = cls.config.get('general', 'codeurl', fallback=None)
    if code is not None:
      try:
        import requests
        from xml.etree import ElementTree as ET
        discData = requests.get(url=(code + '/hosting/discovery'), verify=False).content
        discXml = ET.fromstring(discData)
        if discXml is None:
          raise Exception('Failed to parse XML: %s' % discData)
        # extract urlsrc from first <app> node inside <net-zone>
        urlsrc = discXml.find('net-zone/app')[0].attrib['urlsrc']

        # The supported Collabora end-points
        cls.ENDPOINTS['.odt'] = {}
        cls.ENDPOINTS['.odt']['view'] = urlsrc + 'permission=readonly'
        cls.ENDPOINTS['.odt']['edit'] = urlsrc + 'permission=view'
        cls.ENDPOINTS['.odt']['new']  = urlsrc + 'permission=edit'        # pylint: disable=bad-whitespace
        cls.ENDPOINTS['.ods'] = {}
        cls.ENDPOINTS['.ods']['view'] = urlsrc + 'permission=readonly'
        cls.ENDPOINTS['.ods']['edit'] = urlsrc + 'permission=view'
        cls.ENDPOINTS['.ods']['new']  = urlsrc + 'permission=edit'        # pylint: disable=bad-whitespace
        cls.ENDPOINTS['.odp'] = {}
        cls.ENDPOINTS['.odp']['view'] = urlsrc + 'permission=readonly'
        cls.ENDPOINTS['.odp']['edit'] = urlsrc + 'permission=view'
        cls.ENDPOINTS['.odp']['new']  = urlsrc + 'permission=edit'        # pylint: disable=bad-whitespace
        cls.log.info('msg="Collabora Online endpoints successfully configured" CODEURL="%s"' % cls.ENDPOINTS['.odt']['edit'])

      except Exception as e:
        cls.log.warning('msg="Failed to initialize Collabora Online endpoints" error="%s"' % e)

    # The future-supported Slides end-point
    # slides = cls.config.get('general', 'slidesurl', fallback=None)
    # ...
    #cls.ENDPOINTS['.slide'] = {}
    #cls.ENDPOINTS['.slide']['view'] =
    #cls.ENDPOINTS['.slide']['edit'] =
    #cls.ENDPOINTS['.slide']['new'] =

    # backstop if no app got registered
    if len(cls.ENDPOINTS) == 0:
      cls.log.fatal('msg="No office app got registered, aborting"')
      sys.exit(-22)


  @classmethod
  def refreshconfig(cls):
    '''Re-read the configuration file every 300 secs to catch any runtime parameter change'''
    if time.time() > cls.lastConfigReadTime + 300:
      cls.lastConfigReadTime = time.time()
      cls.config.read('/etc/wopi/wopiserver.conf')
      # refresh some general parameters
      cls.tokenvalidity = cls.config.getint('general', 'tokenvalidity')
      cls.log.setLevel(cls.loglevels[cls.config.get('general', 'loglevel')])
      cls.lockruid = cls.config.get('general', 'lockruid')
      cls.lockrgid = cls.config.get('general', 'lockrgid')


  @classmethod
  def run(cls):
    '''Runs the Flask app in either standalone (https) or embedded (http) mode'''
    if cls.useHttps:
      cls.log.info('msg="WOPI Server starting in standalone secure mode" port="%d" wopiurl="%s"' % (cls.port, cls.wopiurl))
      cls.app.run(host='0.0.0.0', port=cls.port, threaded=True, debug=(cls.config.get('general', 'loglevel') == 'Debug'),
                  ssl_context=(cls.config.get('security', 'wopicert'), cls.config.get('security', 'wopikey')))
    else:
      cls.log.info('msg="WOPI Server starting in unsecure/embedded mode" port="%d" wopiurl="%s"' % (cls.port, cls.wopiurl))
      cls.app.run(host='0.0.0.0', port=cls.port, threaded=True, debug=(cls.config.get('general', 'loglevel') == 'Debug'))


#
# General utilities
#
def _generateWopiSrc(fileid):
  '''Returns a valid WOPISrc for the given fileid'''
  return urllib.parse.quote_plus('%s/wopi/files/%s' % (Wopi.wopiurl, fileid))


def _logGeneralExceptionAndReturn(ex, req):
  '''Convenience function to log a stack trace and return HTTP 500'''
  ex_type, ex_value, ex_traceback = sys.exc_info()
  Wopi.log.error('msg="Unexpected exception caught" exception="%s" type="%s" traceback="%s" client="%s" requestedUrl="%s" token="%s"' % \
                 (ex, ex_type, traceback.format_exception(ex_type, ex_value, ex_traceback), req.remote_addr, req.url, \
                  req.args['access_token'][-20:] if 'access_token' in req.args else 'N/A'))
  return 'Internal error', http.client.INTERNAL_SERVER_ERROR


def _generateAccessToken(ruid, rgid, filename, canedit, username, folderurl, endpoint):
  '''Generate an access token for a given file of a given user, and returns a tuple with
  the file's inode and the URL-encoded access token.
  Access to this function is protected by source IP address.'''
  try:
    # stat now the file to check for existence and get inode and modification time
    # the inode serves as fileid, the mtime can be used for version information
    statInfo = storage.statx(endpoint, filename, ruid, rgid)
  except IOError as e:
    Wopi.log.info('msg="Requested file not found" filename="%s" error="%s"' % (filename, e))
    raise
  exptime = int(time.time()) + Wopi.tokenvalidity
  acctok = jwt.encode({'ruid': ruid, 'rgid': rgid, 'filename': filename, 'username': username,
                       'canedit': canedit, 'folderurl': folderurl, 'exp': exptime, 'endpoint': endpoint},
                      Wopi.wopisecret, algorithm='HS256').decode('UTF-8')
  Wopi.log.info('msg="Access token generated" ruid="%s" rgid="%s" canedit="%r" filename="%s" inode="%s" ' \
                'mtime="%s" folderurl="%s" expiration="%d" token="%s"' % \
                (ruid, rgid, canedit, filename, statInfo['inode'], statInfo['mtime'], folderurl, exptime, acctok[-20:]))
  # return the inode == fileid and the access token
  return statInfo['inode'], acctok


#
# Utilities for the POST-related file actions
#
def _getLockName(filename):
  '''Generates a hidden filename used to store the WOPI locks'''
  if Wopi.lockpath:
    lockfile = filename.split("/files/", 1)[0] + Wopi.lockpath + 'wopilock.' + \
               hashlib.sha1(filename).hexdigest() + '.' + os.path.basename(filename)
  else:
    lockfile = os.path.dirname(filename) + os.path.sep + '.sys.wopilock.' + os.path.basename(filename) + '.'
  return lockfile


def _retrieveWopiLock(fileid, operation, lock, acctok):
  '''Retrieves and logs an existing lock for a given file'''
  l = b''
  for line in storage.readfile(acctok['endpoint'], _getLockName(acctok['filename']), Wopi.lockruid, Wopi.lockrgid):
    if 'No such file or directory' in str(line):
      return None     # no pre-existing lock found
    # the following check is necessary as it happens to get a str instead of bytes
    l += line if type(line) == type(l) else line.encode()
  try:
    # check validity
    retrievedLock = jwt.decode(l, Wopi.wopisecret, algorithms=['HS256'])
    if retrievedLock['exp'] < time.time():
      # we got an expired lock, reject. Note that we may get an ExpiredSignatureError
      # by jwt.decode() as we had stored it with a timed signature.
      raise jwt.exceptions.ExpiredSignatureError
  except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError) as e:
    Wopi.log.warning('msg="%s" user="%s:%s" filename="%s" token="%s" error="WOPI lock expired or invalid, ignoring" exception="%s"' % \
                     (operation.title(), acctok['ruid'], acctok['rgid'], acctok['filename'], \
                      flask.request.args['access_token'][-20:], type(e)))
    # the retrieved lock is not valid any longer, discard and remove it from the backend
    try:
      storage.removefile(acctok['endpoint'], _getLockName(acctok['filename']), Wopi.lockruid, Wopi.lockrgid, 1)
    except IOError:
      # ignore, it's not worth to report anything here
      pass
    return None
  Wopi.log.info('msg="%s" user="%s:%s" filename="%s" fileid="%s" lock="%s" retrievedLock="%s" expTime="%s" token="%s"' % \
                (operation.title(), acctok['ruid'], acctok['rgid'], acctok['filename'], fileid, lock, retrievedLock['wopilock'], \
                 time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(retrievedLock['exp'])), flask.request.args['access_token'][-20:]))
  return retrievedLock['wopilock']


def _storeWopiLock(operation, lock, acctok):
  '''Stores the lock for a given file in the form of an encoded JSON string (cf. the access token)'''
  l = {}
  l['wopilock'] = lock
  # append or overwrite the expiration time
  l['exp'] = int(time.time()) + Wopi.config.getint('general', 'wopilockexpiration')
  try:
    s = jwt.encode(l, Wopi.wopisecret, algorithm='HS256')
    storage.writefile(acctok['endpoint'], _getLockName(acctok['filename']), Wopi.lockruid, Wopi.lockrgid, s, 1)
    Wopi.log.info('msg="%s" filename="%s" token="%s" lock="%s" result="success"' % \
                  (operation.title(), acctok['filename'], flask.request.args['access_token'][-20:], lock))
    Wopi.log.debug('msg="%s" encodedlock="%s" length="%d"' % (operation.title(), s, len(s)))
  except IOError as e:
    Wopi.log.warning('msg="%s" filename="%s" token="%s" lock="%s" result="unable to store lock" reason="%s"' % \
                     (operation.title(), acctok['filename'], flask.request.args['access_token'][-20:], lock, e))


def _compareWopiLocks(lock1, lock2):
  '''Compares two locks and returns True if they represent the same WOPI lock.
     Officially, the comparison must be based on the locks' string representations, but because of
     a bug in Word Online, currently the internal format of the WOPI locks is looked at, based
     on heuristics. Note that this format is subject to change and is not documented!'''
  if lock1 == lock2:
    Wopi.log.debug('msg="compareLocks" lock1="%s" lock2="%s" result="True"' % (lock1, lock2))
    return True
  # before giving up, attempt to parse the lock as a JSON dictionary
  try:
    l1 = json.loads(lock1)
    try:
      l2 = json.loads(lock2)
      if 'S' in l1 and 'S' in l2:
        Wopi.log.debug('msg="compareLocks" lock1="%s" lock2="%s" result="%r"' % (lock1, lock2, l1['S'] == l2['S']))
        return l1['S'] == l2['S']     # used by Word
      #elif 'L' in lock1 and 'L' in lock2:
      #  Wopi.log.debug('msg="compareLocks" lock1="%s" lock2="%s" result="%r"' % (lock1, lock2, lock1['L'] == lock2['L']))
      #  return lock1['L'] == lock2['L']     # used by Excel and PowerPoint
    except (TypeError, ValueError):
      # lock2 is not a JSON dictionary
      if 'S' in l1:
        Wopi.log.debug('msg="compareLocks" lock1="%s" lock2="%s" result="%r"' % (lock1, lock2, l1['S'] == lock2))
        return l1['S'] == lock2          # also used by Word (BUG!)
  except (TypeError, ValueError):
    # lock1 is not a JSON dictionary: log the lock values and fail the comparison
    Wopi.log.debug('msg="compareLocks" lock1="%s" lock2="%s" result="False"' % (lock1, lock2))
    return False


def _makeConflictResponse(operation, retrievedlock, lock, oldlock, filename):
  '''Generates and logs an HTTP 401 response in case of locks conflict'''
  resp = flask.Response()
  resp.headers['X-WOPI-Lock'] = retrievedlock if retrievedlock else ''
  resp.status_code = http.client.CONFLICT
  Wopi.log.info('msg="%s" filename="%s" token="%s", lock="%s" oldLock="%s" retrievedLock="%s" result="conflict"' % \
                (operation.title(), filename, flask.request.args['access_token'][-20:], lock, oldlock, retrievedlock))
  return resp


def _storeWopiFile(request, acctok, targetname=''):
  '''Saves a file from an HTTP request to the given target filename (defaulting to the access token's one),
     and stores the save time as an xattr. Throws IOError in case of any failure'''
  if not targetname:
    targetname = acctok['filename']
  storage.writefile(acctok['endpoint'], targetname, acctok['ruid'], acctok['rgid'], request.get_data())
  # save the current time for later conflict checking: this is never older than the mtime of the file
  storage.setxattr(acctok['endpoint'], targetname, acctok['ruid'], acctok['rgid'], LASTSAVETIMEKEY, int(time.time()))



#############################################################################################################
#
# The Web Application starts here
#
#############################################################################################################

@Wopi.app.route("/", methods=['GET'])
def index():
  '''Return a default index page with some user-friendly information about this service'''
  Wopi.log.info('msg="Accessed index page" client="%s"' % flask.request.remote_addr)
  return """
    <html><head><title>CERNBox WOPI</title></head>
    <body>
    <div align="center" style="color:#000080; padding-top:50px; font-family:Verdana; size:11">
    This is the CERNBox <a href=http://wopi.readthedocs.io>WOPI</a> server to support online office platforms.<br>
    To use this service, please log in to your CERNBox account and click on your office documents.</div>
    <br><br><br><br><br><br><br><br><br><br><hr>
    <i>CERNBox WOPI Server %s at %s. Powered by Flask %s for Python %s</i>.
    </body>
    </html>
    """ % (WOPISERVERVERSION, socket.getfqdn(), flask.__version__, python_version())


@Wopi.app.route("/wopi/cbox/open", methods=['GET'])
def cboxOpen():
  '''Returns a WOPISrc target and an access token to be passed to Microsoft Office online for
  accessing a given file for a given user. This is the most sensitive call as it provides direct
  access to any user's file, therefore it is protected both by IP and a shared secret. The shared
  secret protection is disabled when running in plain http mode for testing purposes.'''
  Wopi.refreshconfig()
  req = flask.request
  # if running in https mode, first check if the shared secret matches ours
  if Wopi.useHttps and ('Authorization' not in req.headers or req.headers['Authorization'] != 'Bearer ' + Wopi.ocsecret):
    Wopi.log.warning('msg="cboxOpen: unauthorized access attempt, missing authorization token" client="%s"' % req.remote_addr)
    return 'Client not authorized', http.client.UNAUTHORIZED
  # now validate the user identity and deny root access
  try:
    ruid = int(req.args['ruid'])
    rgid = int(req.args['rgid'])
    if ruid == 0 or rgid == 0:
      raise ValueError
  except ValueError:
    Wopi.log.warning('msg="cboxOpen: invalid user/group in request" client="%s" user="%s:%s"' % \
                  (req.remote_addr, req.args['ruid'], req.args['rgid']))
    return 'Client not authorized', http.client.UNAUTHORIZED
  # then resolve the client: only our OwnCloud servers shall use this API
  allowedclients = Wopi.config.get('general', 'allowedclients').split()
  for c in allowedclients:
    try:
      for ip in socket.getaddrinfo(c, None):
        if ip[4][0] == req.remote_addr:
          # we got a match, generate the access token
          filename = urllib.parse.unquote(req.args['filename'])
          canedit = 'canedit' in req.args and req.args['canedit'].lower() == 'true'
          username = req.args['username'] if 'username' in req.args else ''
          folderurl = urllib.parse.unquote(req.args['folderurl'])
          endpoint = req.args['endpoint'] if 'endpoint' in req.args else 'default'
          # XXX workaround for new files that cannot be opened in collaborative edit mode until they're closed for the first time
          if canedit and filename in Wopi.openfiles and Wopi.openfiles[filename][0] == '0':
            Wopi.log.warning('msg="cboxOpen: forcing read-only mode on collaborative editing of a new file" client="%s" user="%d:%d"' % \
                             (req.remote_addr, ruid, rgid))
            canedit = False
          try:
            Wopi.log.info('msg="cboxOpen: access granted, generating token" client="%s" user="%d:%d" friendlyname="%s" canedit="%s" endpoint="%s"' % \
                          (req.remote_addr, ruid, rgid, username, canedit, endpoint))
            inode, acctok = _generateAccessToken(str(ruid), str(rgid), filename, canedit, username, folderurl, endpoint)
            # return an URL-encoded WOPISrc URL for the Office Online server
            return '%s&access_token=%s' % (_generateWopiSrc(inode), acctok)      # no need to URL-encode the JWT token
          except IOError:
            return 'Remote error or file not found', http.client.NOT_FOUND
    except socket.gaierror:
      Wopi.log.warning('msg="cboxOpen: %s found in configured allowed clients but unknown by DNS resolution, ignoring"' % c)
  # no match found, fail
  Wopi.log.warning('msg="cboxOpen: unauthorized access attempt, client IP not whitelisted" client="%s"' % req.remote_addr)
  return 'Client not authorized', http.client.UNAUTHORIZED


@Wopi.app.route("/wopi/cbox/download", methods=['GET'])
def cboxDownload():
  '''Returns the file's content for a given valid access token. Used as a download URL,
     so that the file's path is never explicitly visible.'''
  try:
    acctok = jwt.decode(flask.request.args['access_token'], Wopi.wopisecret, algorithms=['HS256'])
    if acctok['exp'] < time.time():
      raise jwt.exceptions.ExpiredSignatureError
    resp = flask.Response(storage.readfile(acctok['endpoint'], acctok['filename'], acctok['ruid'], acctok['rgid']), \
                          mimetype='application/octet-stream')
    resp.headers['Content-Disposition'] = 'attachment; filename="%s"' % os.path.basename(acctok['filename'])
    resp.status_code = http.client.OK
    Wopi.log.info('msg="cboxDownload: direct download succeeded" filename="%s" user="%s:%s" token="%s"' % \
                  (acctok['filename'], acctok['ruid'], acctok['rgid'], flask.request.args['access_token'][-20:]))
    return resp
  except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError) as e:
    Wopi.log.warning('msg="Signature verification failed" client="%s" requestedUrl="%s" token="%s"' % \
                     (flask.request.remote_addr, flask.request.base_url, flask.request.args['access_token']))
    return 'Invalid access token', http.client.NOT_FOUND
  except IOError as e:
    Wopi.log.info('msg="Requested file not found" filename="%s" token="%s" error="%s"' % \
                  (acctok['filename'], flask.request.args['access_token'][-20:], e))
    return 'File not found', http.client.NOT_FOUND
  except KeyError as e:
    Wopi.log.error('msg="Invalid access token or request argument" error="%s"' % e)
    return 'Invalid access token', http.client.UNAUTHORIZED
  except Exception as e:
    return _logGeneralExceptionAndReturn(e, flask.request)


@Wopi.app.route("/wopi/cbox/endpoints", methods=['GET'])
def cboxEndPoints():
  '''Returns the office apps end-points registered with this WOPI server. This is used by the OwnCloud
  client to discover which Apps frontends can be used with this WOPI server.
  Note that if the end-points are relocated and the corresponding configuration entry updated,
  the WOPI server must be restarted.'''
  Wopi.log.info('msg="cboxEndPoints: returning all registered office apps end-points" client="%s" mimetypesCount="%d"' % \
                (flask.request.remote_addr, len(Wopi.ENDPOINTS)))
  return flask.Response(json.dumps(Wopi.ENDPOINTS), mimetype='application/json')


@Wopi.app.route("/wopi/cbox/open/list", methods=['GET'])
def cboxGetOpenFiles():
  '''Returns a list of all currently opened files, for operations purposes only.
  This call is protected by the same shared secret as the /wopi/cbox/open call.'''
  req = flask.request
  # first check if the shared secret matches ours
  if 'Authorization' not in req.headers or req.headers['Authorization'] != 'Bearer ' + Wopi.ocsecret:
    Wopi.log.warning('msg="cboxGetOpenFiles: unauthorized access attempt, missing authorization token" client="%s"' % req.remote_addr)
    return 'Client not authorized', http.client.UNAUTHORIZED
  # first convert the sets into lists, otherwise sets cannot be serialized in JSON format
  jl = {}
  for f in list(Wopi.openfiles.keys()):
    jl[f] = (Wopi.openfiles[f][0], tuple(Wopi.openfiles[f][1]))
  # dump the current list of opened files in JSON format
  Wopi.log.info('msg="cboxGetOpenFiles: returning list of open files" client="%s"' % req.remote_addr)
  return flask.Response(json.dumps(jl), mimetype='application/json')


#
# The WOPI protocol implementation starts here
#
@Wopi.app.route("/wopi/files/<fileid>", methods=['GET'])
def wopiCheckFileInfo(fileid):
  '''Implements the CheckFileInfo WOPI call'''
  # cf. http://wopi.readthedocs.io/projects/wopirest/en/latest/files/CheckFileInfo.html
  Wopi.refreshconfig()
  try:
    acctok = jwt.decode(flask.request.args['access_token'], Wopi.wopisecret, algorithms=['HS256'])
    if acctok['exp'] < time.time():
      raise jwt.exceptions.ExpiredSignatureError
    Wopi.log.info('msg="CheckFileInfo" user="%s:%s" filename="%s" fileid="%s" token="%s"' % \
                  (acctok['ruid'], acctok['rgid'], acctok['filename'], fileid, flask.request.args['access_token'][-20:]))
    statInfo = storage.statx(acctok['endpoint'], acctok['filename'], acctok['ruid'], acctok['rgid'])
    # compute some entities for the response
    wopiSrc = 'WOPISrc=%s&access_token=%s' % (_generateWopiSrc(fileid), flask.request.args['access_token'])
    fExt = os.path.splitext(acctok['filename'])[1]
    # populate metadata for this file
    filemd = {}
    filemd['BaseFileName'] = filemd['BreadcrumbDocName'] = os.path.basename(acctok['filename'])
    furl = acctok['folderurl']
    # encode the path part as it is going to be an URL GET argument
    filemd['BreadcrumbFolderUrl'] = furl[:furl.find('=')+1] + urllib.parse.quote_plus(furl[furl.find('=')+1:])
    if acctok['username'] == '':
      filemd['UserFriendlyName'] = 'Anonymous Guest'
      if '?path' in furl and furl[-2:] != '=/':
        # this is a subfolder of a public share, show it
        filemd['BreadcrumbFolderName'] = 'Back to ' + furl[furl.find('?path'):].split('/')[-1]
      else:
        # this is the top level public share, which is anonymous
        filemd['BreadcrumbFolderName'] = 'Back to the CERNBox share'
    else:
      filemd['UserFriendlyName'] = acctok['username']
      filemd['BreadcrumbFolderName'] = 'Back to ' + acctok['filename'].split('/')[-2]
    filemd['DownloadUrl'] = '%s?access_token=%s' % \
                            (Wopi.config.get('general', 'downloadurl'), flask.request.args['access_token'])
    filemd['HostViewUrl'] = '%s&%s' % (Wopi.ENDPOINTS[fExt]['view'], wopiSrc)
    filemd['HostEditUrl'] = '%s&%s' % (Wopi.ENDPOINTS[fExt]['edit'], wopiSrc)
    # the following is to enable the 'Edit in Word/Excel/PowerPoint' (desktop) action
    try:
      # a path 'a-la owncloud' includes '/files/', which has to be stripped off.
      # XXX This is temporary code for the AARNet config. Note this is not robust as a user path including '/files/' will be broken.
      filemd['ClientUrl'] = Wopi.config.get('general', 'webdavurl') + '/' + \
                            (acctok['filename'].split("/files/", 1)[1] if '/files/' in acctok['filename'] else acctok['filename'])
    except configparser.NoOptionError:
      # if no WebDAV URL is provided, ignore this setting
      pass
    filemd['OwnerId'] = statInfo['ouid'] + ':' + statInfo['ogid']
    filemd['UserId'] = acctok['ruid'] + ':' + acctok['rgid']    # typically same as OwnerId
    filemd['Size'] = statInfo['size']
    filemd['Version'] = statInfo['mtime']   # mtime is used as version here
    filemd['SupportsUpdate'] = filemd['UserCanWrite'] = filemd['SupportsLocks'] = \
        filemd['SupportsGetLock'] = filemd['SupportsDeleteFile'] = acctok['canedit']
        #filemd['SupportsRename'] = filemd['UserCanRename'] = acctok['canedit']      # XXX broken in Office Online
    filemd['SupportsExtendedLockLength'] = True
    filemd['EnableOwnerTermination'] = True     # extension for Collabora Online
    #filemd['UserCanPresent'] = True   # what about the broadcasting feature in Office Online?
    Wopi.log.info('msg="File metadata response" token="%s" metadata="%s"' % (flask.request.args['access_token'][-20:], filemd))
    # send in JSON format
    return flask.Response(json.dumps(filemd), mimetype='application/json')
  except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError) as e:
    Wopi.log.warning('msg="Signature verification failed" client="%s" requestedUrl="%s" token="%s"' % \
                     (flask.request.remote_addr, flask.request.base_url, flask.request.args['access_token']))
    return 'Invalid access token', http.client.NOT_FOUND
  except IOError as e:
    Wopi.log.info('msg="Requested file not found" filename="%s" token="%s" error="%s"' % \
                  (acctok['filename'], flask.request.args['access_token'][-20:], e))
    return 'File not found', http.client.NOT_FOUND
  except KeyError as e:
    Wopi.log.error('msg="Invalid access token or request argument" error="%s"' % e)
    return 'Invalid access token', http.client.UNAUTHORIZED
  except Exception as e:
    return _logGeneralExceptionAndReturn(e, flask.request)


@Wopi.app.route("/wopi/files/<fileid>/contents", methods=['GET'])
def wopiGetFile(fileid):
  '''Implements the GetFile WOPI call'''
  Wopi.refreshconfig()
  try:
    acctok = jwt.decode(flask.request.args['access_token'], Wopi.wopisecret, algorithms=['HS256'])
    if acctok['exp'] < time.time():
      raise jwt.exceptions.ExpiredSignatureError
    Wopi.log.info('msg="GetFile" user="%s:%s" filename="%s" fileid="%s" token="%s"' % \
                  (acctok['ruid'], acctok['rgid'], acctok['filename'], fileid, flask.request.args['access_token'][-20:]))
    # stream file from storage to client
    resp = flask.Response(storage.readfile(acctok['endpoint'], acctok['filename'], acctok['ruid'], acctok['rgid']), \
                          mimetype='application/octet-stream')
    resp.status_code = http.client.OK
    return resp
  except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError) as e:
    Wopi.log.warning('msg="Signature verification failed" client="%s" requestedUrl="%s" token="%s"' % \
                     (flask.request.remote_addr, flask.request.base_url, flask.request.args['access_token']))
    return 'Invalid access token', http.client.UNAUTHORIZED
  except Exception as e:
    return _logGeneralExceptionAndReturn(e, flask.request)


#
# The following operations are all called on POST /wopi/files/<fileid>
#
def wopiLock(fileid, reqheaders, acctok):
  '''Implements the Lock, RefreshLock, and UnlockAndRelock WOPI calls'''
  # cf. http://wopi.readthedocs.io/projects/wopirest/en/latest/files/Lock.html
  op = reqheaders['X-WOPI-Override']
  lock = reqheaders['X-WOPI-Lock']
  oldLock = reqheaders['X-WOPI-OldLock'] if 'X-WOPI-OldLock' in reqheaders else None
  retrievedLock = _retrieveWopiLock(fileid, op, lock, acctok)
  # perform the required checks for the validity of the new lock
  if (oldLock is None and retrievedLock != None and not _compareWopiLocks(retrievedLock, lock)) or \
     (oldLock != None and not _compareWopiLocks(retrievedLock, oldLock)):
    # XXX we got a locking conflict: as we've seen cases of looping clients attempting to restate the same
    # XXX lock over and over again, we keep track of this request and we forcefully clean up the lock
    # XXX once 'too many' requests come for the same lock
    if retrievedLock not in Wopi.repeatedLockRequests:
      Wopi.repeatedLockRequests[retrievedLock] = 1
    else:
      Wopi.repeatedLockRequests[retrievedLock] += 1
      if Wopi.repeatedLockRequests[retrievedLock] == 5:
        try:
          storage.removefile(acctok['endpoint'], _getLockName(acctok['filename']), Wopi.lockruid, Wopi.lockrgid, 1)
        except IOError:
          pass
        Wopi.log.warning('msg="Lock: BLINDLY removed the existing lock to unblock client" user="%s:%s" filename="%s" token="%s"' % \
                         (acctok['ruid'], acctok['rgid'], acctok['filename'], flask.request.args['access_token'][-20:]))
    return _makeConflictResponse(op, retrievedLock, lock, oldLock, acctok['filename'])
  # LOCK or REFRESH_LOCK: set the lock to the given one, including the expiration time
  _storeWopiLock(op, lock, acctok)
  if not retrievedLock:
    # on first lock, set an xattr with the current time for later conflicts checking
    try:
      storage.setxattr(acctok['endpoint'], acctok['filename'], acctok['ruid'], acctok['rgid'], LASTSAVETIMEKEY, int(time.time()))
    except IOError as e:
      # not fatal, but will generate a conflict file later on, so log a warning
      Wopi.log.warning('msg="Unable to set lastwritetime xattr" user="%s:%s" filename="%s" token="%s" reason="%s"' % \
                       (acctok['ruid'], acctok['rgid'], acctok['filename'], flask.request.args['access_token'][-20:], e))
    # also, keep track of files that have been opened for write: this is for statistical purposes only
    # (cf. the GetLock WOPI call and the /wopi/cbox/open/list action)
    if acctok['filename'] not in Wopi.openfiles:
      Wopi.openfiles[acctok['filename']] = (time.asctime(), set([acctok['username']]))
    else:
      # the file was already opened but without lock: this happens on new files (cf. editnew action), just log
      Wopi.log.info('msg="First lock for new file" user="%s:%s" filename="%s" token="%s"' % \
                    (acctok['ruid'], acctok['rgid'], acctok['filename'], flask.request.args['access_token'][-20:]))
  return 'OK', http.client.OK


def wopiUnlock(fileid, reqheaders, acctok):
  '''Implements the Unlock WOPI call'''
  lock = reqheaders['X-WOPI-Lock']
  retrievedLock = _retrieveWopiLock(fileid, 'UNLOCK', lock, acctok)
  if not _compareWopiLocks(retrievedLock, lock):
    return _makeConflictResponse('UNLOCK', retrievedLock, lock, '', acctok['filename'])
  # OK, the lock matches. Remove any extended attribute related to locks and conflicts handling
  try:
    storage.removefile(acctok['endpoint'], _getLockName(acctok['filename']), Wopi.lockruid, Wopi.lockrgid, 1)
  except IOError:
    # ignore, it's not worth to report anything here
    pass
  try:
    storage.rmxattr(acctok['endpoint'], acctok['filename'], acctok['ruid'], acctok['rgid'], LASTSAVETIMEKEY)
  except IOError:
    # same as above
    pass
  # and update our internal list of opened files
  try:
    del Wopi.openfiles[acctok['filename']]
  except KeyError:
    # already removed?
    pass
  return 'OK', http.client.OK


def wopiGetLock(fileid, reqheaders_unused, acctok):
  '''Implements the GetLock WOPI call'''
  resp = flask.Response()
  # throws exception if no lock
  resp.headers['X-WOPI-Lock'] = _retrieveWopiLock(fileid, 'GETLOCK', '', acctok)
  resp.status_code = http.client.OK
  # for statistical purposes, check whether a lock exists and update internal bookkeeping
  if resp.headers['X-WOPI-Lock']:
    try:
      # the file was already opened for write, check whether this is a new user
      if not acctok['username'] in Wopi.openfiles[acctok['filename']][1]:
        # yes it's a new user
        Wopi.openfiles[acctok['filename']][1].add(acctok['username'])
        if len(Wopi.openfiles[acctok['filename']][1]) > 1:
          # for later monitoring, explicitly log that this file is being edited by at least two users
          Wopi.log.info('msg="Collaborative editing detected" filename="%s" token="%s" users="%s"' % \
                         (acctok['filename'], flask.request.args['access_token'][-20:], list(Wopi.openfiles[acctok['filename']][1])))
    except KeyError:
      # existing lock but missing Wopi.openfiles[acctok['filename']] ?
      Wopi.log.warning('msg="Repopulating missing metadata" filename="%s" token="%s" user="%s"' % \
                       (acctok['filename'], flask.request.args['access_token'][-20:], acctok['username']))
      Wopi.openfiles[acctok['filename']] = (time.asctime(), set([acctok['username']]))
  return resp


def wopiPutRelative(fileid, reqheaders, acctok):
  '''Implements the PutRelative WOPI call. Corresponds to the 'Save as...' menu entry.'''
  # cf. http://wopi.readthedocs.io/projects/wopirest/en/latest/files/PutRelativeFile.html
  suggTarget = reqheaders['X-WOPI-SuggestedTarget'] if 'X-WOPI-SuggestedTarget' in reqheaders else ''
  relTarget = reqheaders['X-WOPI-RelativeTarget'] if 'X-WOPI-RelativeTarget' in reqheaders else ''
  overwriteTarget = 'X-WOPI-OverwriteRelativeTarget' in reqheaders and bool(reqheaders['X-WOPI-OverwriteRelativeTarget'])
  Wopi.log.info('msg="PutRelative" user="%s:%s" filename="%s" fileid="%s" suggTarget="%s" relTarget="%s" overwrite="%r" token="%s"' % \
                (acctok['ruid'], acctok['rgid'], acctok['filename'], fileid, \
                 suggTarget, relTarget, overwriteTarget, flask.request.args['access_token'][-20:]))
  # either one xor the other must be present
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
        storage.stat(acctok['endpoint'], targetName, acctok['ruid'], acctok['rgid'])
        # the file exists: try a different name
        name, ext = os.path.splitext(targetName)
        targetName = name + '_copy' + ext
      except IOError as e:
        if 'No such file or directory' in str(e):
          # OK, the targetName is good to go
          break
        else:
          Wopi.log.info('msg="PutRelative" user="%s:%s" filename="%s" token="%s" suggTarget="%s" error="%s"' % \
                        (acctok['ruid'], acctok['rgid'], targetName, flask.request.args['access_token'][-20:], suggTarget, str(e)))
          return 'Illegal filename %s: %s' % (targetName, e), http.client.BAD_REQUEST
  else:
    # the relative target is a filename to be respected, and that may overwrite an existing file
    relTarget = os.path.dirname(acctok['filename']) + os.path.sep + relTarget    # make full path
    try:
      # check for file existence + lock
      fileExists = retrievedLock = False
      fileExists = storage.stat(acctok['endpoint'], relTarget, acctok['ruid'], acctok['rgid'])
      retrievedLock = storage.stat(acctok['endpoint'], _getLockName(relTarget), Wopi.lockruid, Wopi.lockrgid)
    except IOError:
      pass
    if fileExists and (not overwriteTarget or retrievedLock):
      return _makeConflictResponse('PUTRELATIVE', retrievedLock, '', '', relTarget)
    # else we can use the relative target
    targetName = relTarget
  # either way, we now have a targetName to save the file: attempt to do so
  try:
    _storeWopiFile(flask.request, acctok, targetName)
  except IOError as e:
    Wopi.log.info('msg="Error writing file" filename="%s" token="%s" error="%s"' % \
                  (targetName, flask.request.args['access_token'][-20:], e))
    return 'I/O Error', http.client.INTERNAL_SERVER_ERROR
  # generate an access token for the new file
  Wopi.log.info('msg="PutRelative: generating new access token" user="%s:%s" filename="%s" canedit="True" friendlyname="%s"' % \
           (acctok['ruid'], acctok['rgid'], targetName, acctok['username']))
  inode, newacctok = _generateAccessToken(acctok['ruid'], acctok['rgid'], targetName, True, acctok['username'], \
                                          acctok['folderurl'], acctok['endpoint'])
  # prepare and send the response as JSON
  putrelmd = {}
  putrelmd['Name'] = os.path.basename(targetName)
  putrelmd['Url'] = '%s?access_token=%s' % (_generateWopiSrc(inode), newacctok)
  putrelmd['HostEditUrl'] = '%s&WOPISrc=%s&access_token=%s' % \
                            (Wopi.ENDPOINTS[os.path.splitext(targetName)[1]]['edit'], \
                             _generateWopiSrc(inode), newacctok)
  Wopi.log.debug('msg="PutRelative response" token="%s" metadata="%s"' % (newacctok[-20:], putrelmd))
  return flask.Response(json.dumps(putrelmd), mimetype='application/json')


def wopiDeleteFile(fileid, reqheaders_unused, acctok):
  '''Implements the DeleteFile WOPI call'''
  retrievedLock = _retrieveWopiLock(fileid, 'DELETE', '', acctok)
  if retrievedLock != None:
    # file is locked and cannot be deleted
    return _makeConflictResponse('DELETE', retrievedLock, '', '', acctok['filename'])
  try:
    storage.removefile(acctok['endpoint'], acctok['filename'], acctok['ruid'], acctok['rgid'])
    return 'OK', http.client.OK
  except IOError as e:
    Wopi.log.info('msg="DeleteFile" token="%s" error="%s"' % (flask.request.args['access_token'][-20:], e))
    return 'Internal error', http.client.INTERNAL_SERVER_ERROR


def wopiRenameFile(fileid, reqheaders, acctok):
  '''Implements the RenameFile WOPI call.'''
  targetName = reqheaders['X-WOPI-RequestedName']
  lock = reqheaders['X-WOPI-Lock']
  retrievedLock = _retrieveWopiLock(fileid, 'RENAMEFILE', lock, acctok)
  if retrievedLock != None and not _compareWopiLocks(retrievedLock, lock):
    return _makeConflictResponse('RENAMEFILE', retrievedLock, lock, '', acctok['filename'])
  try:
    # the destination name comes without base path and without extension
    targetName = os.path.dirname(acctok['filename']) + '/' + targetName + os.path.splitext(acctok['filename'])[1]
    Wopi.log.info('msg="RenameFile" user="%s:%s" filename="%s" token="%s" targetname="%s"' % \
                  (acctok['ruid'], acctok['rgid'], acctok['filename'], flask.request.args['access_token'][-20:], targetName))
    storage.renamefile(acctok['endpoint'], acctok['filename'], targetName, acctok['ruid'], acctok['rgid'])
    storage.renamefile(acctok['endpoint'], _getLockName(acctok['filename']), _getLockName(targetName), Wopi.lockruid, Wopi.lockrgid)
    # prepare and send the response as JSON
    renamemd = {}
    renamemd['Name'] = reqheaders['X-WOPI-RequestedName']
    return flask.Response(json.dumps(renamemd), mimetype='application/json')
  except IOError as e:
    # assume the rename failed because of the destination filename and report the error
    Wopi.log.info('msg="RenameFile" token="%s" error="%s"' % (flask.request.args['access_token'][-20:], e))
    resp = flask.Response()
    resp.headers['X-WOPI-InvalidFileNameError'] = 'Failed to rename: %s' % e
    resp.status_code = http.client.BAD_REQUEST
    return resp


def wopiCreateNewFile(fileid, acctok):
  '''Implements the editnew action as part of the PutFile WOPI call.'''
  Wopi.log.info('msg="PutFile" user="%s:%s" filename="%s" fileid="%s" action="editnew" token="%s"' % \
                (acctok['ruid'], acctok['rgid'], acctok['filename'], fileid, flask.request.args['access_token'][-20:]))
  try:
    # try to stat the file and raise IOError if not there
    if storage.stat(acctok['endpoint'], acctok['filename'], acctok['ruid'], acctok['rgid'])['size'] == 0:
      # a 0-size file is equivalent to not existing
      raise IOError
    Wopi.log.warning('msg="PutFile" error="File exists but no WOPI lock provided" filename="%s" token="%s"' %
                     (acctok['filename'], flask.request.args['access_token']))
    return 'File exists', http.client.CONFLICT
  except IOError:
    # indeed the file did not exist, so we write it for the first time
    _storeWopiFile(flask.request, acctok)
    Wopi.log.info('msg="File successfully written" action="editnew" user="%s:%s" filename="%s" token="%s"' % \
                  (acctok['ruid'], acctok['rgid'], acctok['filename'], flask.request.args['access_token']))
    # and we keep track of it as an open file with timestamp = Epoch, despite not having any lock yet.
    # XXX this is to work around an issue with concurrent editing of newly created files (cf. cboxOpen)
    Wopi.openfiles[acctok['filename']] = ('0', set([acctok['username']]))
    return 'OK', http.client.OK


@Wopi.app.route("/wopi/files/<fileid>", methods=['POST'])
def wopiFilesPost(fileid):
  '''A dispatcher metod for all POST operations on files'''
  Wopi.refreshconfig()
  try:
    acctok = jwt.decode(flask.request.args['access_token'], Wopi.wopisecret, algorithms=['HS256'])
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
    elif op == 'DELETE':
      return wopiDeleteFile(fileid, headers, acctok)
    elif op == 'RENAME_FILE':
      return wopiRenameFile(fileid, headers, acctok)
    #elif op == 'PUT_USER_INFO':   https://wopirest.readthedocs.io/en/latest/files/PutUserInfo.html
    else:
      Wopi.log.warning('msg="Unknown/unsupported operation" operation="%s"' % op)
      return 'Not supported operation found in header', http.client.NOT_IMPLEMENTED
  except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError) as e:
    Wopi.log.warning('msg="Signature verification failed" client="%s" requestedUrl="%s" token="%s"' % \
                     (flask.request.remote_addr, flask.request.base_url, flask.request.args['access_token']))
    return 'Invalid access token', http.client.NOT_FOUND
  except Exception as e:
    return _logGeneralExceptionAndReturn(e, flask.request)


@Wopi.app.route("/wopi/files/<fileid>/contents", methods=['POST'])
def wopiPutFile(fileid):
  '''Implements the PutFile WOPI call'''
  Wopi.refreshconfig()
  try:
    acctok = jwt.decode(flask.request.args['access_token'], Wopi.wopisecret, algorithms=['HS256'])
    if acctok['exp'] < time.time():
      raise jwt.exceptions.ExpiredSignatureError
    if 'X-WOPI-Lock' not in flask.request.headers:
      # no lock given: assume we are in creation mode (cf. editnew WOPI action)
      return wopiCreateNewFile(fileid, acctok)
    # otherwise, check that the caller holds the current lock on the file
    lock = flask.request.headers['X-WOPI-Lock']
    retrievedLock = _retrieveWopiLock(fileid, 'PUTFILE', lock, acctok)
    if retrievedLock != None and not _compareWopiLocks(retrievedLock, lock):
      return _makeConflictResponse('PUTFILE', retrievedLock, lock, '', acctok['filename'])
    # OK, we can save the file now
    Wopi.log.info('msg="PutFile" user="%s:%s" filename="%s" fileid="%s" action="edit" token="%s"' % \
                  (acctok['ruid'], acctok['rgid'], acctok['filename'], fileid, flask.request.args['access_token'][-20:]))
    try:
      # check now the destination file against conflicts
      savetime = int(storage.getxattr(acctok['endpoint'], acctok['filename'], acctok['ruid'], acctok['rgid'], LASTSAVETIMEKEY))
      # we got our xattr: if mtime is greater, someone may have updated the file from a different source (e.g. FUSE or SMB mount)
      mtime = storage.stat(acctok['endpoint'], acctok['filename'], acctok['ruid'], acctok['rgid'])['mtime']
      if int(mtime) > int(savetime):
        # this is the case, force conflict. Note we can't force a resolution greater than one second!
        Wopi.log.info('msg="Forcing conflict based on lastWopiSaveTime" user="%s:%s" filename="%s" token="%s" savetime="%ld" lastmtime="%ld"' % \
                      (acctok['ruid'], acctok['rgid'], acctok['filename'], flask.request.args['access_token'][-20:], savetime, mtime))
        raise IOError
      Wopi.log.info('msg="Got lastWopiSaveTime" user="%s:%s" filename="%s" token="%s" savetime="%ld" lastmtime="%ld"' % \
                    (acctok['ruid'], acctok['rgid'], acctok['filename'], flask.request.args['access_token'][-20:], savetime, mtime))
    except IOError:
      # either the file was deleted or it was updated/overwritten by others: force conflict
      newname, ext = os.path.splitext(acctok['filename'])
      # !!! note the OwnCloud format is '<filename>_conflict-<date>-<time>', but it is not synchronized back !!!
      newname = '%s-conflict-%s%s' % (newname, time.strftime('%Y%m%d-%H%M%S'), ext.strip())
      _storeWopiFile(flask.request, acctok, newname)
      # keep track of this action in the original file's xattr, to avoid looping (see below)
      storage.setxattr(acctok['endpoint'], acctok['filename'], acctok['ruid'], acctok['rgid'], LASTSAVETIMEKEY, 'conflict')
      Wopi.log.info('msg="Conflicting copy created" user="%s:%s" token="%s" newFilename="%s"' % \
                    (acctok['ruid'], acctok['rgid'], flask.request.args['access_token'], newname))
      # and report failure to Office Online: it will retry a couple of times and eventually it will notify the user
      return 'Conflicting copy created', http.client.INTERNAL_SERVER_ERROR
    except (ValueError, TypeError) as e:
      # the xattr was not an integer: assume Office Online is looping on an already conflicting file,
      # therefore do nothing and keep reporting internal error. Of course if the attribute was modified by hand,
      # this mechanism fails.
      Wopi.log.info('msg="Conflicting copy already created" user="%s:%s" token="%s" filename="%s"' % \
                    (acctok['ruid'], acctok['rgid'], flask.request.args['access_token'], acctok['filename']))
      return 'Conflicting copy already created', http.client.INTERNAL_SERVER_ERROR
    # Go for overwriting the file. Note that the entire check+write operation should be atomic,
    # but the previous check still gives the opportunity of a race condition. We just live with it
    # as OwnCloud does not seem to provide anything better...
    # Anyhow, previous versions are all stored and recoverable by the user.
    _storeWopiFile(flask.request, acctok)
    Wopi.log.info('msg="File successfully written" action="edit" user="%s:%s" filename="%s" token="%s"' % \
                  (acctok['ruid'], acctok['rgid'], acctok['filename'], flask.request.args['access_token'][-20:]))
    return 'OK', http.client.OK
  except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError) as e:
    Wopi.log.warning('msg="Signature verification failed" client="%s" requestedUrl="%s" token="%s"' % \
                     (flask.request.remote_addr, flask.request.base_url, flask.request.args['access_token']))
    return 'Invalid access token', http.client.NOT_FOUND
  except IOError as e:
    Wopi.log.info('msg="Error writing file" filename="%s" token="%s" error="%s"' % \
                  (acctok['filename'], flask.request.args['access_token'], e))
    return 'I/O Error', http.client.INTERNAL_SERVER_ERROR
  except Exception as e:
    return _logGeneralExceptionAndReturn(e, flask.request)


#
# Start the Flask endless listening loop if started in standalone mode
#
if __name__ == '__main__':
  Wopi.init()
  Wopi.initAppsRegistry()
  Wopi.run()
