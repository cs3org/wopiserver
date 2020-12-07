#!/usr/bin/env python3
'''
wopiserver.py

The Web-application Open Platform Interface (WOPI) gateway for the ScienceMesh IOP

Author: Giuseppe Lo Presti (@glpatcern), CERN/IT-ST
Contributions: see README.md
'''

import sys
import os
import time
from datetime import datetime
import socket
import configparser
from platform import python_version
import logging
import logging.handlers
import urllib.request
import urllib.parse
import http.client
import json
import wopiutils as utils
try:
  import flask                   # Flask app server
  from werkzeug.exceptions import NotFound as Flask_NotFound
  from werkzeug.exceptions import MethodNotAllowed as Flask_MethodNotAllowed
  import jwt                     # JSON Web Tokens support
  from prometheus_flask_exporter import PrometheusMetrics    # Prometheus support
except ImportError:
  print("Missing modules, please install Flask and JWT with `pip3 install flask PyJWT pyOpenSSL`")
  raise

# the following constant is replaced on the fly when generating the RPM (cf. spec file)
WOPISERVERVERSION = 'git'

# this is the xattr key used for conflicts resolution on the remote storage
LASTSAVETIMEKEY = 'iop.wopi.lastwritetime'

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
    print("Missing module when attempting to import %s.py. Please make sure dependencies are met." % storagetype)
    raise


class Wopi:
  '''A singleton container for all state information of the WOPI server'''
  app = flask.Flask("WOPIServer")
  metrics = PrometheusMetrics(app, group_by='endpoint')
  port = 0
  lastConfigReadTime = time.time()
  loglevels = {"Critical": logging.CRITICAL,  # 50
               "Error":    logging.ERROR,     # 40
               "Warning":  logging.WARNING,   # 30
               "Info":     logging.INFO,      # 20
               "Debug":    logging.DEBUG      # 10
              }
  log = utils.JsonLogger(app.logger)
  openfiles = {}

  @classmethod
  def init(cls):
    '''Initialises the application, bails out in case of failures. Note this is not a __init__ method'''
    try:
      # configure the logging
      loghandler = logging.FileHandler('/var/log/wopi/wopiserver.log')
      loghandler.setFormatter(logging.Formatter(
          fmt='{"time": "%(asctime)s", "process": "%(name)s", "level": "%(levelname)s", %(message)s}',
          datefmt='%Y-%m-%dT%H:%M:%S'))
      cls.app.logger.handlers = [loghandler]
      # read the configuration
      cls.config = configparser.ConfigParser()
      with open('/etc/wopi/wopiserver.defaults.conf') as fdef:
        cls.config.read_file(fdef)
      cls.config.read('/etc/wopi/wopiserver.conf')
      # load the requested storage layer
      storage_layer_import(cls.config.get('general', 'storagetype'))
      # prepare the Flask web app
      cls.port = int(cls.config.get('general', 'port'))
      cls.log.setLevel(cls.loglevels[cls.config.get('general', 'loglevel')])
      try:
        cls.nonofficetypes = cls.config.get('general', 'nonofficetypes').split()
      except (TypeError, configparser.NoOptionError) as e:
        cls.nonofficetypes = []
      with open(cls.config.get('security', 'wopisecretfile')) as s:
        cls.wopisecret = s.read().strip('\n')
      with open(cls.config.get('security', 'iopsecretfile')) as s:
        cls.iopsecret = s.read().strip('\n')
      cls.tokenvalidity = cls.config.getint('general', 'tokenvalidity')
      storage.init(cls.config, cls.log)                          # initialize the storage layer
      cls.useHttps = cls.config.get('security', 'usehttps').lower() == 'yes'
      cls.repeatedLockRequests = {}               # cf. the wopiLock() function below
      cls.wopiurl = cls.config.get('general', 'wopiurl')
      if cls.config.has_option('general', 'lockpath'):
        cls.lockpath = cls.config.get('general', 'lockpath')
      else:
        cls.lockpath = ''
      _ = cls.config.get('general', 'downloadurl')   # make sure this is defined
      # initialize the utils module
      utils.init(storage, cls)
    except (configparser.NoOptionError, OSError) as e:
      # any error we get here with the configuration is fatal
      cls.log.fatal('msg="Failed to initialize the service, aborting" error="%s"' % e)
      sys.exit(-22)

  @classmethod
  def initappsregistry(cls):
    '''Initializes the CERNBox Office-like Apps Registry'''
    # TODO all this is supposed to be moved to the CERNBox Apps Registry microservice at some stage in the future
    cls.ENDPOINTS = {}

    oos = cls.config.get('general', 'oosurl', fallback=None)
    if oos:
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
      cls.log.info('msg="Microsoft Office Online endpoints successfully configured" OfficeURL="%s"' % cls.ENDPOINTS['.docx']['edit'])

    code = cls.config.get('general', 'codeurl', fallback=None)
    if code:
      try:
        import requests
        from xml.etree import ElementTree as ET
        discData = requests.get(url=(code + '/hosting/discovery'), verify=False).content
        discXml = ET.fromstring(discData)
        # extract urlsrc from first <app> node inside <net-zone>
        urlsrc = discXml.find('net-zone/app')[0].attrib['urlsrc']

        # The supported Collabora end-points
        cls.ENDPOINTS['.odt'] = {}
        cls.ENDPOINTS['.odt']['view'] = urlsrc + 'permission=readonly'
        cls.ENDPOINTS['.odt']['edit'] = urlsrc + 'permission=edit'
        cls.ENDPOINTS['.odt']['new']  = urlsrc + 'permission=edit'        # pylint: disable=bad-whitespace
        cls.ENDPOINTS['.ods'] = {}
        cls.ENDPOINTS['.ods']['view'] = urlsrc + 'permission=readonly'
        cls.ENDPOINTS['.ods']['edit'] = urlsrc + 'permission=edit'
        cls.ENDPOINTS['.ods']['new']  = urlsrc + 'permission=edit'        # pylint: disable=bad-whitespace
        cls.ENDPOINTS['.odp'] = {}
        cls.ENDPOINTS['.odp']['view'] = urlsrc + 'permission=readonly'
        cls.ENDPOINTS['.odp']['edit'] = urlsrc + 'permission=edit'
        cls.ENDPOINTS['.odp']['new']  = urlsrc + 'permission=edit'        # pylint: disable=bad-whitespace
        cls.log.info('msg="Collabora Online endpoints successfully configured" CODEURL="%s"' % cls.ENDPOINTS['.odt']['edit'])

      except (IOError, ET.ParseError) as e:
        cls.log.warning('msg="Failed to initialize Collabora Online endpoints" error="%s"' % e)

    # The WOPI Bridge end-point
    bridge = cls.config.get('general', 'wopibridgeurl', fallback=None)
    if not bridge:
      # fallback to the same WOPI url but on default port 8000
      bridge = urllib.parse.urlsplit(cls.wopiurl)
      bridge = '%s://%s:8000/wopib' % (bridge.scheme, bridge.netloc[:bridge.netloc.find(':')+1])
    # The bridge only supports CodiMD for now, therefore this is hardcoded:
    # once we move to the Apps Registry microservice, we can make it dynamic
    cls.ENDPOINTS['.md'] = {}
    cls.ENDPOINTS['.md']['view'] = cls.ENDPOINTS['.md']['edit'] = bridge + '/open'
    cls.ENDPOINTS['.zmd'] = {}
    cls.ENDPOINTS['.zmd']['view'] = cls.ENDPOINTS['.zmd']['edit'] = bridge + '/open'
    cls.ENDPOINTS['.txt'] = {}
    cls.ENDPOINTS['.txt']['view'] = cls.ENDPOINTS['.txt']['edit'] = bridge + '/open'
    cls.log.info('msg="WOPI Bridge endpoints successfully configured" BridgeURL="%s"' % bridge)


  @classmethod
  def refreshconfig(cls):
    '''Re-read the configuration file every 300 secs to catch any runtime parameter change'''
    if time.time() > cls.lastConfigReadTime + 300:
      cls.lastConfigReadTime = time.time()
      cls.config.read('/etc/wopi/wopiserver.conf')
      # refresh some general parameters
      cls.tokenvalidity = cls.config.getint('general', 'tokenvalidity')
      cls.log.setLevel(cls.loglevels[cls.config.get('general', 'loglevel')])


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
# The Flask web application starts here
#
@Wopi.app.errorhandler(Exception)
def handleException(ex):
  '''Generic method to log any uncaught exception'''
  if isinstance(ex, Flask_NotFound) or isinstance(ex, Flask_MethodNotAllowed):
    return ex
  return utils.logGeneralExceptionAndReturn(ex, flask.request)


@Wopi.app.route("/", methods=['GET'])
def redir():
  '''A simple redirect to the page below'''
  return flask.redirect("/wopi")

@Wopi.app.route("/wopi", methods=['GET'])
def index():
  '''Return a default index page with some user-friendly information about this service'''
  Wopi.log.debug('msg="Accessed index page" client="%s"' % flask.request.remote_addr)
  return """
    <html><head><title>ScienceMesh WOPI Server</title></head>
    <body>
    <div align="center" style="color:#000080; padding-top:50px; font-family:Verdana; size:11">
    This is the ScienceMesh IOP <a href=http://wopi.readthedocs.io>WOPI</a> server to support online office-like editors.<br>
    To use this service, please log in to your EFSS Storage and click on a supported document.</div>
    <div style="position: absolute; bottom: 10px; left: 10px; width: 99%%;"><hr>
    <i>ScienceMesh WOPI Server %s at %s. Powered by Flask %s for Python %s</i>.
    </body>
    </html>
    """ % (WOPISERVERVERSION, socket.getfqdn(), flask.__version__, python_version())


@Wopi.app.route("/wopi/iop/open", methods=['GET'])
@Wopi.metrics.do_not_track()
@Wopi.metrics.counter('open_by_ext', 'Number of /open calls by file extension',
  labels={'open_type': lambda:
    flask.request.args['filename'].split('.')[-1] \
    if 'filename' in flask.request.args and '.' in flask.request.args['filename'] \
    else ('noext' if 'filename' in flask.request.args else 'fileid')
    })
def iopOpen():
  '''Generates a WOPISrc target and an access token to be passed to a WOPI-compatible Office-like app
  for accessing a given file for a given user.
  Required headers:
  - Authorization: a bearer shared secret to protect this call as it provides direct access to any user's file
  - TokenHeader: an x-access-token to serve as user identity towards Reva
    - OR int ruid, rgid as query parameters: a real Unix user identity (id:group); this is for legacy compatibility
  Request arguments:
  - enum viewmode: how the user should access the file, according to utils.ViewMode/the CS3 app provider API
    - OR bool canedit: True if full access should be given to the user, otherwise read-only access is granted
  - string username (optional): user's full display name, typically shown by the Office app
  - string filename OR fileid: the full path of the filename to be opened, or its fileid
  - string folderurl: the URL to come back to the containing folder for this file, typically shown by the Office app
  - string endpoint (optional): the storage endpoint to be used to look up the file or the storage id, in case of
    multi-instance underlying storage; defaults to 'default'
  '''
  Wopi.refreshconfig()
  req = flask.request
  # if running in https mode, first check if the shared secret matches ours
  if 'Authorization' not in req.headers or req.headers['Authorization'] != 'Bearer ' + Wopi.iopsecret:
    Wopi.log.warning('msg="iopOpen: unauthorized access attempt, missing authorization token" ' \
                     'client="%s"' % req.remote_addr)
    return 'Client not authorized', http.client.UNAUTHORIZED
  # now validate the user identity and deny root access
  try:
    if 'TokenHeader' in req.headers:
      userid = req.headers['TokenHeader']
    else:
      # backwards compatibility
      userid = 'N/A'
      ruid = int(req.args['ruid'])
      rgid = int(req.args['rgid'])
      userid = '%d:%d' % (ruid, rgid)
      if ruid == 0 or rgid == 0:
        raise ValueError
  except ValueError:
    Wopi.log.warning('msg="iopOpen: invalid or missing user/token in request" client="%s" user="%s"' % \
                     (req.remote_addr, userid))
    return 'Client not authorized', http.client.UNAUTHORIZED
  fileid = urllib.parse.unquote(req.args['filename']) if 'filename' in req.args else req.args['fileid']
  if 'viewmode' in req.args:
    try:
      viewmode = utils.ViewMode(req.args['viewmode'])
    except ValueError:
      Wopi.log.warning('msg="iopOpen: invalid viewmode parameter" client="%s" viewmode="%s"' % \
                       (req.remote_addr, req.args['viewmode']))
      return 'Invalid argument', http.client.BAD_REQUEST
  else:
    # backwards compatibility
    viewmode = utils.ViewMode.READ_WRITE if 'canedit' in req.args and req.args['canedit'].lower() == 'true' \
               else utils.ViewMode.READ_ONLY
  username = req.args['username'] if 'username' in req.args else ''
  folderurl = urllib.parse.unquote(req.args['folderurl'])
  endpoint = req.args['endpoint'] if 'endpoint' in req.args else 'default'
  try:
    inode, acctok = utils.generateAccessToken(userid, fileid, viewmode, username, folderurl, endpoint)
    # return an URL-encoded WOPISrc URL for the Office Online server
    return '%s&access_token=%s' % (utils.generateWopiSrc(inode), acctok)      # no need to URL-encode the JWT token
  except IOError as e:
    Wopi.log.info('msg="iopOpen: remote error on generating token" client="%s" user="%s" ' \
                  'friendlyname="%s" mode="%s" endpoint="%s" reason="%s"' % \
                  (req.remote_addr, userid, username, viewmode, endpoint, e))
    return 'Remote error, file not found or file is a directory', http.client.NOT_FOUND


@Wopi.app.route("/wopi/cbox/open", methods=['GET'])
def cboxOpen():
  '''CERNBox-specific endpoint for /open, provided for backwards compatibility'''
  return iopOpen()


@Wopi.app.route("/wopi/iop/open/list", methods=['GET'])
def iopGetOpenFiles():
  '''Returns a list of all currently opened files, for operations purposes only.
  This call is protected by the same shared secret as the /wopi/iop/open call.'''
  req = flask.request
  if 'Authorization' not in req.headers or req.headers['Authorization'] != 'Bearer ' + Wopi.iopsecret:
    Wopi.log.warning('msg="iopGetOpenFiles: unauthorized access attempt, missing authorization token" ' \
                     'client="%s"' % req.remote_addr)
    return 'Client not authorized', http.client.UNAUTHORIZED
  # first convert the sets into lists, otherwise sets cannot be serialized in JSON format
  jlist = {}
  for f in list(Wopi.openfiles.keys()):
    jlist[f] = (Wopi.openfiles[f][0], tuple(Wopi.openfiles[f][1]))
  # dump the current list of opened files in JSON format
  Wopi.log.info('msg="iopGetOpenFiles: returning list of open files" client="%s"' % req.remote_addr)
  return flask.Response(json.dumps(jlist), mimetype='application/json')


@Wopi.app.route("/wopi/cbox/download", methods=['GET'])
def cboxDownload():
  '''Returns the file's content for a given valid access token. Used as a download URL,
     so that the file's path is never explicitly visible.'''
  # TODO this endpoint should be removed altogether: the download should be directly served by Reva
  try:
    acctok = jwt.decode(flask.request.args['access_token'], Wopi.wopisecret, algorithms=['HS256'])
    if acctok['exp'] < time.time():
      raise jwt.exceptions.ExpiredSignatureError
    resp = flask.Response(storage.readfile(acctok['endpoint'], acctok['filename'], acctok['userid']), \
                          mimetype='application/octet-stream')
    resp.headers['Content-Disposition'] = 'attachment; filename="%s"' % os.path.basename(acctok['filename'])
    resp.status_code = http.client.OK
    Wopi.log.info('msg="cboxDownload: direct download succeeded" filename="%s" user="%s" token="%s"' % \
                  (acctok['filename'], acctok['userid'], flask.request.args['access_token'][-20:]))
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


@Wopi.app.route("/wopi/cbox/endpoints", methods=['GET'])
@Wopi.metrics.do_not_track()
def cboxEndPoints():
  '''Returns the office apps end-points registered with this WOPI server. This is used by the EFSS
  client to discover which Apps frontends can be used with this WOPI server.
  Note that if the end-points are relocated and the corresponding configuration entry updated,
  the WOPI server must be restarted.'''
  # TODO this endpoint should be moved to the Apps Registry service in Reva
  Wopi.log.info('msg="cboxEndPoints: returning all registered office apps end-points" client="%s" mimetypesCount="%d"' % \
                (flask.request.remote_addr, len(Wopi.ENDPOINTS)))
  return flask.Response(json.dumps(Wopi.ENDPOINTS), mimetype='application/json')


@Wopi.app.route("/wopi/cbox/lock", methods=['GET', 'POST'])
def cboxLock():
  '''Lock a given filename so that a later WOPI lock call would detect a conflict.
  Used for OnlyOffice as they do not use WOPI: this way better interoperability is ensured.
  It creates a LibreOffice-compatible lock, which is checked by the WOPI lock call
  as well as by LibreOffice.
  Method: POST to create a lock, GET to query for it
  Request arguments:
  - string filename: the full path of the filename to be opened
  - string userid (optional): the user identity to create the file, defaults to 'root:root'
  - string endpoint (optional): the storage endpoint to be used to look up the file or the storage id, in case of
    multi-instance underlying storage; defaults to 'default'
  The call returns:
  - HTTP UNAUTHORIZED (401) if the 'Authorization: Bearer' secret is not provided in the header (cf. /wopi/cbox/open)
  - HTTP CONFLICT (409) if a previous lock already exists, or on query, if the file got modified since the lock was created
  - HTTP NOT_FOUND (404) if the file to be locked does not exist, or on query, if no lock exists
  - HTTP INTERNAL_SERVER_ERROR (500) if writing the lock file failed, though no lock existed
  - HTTP OK (200) if the operation succeeded (on query, if no file modification took place since the lock was created)
  In the latter case, a unique lock ID is returned, which is the timestamp when the lock was first created.
  '''
  req = flask.request
  # first check if the shared secret matches ours
  if 'Authorization' not in req.headers or req.headers['Authorization'] != 'Bearer ' + Wopi.iopsecret:
    Wopi.log.warning('msg="cboxLock: unauthorized access attempt, missing authorization token" '
                     'client="%s"' % req.remote_addr)
    return 'Client not authorized', http.client.UNAUTHORIZED
  filename = req.args['filename']
  userid = req.args['userid'] if 'userid' in req.args else '0:0'
  endpoint = req.args['endpoint'] if 'endpoint' in req.args else 'default'
  query = req.method == 'GET'
  Wopi.log.info('msg="cboxLock: start processing" filename="%s" request="%s"' % (filename, "query" if query else "create"))

  # first make sure the file itself exists
  try:
    filestat = storage.stat(endpoint, filename, userid)
  except IOError as e:
    Wopi.log.warning('msg="cboxLock: target file not found" filename="%s"' % filename)
    return 'File not found or file is a directory', http.client.NOT_FOUND

  # probe if a WOPI lock already exists and expire it if too old:
  # need to craft a special access token
  acctok = {}
  acctok['filename'] = filename
  acctok['endpoint'] = endpoint
  acctok['userid'] = userid
  utils.retrieveWopiLock(0, 'GETLOCK', '', acctok)

  # then probe the existence of a MS Office lock
  try:
    mslockstat = storage.stat(endpoint, utils.getMicrosoftOfficeLockName(filename), userid)
    Wopi.log.info('msg="cboxLock: found existing Microsoft Office lock" filename="%s" lockmtime="%ld"' % \
                  (filename, mslockstat['mtime']))
    return 'Previous lock exists', http.client.CONFLICT
  except IOError as e:
    pass

  if query:
    # in case of lock query, probe by reading the requested LibreOffice-compatible lock
    try:
      lock = next(storage.readfile(endpoint, utils.getLibreOfficeLockName(filename), userid))
      if isinstance(lock, IOError):
        raise lock
      # lock is there, check last mtime
      lockstat = storage.stat(endpoint, utils.getLibreOfficeLockName(filename), userid)
    except (IOError, StopIteration) as e:
      # be optimistic, any error here (including no content in the lock file) is like ENOENT
      Wopi.log.info('msg="cboxLock: lock to be queried not found" filename="%s" reason="%s"' % \
                    (filename, 'empty lock' if isinstance(e, StopIteration) else str(e)))
      return 'Previous lock not found', http.client.NOT_FOUND
    if filestat['mtime'] > lockstat['mtime']:
      # we were asked to query an existing lock, but the file was modified in between (e.g. by a sync client):
      # notify potential conflict
      Wopi.log.info('msg="cboxLock: file got modified after LibreOffice-compatible lock file was created" ' \
                    'filename="%s" request="query"' % filename)
      return 'File modified since open time', http.client.CONFLICT
    # now check content
    lock = lock.decode('utf-8')
    if 'OnlyOffice Online Editor' not in lock:
      Wopi.log.info('msg="cboxLock: found existing LibreOffice lock" filename="%s" holder="%s" lockmtime="%ld" request="query"' % \
                    (filename, lock.split(',')[1] if ',' in lock else lock, lockstat['mtime']))
      return 'Previous lock exists', http.client.CONFLICT
    # if the lock was created for OnlyOffice, it's OK (OnlyOffice will handle the collaborative session)
    try:
      # extract the creation timestamp on the pre-existing lock if any (see below how the lock is constructed)
      lockid = int(lock.split(';\n')[1].strip(';'))
    except (IndexError, ValueError):
      # lock got corrupted and did not contain the extra creation timestamp
      Wopi.log.info('msg="cboxLock: found existing LibreOffice lock" filename="%s" holder="%s" lockmtime="%ld" request="query"' % \
                    (filename, lock.split(',')[1] if ',' in lock else lock, lockstat['mtime']))
      return 'Previous lock exists', http.client.CONFLICT
    Wopi.log.info('msg="cboxLock: lock file still valid" filename="%s" id="%d" lockmtime="%ld" request="query"' % \
                  (filename, lockid, lockstat['mtime']))
    return str(lockid), http.client.OK

  # else: create a LibreOffice-compatible lock, but with an extra line that contains the timestamp when it was first
  # created (i.e. now or whatever was found on the previous one). This is used by the OnlyOffice integration.
  # TODO once OnlyOffice supports locking, we may create an OnlyOffice-compatible lock here (cf. CERNBOX-1051)
  # provided we can extend it in a similar way.
  try:
    lockid = int(time.time())
    lolockcontent = ',OnlyOffice Online Editor,%s,%s,ExtWebApp;\n%d;' % \
                    (Wopi.wopiurl, time.strftime('%d.%m.%Y %H:%M', time.localtime(time.time())), lockid)
    # try to write in exclusive mode (and if a valid WOPI lock exists, assume the corresponding LibreOffice lock
    # is still there so the write will fail)
    storage.writefile(endpoint, utils.getLibreOfficeLockName(filename), userid, lolockcontent, islock=True)
    Wopi.log.info('msg="cboxLock: created LibreOffice-compatible lock file" filename="%s" id="%d"' % (filename, lockid))
    return str(lockid), http.client.OK
  except IOError as e:
    if 'File exists and islock flag requested' not in str(e):
      # writing failed
      Wopi.log.error('msg="cboxLock: unable to store LibreOffice-compatible lock file" filename="%s" reason="%s"' % \
                     (filename, e))
      return 'Error locking file', http.client.INTERNAL_SERVER_ERROR
    # otherwise, a lock existed: try and read it
    try:
      lock = next(storage.readfile(endpoint, utils.getLibreOfficeLockName(filename), userid))
      if isinstance(lock, IOError):
        raise lock
    except (IOError, StopIteration) as e:
      #  CERNBOX-1279: another thread was faster in creating the lock, but it's still in flight (StopIteration = no content)!
      Wopi.log.warning('msg="cboxLock: detected race condition, attempting to re-read LibreOffice-compatible lock" ' \
                       'filename="%s" reason="%s"' % (filename, 'empty lock' if isinstance(e, StopIteration) else str(e)))
      # let's just try again in a short while (not too short though: 2 secs were not enough in testing)
      time.sleep(5)
      try:
        lock = next(storage.readfile(endpoint, utils.getLibreOfficeLockName(filename), userid))
        if isinstance(lock, IOError):
          raise lock
      except (IOError, StopIteration) as e:
        # give up
        Wopi.log.warning('msg="cboxLock: unable to read existing LibreOffice lock" filename="%s" reason="%s"' % \
                         (filename, 'empty lock' if isinstance(e, StopIteration) else str(e)))
        return 'Previous lock exists', http.client.CONFLICT
    lock = lock.decode('utf-8')
    if 'OnlyOffice Online Editor' not in lock:
      # a previous lock existed and it's not held by us, fail with conflict
      Wopi.log.info('msg="cboxLock: found existing LibreOffice lock" filename="%s" holder="%s" request="create"' % \
                    (filename, lock.split(',')[1] if ',' in lock else lock))
      return 'Previous lock exists', http.client.CONFLICT
    # otherwise, extract the previous timestamp and refresh the lock itself
    # (this is equivalent to a touch, needed to make the mtime check on query valid, see above)
    try:
      lockid = int(lock.split(';\n')[1].strip(';'))
      lolockcontent = ',OnlyOffice Online Editor,%s,%s,ExtWebApp;\n%d;' % \
                      (Wopi.wopiurl, time.strftime('%d.%m.%Y %H:%M', time.localtime(time.time())), lockid)
      storage.writefile(endpoint, utils.getLibreOfficeLockName(filename), userid, lolockcontent, islock=False)
      Wopi.log.info('msg="cboxLock: refreshed LibreOffice-compatible lock file" filename="%s" id="%d"' % (filename, lockid))
      return str(lockid), http.client.OK
    except IndexError as e:
      Wopi.log.error('msg="cboxLock: unable to refresh LibreOffice-compatible lock file" filename="%s" lock="%s" reason="%s"' % \
                     (filename, lock, e))
    except IOError as e:
      # this is unexpected, return failure
      Wopi.log.error('msg="cboxLock: unable to refresh LibreOffice-compatible lock file" filename="%s" reason="%s"' % \
                     (filename, e))
      return 'Error relocking file', http.client.INTERNAL_SERVER_ERROR


@Wopi.app.route("/wopi/cbox/unlock", methods=['POST'])
def cboxUnlock():
  '''Unlock a given filename. Used for OnlyOffice as they do not use WOPI (see cboxLock).
  Request arguments:
  - string filename: the full path of the filename to be opened
  - string userid (optional): the user identity to create the file, defaults to 'root:root'
  - string endpoint (optional): the storage endpoint to be used to look up the file or the storage id, in case of
    multi-instance underlying storage; defaults to 'default'
  The call returns:
  - HTTP UNAUTHORIZED (401) if the 'Authorization: Bearer' secret is not provided in the header (cf. /wopi/cbox/open)
  - HTTP CONFLICT (409) if a lock exists, but held by another application
  - HTTP NOT_FOUND (404) if no lock was found for the given file
  - HTTP INTERNAL_SERVER_ERROR (500) if some other I/O error occurred with the given lock file
  - HTTP OK (200) if a lock for OnlyOffice existed. In this case it is removed.
  '''
  req = flask.request
  # first check if the shared secret matches ours
  if 'Authorization' not in req.headers or req.headers['Authorization'] != 'Bearer ' + Wopi.iopsecret:
    Wopi.log.warning('msg="cboxUnlock: unauthorized access attempt, missing authorization token" ' \
                     'client="%s"' % req.remote_addr)
    return 'Client not authorized', http.client.UNAUTHORIZED
  filename = req.args['filename']
  userid = req.args['userid'] if 'userid' in req.args else '0:0'
  endpoint = req.args['endpoint'] if 'endpoint' in req.args else 'default'
  Wopi.log.info('msg="cboxUnlock: start processing" filename="%s"' % filename)
  try:
    # probe if a WOPI/LibreOffice lock exists with the expected signature
    lock = next(storage.readfile(endpoint, utils.getLibreOfficeLockName(filename), userid))
    if isinstance(lock, IOError):
      # typically ENOENT, any other error is grouped here
      Wopi.log.warning('msg="cboxUnlock: lock file not found" filename="%s"' % filename)
      return 'Lock not found', http.client.NOT_FOUND
    lock = lock.decode('utf-8')
    if 'OnlyOffice Online Editor' in lock:
      # remove the LibreOffice-compatible lock file
      storage.removefile(endpoint, utils.getLibreOfficeLockName(filename), userid, 1)
      # and log this along with the previous lockid for reference
      lockid = int(lock.split(';\n')[1].strip(';'))
      Wopi.log.info('msg="cboxUnlock: successfully removed LibreOffice-compatible lock file" filename="%s" id="%d"' % \
                    (filename, lockid))
      return 'OK', http.client.OK
    # else another lock exists
    Wopi.log.info('msg="cboxUnlock: lock file held by another application" filename="%s" holder="%s"' % \
                  (filename, lock.split(',')[1] if ',' in lock else lock))
    return 'Lock held by another application', http.client.CONFLICT
  except (IOError, StopIteration) as e:
    Wopi.log.error('msg="cboxUnlock: remote error with the requested lock" filename="%s" reason="%s"' % \
                   (filename, 'empty lock' if isinstance(e, StopIteration) else str(e)))
    return 'Error unlocking file', http.client.INTERNAL_SERVER_ERROR


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
    acctok['viewmode'] = utils.ViewMode(acctok['viewmode'])
    if acctok['exp'] < time.time():
      raise jwt.exceptions.ExpiredSignatureError
    Wopi.log.info('msg="CheckFileInfo" user="%s" filename="%s" fileid="%s" token="%s"' % \
                  (acctok['userid'], acctok['filename'], fileid, flask.request.args['access_token'][-20:]))
    statInfo = storage.statx(acctok['endpoint'], acctok['filename'], acctok['userid'])
    # compute some entities for the response
    wopiSrc = 'WOPISrc=%s&access_token=%s' % (utils.generateWopiSrc(fileid), flask.request.args['access_token'])
    fExt = os.path.splitext(acctok['filename'])[1]
    # populate metadata for this file
    filemd = {}
    filemd['BaseFileName'] = filemd['BreadcrumbDocName'] = os.path.basename(acctok['filename'])
    furl = acctok['folderurl']
    # encode the path part as it is going to be an URL GET argument
    filemd['BreadcrumbFolderUrl'] = furl[:furl.find('=')+1] + urllib.parse.quote_plus(furl[furl.find('=')+1:])
    if acctok['username'] == '':
      filemd['UserFriendlyName'] = 'Guest ' + utils.randomString(3)
      if '?path' in furl and furl[-1] != '=':
        # this is a subfolder of a public share, show it
        filemd['BreadcrumbFolderName'] = 'Back to ' + furl[furl.find('?path'):].split('/')[-1]
      else:
        # this is the top level public share, which is anonymous
        filemd['BreadcrumbFolderName'] = 'Back to the CERNBox share'
    else:
      filemd['UserFriendlyName'] = acctok['username']
      filemd['BreadcrumbFolderName'] = 'Back to ' + acctok['filename'].split('/')[-2]
    if acctok['viewmode'] in (utils.ViewMode.READ_ONLY, utils.ViewMode.READ_WRITE):
      filemd['DownloadUrl'] = '%s?access_token=%s' % \
                              (Wopi.config.get('general', 'downloadurl'), flask.request.args['access_token'])
    filemd['OwnerId'] = statInfo['userid']
    filemd['UserId'] = acctok['userid']     # typically same as OwnerId; different when accessing shared documents
    filemd['Size'] = statInfo['size']
    # TODO the version is generated like this in ownCloud: 'V' . $file->getEtag() . \md5($file->getChecksum());
    filemd['Version'] = statInfo['mtime']   # mtime is used as version here
    filemd['SupportsExtendedLockLength'] = filemd['SupportsGetLock'] = True
    filemd['SupportsUpdate'] = filemd['UserCanWrite'] = filemd['SupportsLocks'] = filemd['SupportsRename'] = \
        filemd['SupportsDeleteFile'] = filemd['UserCanRename'] = acctok['viewmode'] == utils.ViewMode.READ_WRITE
    filemd['UserCanNotWriteRelative'] = acctok['viewmode'] != utils.ViewMode.READ_WRITE
    # populate app-specific metadata
    # the following properties are only used by MS Office Online
    if fExt in ['.docx', '.xlsx', '.pptx']:
      # TODO once the endpoints are managed by Reva, this metadata has to be provided in the initial /open call
      filemd['HostViewUrl'] = '%s&%s' % (Wopi.ENDPOINTS[fExt]['view'], wopiSrc)
      filemd['HostEditUrl'] = '%s&%s' % (Wopi.ENDPOINTS[fExt]['edit'], wopiSrc)
      # the following actions are broken in MS Office Online, therefore they are disabled
      filemd['SupportsRename'] = filemd['UserCanRename'] = False
    # the following is to enable the 'Edit in Word/Excel/PowerPoint' (desktop) action (probably broken)
    try:
      filemd['ClientUrl'] = Wopi.config.get('general', 'webdavurl') + '/' + acctok['filename']
    except configparser.NoOptionError:
      # if no WebDAV URL is provided, ignore this setting
      pass
    # extensions for Collabora Online
    filemd['EnableOwnerTermination'] = True
    filemd['DisableExport'] = filemd['DisableCopy'] = filemd['DisablePrint'] = acctok['viewmode'] == utils.ViewMode.VIEW_ONLY
    #filemd['LastModifiedTime'] = datetime.fromtimestamp(int(statInfo['mtime'])).isoformat()   # this currently breaks

    Wopi.log.info('msg="File metadata response" token="%s" metadata="%s"' % (flask.request.args['access_token'][-20:], filemd))
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


@Wopi.app.route("/wopi/files/<fileid>/contents", methods=['GET'])
def wopiGetFile(fileid):
  '''Implements the GetFile WOPI call'''
  Wopi.refreshconfig()
  try:
    acctok = jwt.decode(flask.request.args['access_token'], Wopi.wopisecret, algorithms=['HS256'])
    if acctok['exp'] < time.time():
      raise jwt.exceptions.ExpiredSignatureError
    Wopi.log.info('msg="GetFile" user="%s" filename="%s" fileid="%s" token="%s"' % \
                  (acctok['userid'], acctok['filename'], fileid, flask.request.args['access_token'][-20:]))
    # stream file from storage to client
    resp = flask.Response(storage.readfile(acctok['endpoint'], acctok['filename'], acctok['userid']), \
                          mimetype='application/octet-stream')
    resp.status_code = http.client.OK
    return resp
  except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError) as e:
    Wopi.log.warning('msg="Signature verification failed" client="%s" requestedUrl="%s" error="%s" token="%s"' % \
                     (flask.request.remote_addr, flask.request.base_url, e, flask.request.args['access_token']))
    return 'Invalid access token', http.client.UNAUTHORIZED


#
# The following operations are all called on POST /wopi/files/<fileid>
#
def wopiUnlock(fileid, reqheaders, acctok, force=False):
  '''Implements the Unlock WOPI call'''
  lock = reqheaders['X-WOPI-Lock']
  retrievedLock = utils.retrieveWopiLock(fileid, 'UNLOCK', lock, acctok)
  if not force and not utils.compareWopiLocks(retrievedLock, lock):
    return utils.makeConflictResponse('UNLOCK', retrievedLock, lock, '', acctok['filename'])
  # OK, the lock matches. Remove any extended attribute related to locks and conflicts handling
  try:
    storage.removefile(acctok['endpoint'], utils.getLockName(acctok['filename']), acctok['userid'], 1)
  except IOError:
    # ignore, it's not worth to report anything here
    pass
  try:
    storage.rmxattr(acctok['endpoint'], acctok['filename'], acctok['userid'], LASTSAVETIMEKEY)
  except IOError:
    # same as above
    pass
  try:
    # also remove the LibreOffice-compatible lock file
    storage.removefile(acctok['endpoint'], utils.getLibreOfficeLockName(acctok['filename']), acctok['userid'], 1)
  except IOError:
    # same as above
    pass
  # and update our internal list of opened files
  if not force:
    try:
      del Wopi.openfiles[acctok['filename']]
    except KeyError:
      # already removed?
      pass
  return 'OK', http.client.OK


def wopiLock(fileid, reqheaders, acctok):
  '''Implements the Lock, RefreshLock, and UnlockAndRelock WOPI calls'''
  # cf. http://wopi.readthedocs.io/projects/wopirest/en/latest/files/Lock.html
  op = reqheaders['X-WOPI-Override']
  lock = reqheaders['X-WOPI-Lock']
  oldLock = reqheaders['X-WOPI-OldLock'] if 'X-WOPI-OldLock' in reqheaders else None
  retrievedLock = utils.retrieveWopiLock(fileid, op, lock, acctok)
  # perform the required checks for the validity of the new lock
  if (oldLock is None and retrievedLock is not None and not utils.compareWopiLocks(retrievedLock, lock)) or \
     (oldLock is not None and not utils.compareWopiLocks(retrievedLock, oldLock)):
    # XXX we got a locking conflict: as we've seen cases of looping clients attempting to restate the same
    # XXX lock over and over again, we keep track of this request and we forcefully clean up the lock
    # XXX and let the request succeed once 'too many' (> 5) requests come for the same lock
    if retrievedLock not in Wopi.repeatedLockRequests:
      Wopi.repeatedLockRequests[retrievedLock] = 1
    else:
      Wopi.repeatedLockRequests[retrievedLock] += 1
    if Wopi.repeatedLockRequests[retrievedLock] < 5:
      return utils.makeConflictResponse(op, retrievedLock, lock, oldLock, acctok['filename'])
    wopiUnlock(fileid, reqheaders, acctok, force=True)
    Wopi.log.warning('msg="Lock: BLINDLY removed the existing lock to unblock client" op="%s" user="%s" '\
                     'filename="%s" token="%s"' % \
                     (op, acctok['userid'], acctok['filename'], \
                      flask.request.args['access_token'][-20:]))
  # LOCK or REFRESH_LOCK: set the lock to the given one, including the expiration time
  try:
    utils.storeWopiLock(op, lock, acctok, os.path.splitext(acctok['filename'])[1] in Wopi.nonofficetypes)
  except IOError as e:
    if utils.EXCL_ERROR in str(e):
      # this file was already locked externally: storeWopiLock looks at LibreOffice-compatible locks
      return utils.makeConflictResponse(op, 'External App', lock, oldLock, acctok['filename'], \
                                        'The file was locked by another application')
    elif 'No such file or directory' in str(e):
      # the file got renamed/deleted: this is equivalent to a conflict
      return utils.makeConflictResponse(op, 'External App', lock, oldLock, acctok['filename'], \
                                        'The file got moved or deleted')
    # any other failure
    return str(e), http.client.INTERNAL_SERVER_ERROR
  if not retrievedLock:
    # on first lock, set an xattr with the current time for later conflicts checking
    try:
      storage.setxattr(acctok['endpoint'], acctok['filename'], acctok['userid'], LASTSAVETIMEKEY, int(time.time()))
    except IOError as e:
      # not fatal, but will generate a conflict file later on, so log a warning
      Wopi.log.warning('msg="Unable to set lastwritetime xattr" user="%s" filename="%s" token="%s" reason="%s"' % \
                       (acctok['userid'], acctok['filename'], flask.request.args['access_token'][-20:], e))
    # also, keep track of files that have been opened for write: this is for statistical purposes only
    # (cf. the GetLock WOPI call and the /wopi/cbox/open/list action)
    if acctok['filename'] not in Wopi.openfiles:
      Wopi.openfiles[acctok['filename']] = (time.asctime(), set([acctok['username']]))
    else:
      # the file was already opened but without lock: this happens on new files (cf. editnew action), just log
      Wopi.log.info('msg="First lock for new file" user="%s" filename="%s" token="%s"' % \
                    (acctok['userid'], acctok['filename'], flask.request.args['access_token'][-20:]))
  return 'OK', http.client.OK


def wopiGetLock(fileid, _reqheaders_unused, acctok):
  '''Implements the GetLock WOPI call'''
  resp = flask.Response()
  lock = utils.retrieveWopiLock(fileid, 'GETLOCK', '', acctok)
  resp.status_code = http.client.OK
  if lock:
    resp.headers['X-WOPI-Lock'] = lock
    # for statistical purposes, check whether a lock exists and update internal bookkeeping
    try:
      # the file was already opened for write, check whether this is a new user
      if not acctok['username'] in Wopi.openfiles[acctok['filename']][1]:
        # yes it's a new user
        Wopi.openfiles[acctok['filename']][1].add(acctok['username'])
        if len(Wopi.openfiles[acctok['filename']][1]) > 1:
          # for later monitoring, explicitly log that this file is being edited by at least two users
          Wopi.log.info('msg="Collaborative editing detected" filename="%s" token="%s" users="%s"' % \
                         (acctok['filename'], flask.request.args['access_token'][-20:],
                          list(Wopi.openfiles[acctok['filename']][1])))
    except KeyError:
      # existing lock but missing Wopi.openfiles[acctok['filename']] ?
      Wopi.log.warning('msg="Repopulating missing metadata" filename="%s" token="%s" user="%s"' % \
                       (acctok['filename'], flask.request.args['access_token'][-20:], acctok['username']))
      Wopi.openfiles[acctok['filename']] = (time.asctime(), set([acctok['username']]))
  # we might want to check if a non-WOPI lock exists for this file:
  #try:
  #  lockstat = storage.stat(acctok['endpoint'], utils.getLibreOfficeLockName(acctok['filename']), acctok['userid'])
  #  return utils.makeConflictResponse('GetLock', 'External App', '', '', acctok['filename'], \
  #                                    'The file was locked by another application')
  #except IOError:
  #  pass
  # however implications have to be properly understood as we've seen cases of locks left behind
  return resp


def wopiPutRelative(fileid, reqheaders, acctok):
  '''Implements the PutRelative WOPI call. Corresponds to the 'Save as...' menu entry.'''
  # cf. http://wopi.readthedocs.io/projects/wopirest/en/latest/files/PutRelativeFile.html
  suggTarget = reqheaders['X-WOPI-SuggestedTarget'] if 'X-WOPI-SuggestedTarget' in reqheaders else ''
  relTarget = reqheaders['X-WOPI-RelativeTarget'] if 'X-WOPI-RelativeTarget' in reqheaders else ''
  overwriteTarget = 'X-WOPI-OverwriteRelativeTarget' in reqheaders and bool(reqheaders['X-WOPI-OverwriteRelativeTarget'])
  Wopi.log.info('msg="PutRelative" user="%s" filename="%s" fileid="%s" suggTarget="%s" relTarget="%s" '
                'overwrite="%r" token="%s"' % \
                (acctok['userid'], acctok['filename'], fileid, \
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
        storage.stat(acctok['endpoint'], targetName, acctok['userid'])
        # the file exists: try a different name
        name, ext = os.path.splitext(targetName)
        targetName = name + '_copy' + ext
      except IOError as e:
        if 'No such file or directory' in str(e):
          # OK, the targetName is good to go
          break
        # we got another error with this file, fail
        Wopi.log.info('msg="PutRelative" user="%s" filename="%s" token="%s" suggTarget="%s" error="%s"' % \
                      (acctok['userid'], targetName, flask.request.args['access_token'][-20:], \
                       suggTarget, str(e)))
        return 'Illegal filename %s: %s' % (targetName, e), http.client.BAD_REQUEST
  else:
    # the relative target is a filename to be respected, and that may overwrite an existing file
    relTarget = os.path.dirname(acctok['filename']) + os.path.sep + relTarget    # make full path
    try:
      # check for file existence + lock
      fileExists = retrievedLock = False
      fileExists = storage.stat(acctok['endpoint'], relTarget, acctok['userid'])
      retrievedLock = storage.stat(acctok['endpoint'], utils.getLockName(relTarget), acctok['userid'])
    except IOError:
      pass
    if fileExists and (not overwriteTarget or retrievedLock):
      return utils.makeConflictResponse('PUTRELATIVE', retrievedLock, '', '', relTarget, 'Target file already exists')
    # else we can use the relative target
    targetName = relTarget
  # either way, we now have a targetName to save the file: attempt to do so
  try:
    utils.storeWopiFile(flask.request, acctok, LASTSAVETIMEKEY, targetName)
  except IOError as e:
    Wopi.log.info('msg="Error writing file" filename="%s" token="%s" error="%s"' % \
                  (targetName, flask.request.args['access_token'][-20:], e))
    return 'I/O Error', http.client.INTERNAL_SERVER_ERROR
  # generate an access token for the new file
  Wopi.log.info('msg="PutRelative: generating new access token" user="%s" filename="%s" ' \
                'mode="ViewMode.READ_WRITE" friendlyname="%s"' % \
                (acctok['userid'], targetName, acctok['username']))
  inode, newacctok = utils.generateAccessToken(acctok['userid'], targetName, utils.ViewMode.READ_WRITE, acctok['username'], \
                                               acctok['folderurl'], acctok['endpoint'])
  # prepare and send the response as JSON
  putrelmd = {}
  putrelmd['Name'] = os.path.basename(targetName)
  putrelmd['Url'] = '%s?access_token=%s' % (utils.generateWopiSrc(inode), newacctok)
  putrelmd['HostEditUrl'] = '%s&WOPISrc=%s&access_token=%s' % \
                            (Wopi.ENDPOINTS[os.path.splitext(targetName)[1]]['edit'], \
                             utils.generateWopiSrc(inode), newacctok)
  Wopi.log.debug('msg="PutRelative response" token="%s" metadata="%s"' % (newacctok[-20:], putrelmd))
  return flask.Response(json.dumps(putrelmd), mimetype='application/json')


def wopiDeleteFile(fileid, _reqheaders_unused, acctok):
  '''Implements the DeleteFile WOPI call'''
  retrievedLock = utils.retrieveWopiLock(fileid, 'DELETE', '', acctok)
  if retrievedLock is not None:
    # file is locked and cannot be deleted
    return utils.makeConflictResponse('DELETE', retrievedLock, '', '', acctok['filename'])
  try:
    storage.removefile(acctok['endpoint'], acctok['filename'], acctok['userid'])
    return 'OK', http.client.OK
  except IOError as e:
    Wopi.log.info('msg="DeleteFile" token="%s" error="%s"' % (flask.request.args['access_token'][-20:], e))
    return 'Internal error', http.client.INTERNAL_SERVER_ERROR


def wopiRenameFile(fileid, reqheaders, acctok):
  '''Implements the RenameFile WOPI call.'''
  targetName = reqheaders['X-WOPI-RequestedName']
  lock = reqheaders['X-WOPI-Lock']
  retrievedLock = utils.retrieveWopiLock(fileid, 'RENAMEFILE', lock, acctok)
  if retrievedLock is not None and not utils.compareWopiLocks(retrievedLock, lock):
    return utils.makeConflictResponse('RENAMEFILE', retrievedLock, lock, '', acctok['filename'])
  try:
    # the destination name comes without base path and without extension
    targetName = os.path.dirname(acctok['filename']) + '/' + targetName + os.path.splitext(acctok['filename'])[1]
    Wopi.log.info('msg="RenameFile" user="%s" filename="%s" token="%s" targetname="%s"' % \
                  (acctok['userid'], acctok['filename'], flask.request.args['access_token'][-20:], targetName))
    storage.renamefile(acctok['endpoint'], acctok['filename'], targetName, acctok['userid'])
    # also rename the locks
    storage.renamefile(acctok['endpoint'], utils.getLockName(acctok['filename']), utils.getLockName(targetName), \
                       acctok['userid'])
    storage.renamefile(acctok['endpoint'], utils.getLibreOfficeLockName(acctok['filename']), \
                       utils.getLibreOfficeLockName(targetName), acctok['userid'])
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
  Wopi.log.info('msg="PutFile" user="%s" filename="%s" fileid="%s" action="editnew" token="%s"' % \
                (acctok['userid'], acctok['filename'], fileid, flask.request.args['access_token'][-20:]))
  try:
    # try to stat the file and raise IOError if not there
    if storage.stat(acctok['endpoint'], acctok['filename'], acctok['userid'])['size'] == 0:
      # a 0-size file is equivalent to not existing
      raise IOError
    Wopi.log.warning('msg="PutFile" error="File exists but no WOPI lock provided" filename="%s" token="%s"' %
                     (acctok['filename'], flask.request.args['access_token']))
    return 'File exists', http.client.CONFLICT
  except IOError:
    # indeed the file did not exist, so we write it for the first time
    utils.storeWopiFile(flask.request, acctok, LASTSAVETIMEKEY)
    Wopi.log.info('msg="File stored successfully" action="editnew" user="%s" filename="%s" token="%s"' % \
                  (acctok['userid'], acctok['filename'], flask.request.args['access_token']))
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
    if op != 'GET_LOCK' and utils.ViewMode(acctok['viewmode']) != utils.ViewMode.READ_WRITE:
      # protect this call if the WOPI client does not have privileges
      return 'Attempting to perform a write operation using a read-only token', http.client.UNAUTHORIZED
    if op in ('LOCK', 'REFRESH_LOCK'):
      return wopiLock(fileid, headers, acctok)
    if op == 'UNLOCK':
      return wopiUnlock(fileid, headers, acctok)
    if op == 'GET_LOCK':
      return wopiGetLock(fileid, headers, acctok)
    if op == 'PUT_RELATIVE':
      return wopiPutRelative(fileid, headers, acctok)
    if op == 'DELETE':
      return wopiDeleteFile(fileid, headers, acctok)
    if op == 'RENAME_FILE':
      return wopiRenameFile(fileid, headers, acctok)
    #elif op == 'PUT_USER_INFO':   https://wopirest.readthedocs.io/en/latest/files/PutUserInfo.html
    # Any other op is unsupported
    Wopi.log.warning('msg="Unknown/unsupported operation" operation="%s"' % op)
    return 'Not supported operation found in header', http.client.NOT_IMPLEMENTED
  except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError) as e:
    Wopi.log.warning('msg="Signature verification failed" client="%s" requestedUrl="%s" error="%s" token="%s"' % \
                     (flask.request.remote_addr, flask.request.base_url, e, flask.request.args['access_token']))
    return 'Invalid access token', http.client.NOT_FOUND


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
    retrievedLock = utils.retrieveWopiLock(fileid, 'PUTFILE', lock, acctok)
    if retrievedLock is not None and not utils.compareWopiLocks(retrievedLock, lock):
      return utils.makeConflictResponse('PUTFILE', retrievedLock, lock, '', acctok['filename'], \
                                        'Cannot overwrite file locked by another application')
    # OK, we can save the file now
    Wopi.log.info('msg="PutFile" user="%s" filename="%s" fileid="%s" action="edit" token="%s"' % \
                  (acctok['userid'], acctok['filename'], fileid, flask.request.args['access_token'][-20:]))
    try:
      # check now the destination file against conflicts
      savetime = storage.getxattr(acctok['endpoint'], acctok['filename'], acctok['userid'], LASTSAVETIMEKEY)
      mtime = None
      mtime = storage.stat(acctok['endpoint'], acctok['filename'], acctok['userid'])['mtime']
      if savetime is None or int(mtime) > int(savetime):
        # no xattr was there or we got our xattr but mtime is more recent: someone may have updated the file
        # from a different source (e.g. FUSE or SMB mount), therefore force conflict.
        # Note we can't get a time resolution better than one second!
        Wopi.log.info('msg="Forcing conflict based on lastWopiSaveTime" user="%s" filename="%s" ' \
                      'savetime="%s" lastmtime="%s" token="%s"' % \
                      (acctok['userid'], acctok['filename'], \
                       savetime, mtime, flask.request.args['access_token'][-20:]))
        raise IOError
      Wopi.log.debug('msg="Got lastWopiSaveTime" user="%s" filename="%s" savetime="%s" lastmtime="%s" token="%s"' % \
                     (acctok['userid'], acctok['filename'], savetime, mtime, flask.request.args['access_token'][-20:]))
    except IOError:
      # either the file was deleted or it was updated/overwritten by others: force conflict
      newname, ext = os.path.splitext(acctok['filename'])
      # !!! typical EFSS formats are like '<filename>_conflict-<date>-<time>', but they're not synchronized back !!!
      newname = '%s-conflict-%s%s' % (newname, time.strftime('%Y%m%d-%H%M%S'), ext.strip())
      utils.storeWopiFile(flask.request, acctok, LASTSAVETIMEKEY, newname)
      # keep track of this action in the original file's xattr, to avoid looping (see below)
      storage.setxattr(acctok['endpoint'], acctok['filename'], acctok['userid'], LASTSAVETIMEKEY, 'conflict')
      Wopi.log.info('msg="Conflicting copy created" user="%s" savetime="%s" lastmtime="%s" newfilename="%s" token="%s"' % \
                    (acctok['userid'], savetime, mtime, newname, flask.request.args['access_token'][-20:]))
      # and report failure to the application: note we use a CONFLICT response as it is better handled by the app
      return utils.makeConflictResponse('PUTFILE', 'External App', lock, '', acctok['filename'], \
                                        'The file being edited got moved or overwritten, conflict copy created')
    except (ValueError, TypeError) as e:
      # the xattr was not an integer: assume the app is looping on an already conflicting file,
      # therefore do nothing and report internal error. Of course if the attribute was modified by hand,
      # this mechanism fails.
      Wopi.log.info('msg="Conflicting copy already created" filename="%s" savetime="%s" lastmtime="%s" error="%s" token="%s"' % \
                    (acctok['filename'], savetime, mtime, e, flask.request.args['access_token'][-20:]))
      return 'Conflict copy already created', http.client.INTERNAL_SERVER_ERROR
    # Go for overwriting the file. Note that the entire check+write operation should be atomic,
    # but the previous check still gives the opportunity of a race condition. We just live with it.
    # Anyhow, the EFSS should support versioning for such cases.
    utils.storeWopiFile(flask.request, acctok, LASTSAVETIMEKEY)
    Wopi.log.info('msg="File stored successfully" action="edit" user="%s" filename="%s" token="%s"' % \
                  (acctok['userid'], acctok['filename'], flask.request.args['access_token'][-20:]))
    return 'OK', http.client.OK
  except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError) as e:
    Wopi.log.warning('msg="Signature verification failed" client="%s" requestedUrl="%s" token="%s"' % \
                     (flask.request.remote_addr, flask.request.base_url, flask.request.args['access_token']))
    return 'Invalid access token', http.client.NOT_FOUND
  except IOError as e:
    Wopi.log.info('msg="Error writing file" filename="%s" token="%s" error="%s"' % \
                  (acctok['filename'], flask.request.args['access_token'], e))
    return 'I/O Error', http.client.INTERNAL_SERVER_ERROR


#
# Start the Flask endless listening loop if started in standalone mode
#
if __name__ == '__main__':
  Wopi.init()
  Wopi.initappsregistry()
  Wopi.run()
