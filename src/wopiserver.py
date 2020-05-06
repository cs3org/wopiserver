#!/usr/bin/python3
'''
wopiserver.py

The Web-application Open Platform Interface (WOPI) gateway for the ScienceMesh IOP

Author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
Contributions: Michael.DSilva@aarnet.edu.au
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
      cls.iopsecret = open(cls.config.get('security', 'iopsecretfile')).read().strip('\n')
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
      _ = cls.config.get('general', 'downloadurl')   # make sure this is defined
      # initialize the utils module
      utils.init(storage, cls)
    except Exception as e:
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
      cls.ENDPOINTS['.one'] = {}
      cls.ENDPOINTS['.one']['view']  = oos + '/o/onenoteframe.aspx?edit=0'                             # pylint: disable=bad-whitespace
      cls.ENDPOINTS['.one']['edit']  = oos + '/o/onenoteframe.aspx?edit=1'                             # pylint: disable=bad-whitespace
      cls.ENDPOINTS['.one']['new']   = oos + '/o/onenoteframe.aspx?edit=1&new=1'                       # pylint: disable=bad-whitespace
      cls.log.info('msg="Microsoft Office Online endpoints successfully configured"')

    code = cls.config.get('general', 'codeurl', fallback=None)
    if code:
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
    slides = cls.config.get('general', 'slidesurl', fallback=None)
    if slides:
      cls.ENDPOINTS['.slide'] = {}
      cls.ENDPOINTS['.slide']['view'] = slides + '?edit=0'
      cls.ENDPOINTS['.slide']['edit'] = slides + '?edit=1'
      cls.ENDPOINTS['.slide']['new'] = slides + '?edit=1'
      cls.log.info('msg="Slides endpoints successfully configured"')

    # The future-supported CodiMD end-point
    codimd = cls.config.get('general', 'codimdurl', fallback=None)
    if codimd:
      cls.ENDPOINTS['.md'] = {}
      cls.ENDPOINTS['.md']['view'] = cls.ENDPOINTS['.md']['edit'] = codimd + '/open'
      cls.ENDPOINTS['.md']['new'] = codimd + '/new'
      cls.ENDPOINTS['.mdx'] = {}
      cls.ENDPOINTS['.mdx']['view'] = cls.ENDPOINTS['.mdx']['edit'] = codimd + '/open'
      cls.ENDPOINTS['.mdx']['new'] = codimd + '/new'
      cls.ENDPOINTS['.txt'] = {}
      cls.ENDPOINTS['.txt']['view'] = cls.ENDPOINTS['.txt']['edit'] = codimd + '/open'
      cls.ENDPOINTS['.txt']['new'] = codimd + '/new'
      cls.log.info('msg="CodiMD endpoints successfully configured"')

    # backstop if no app got registered
    if not cls.ENDPOINTS:
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
# The Flask web application starts here
#
@Wopi.app.route("/", methods=['GET'])
def index():
  '''Return a default index page with some user-friendly information about this service'''
  Wopi.log.info('msg="Accessed index page" client="%s"' % flask.request.remote_addr)
  return """
    <html><head><title>ScienceMesh WOPI</title></head>
    <body>
    <div align="center" style="color:#000080; padding-top:50px; font-family:Verdana; size:11">
    This is the ScienceMesh IOP <a href=http://wopi.readthedocs.io>WOPI</a> server to support online office platforms.<br>
    To use this service, please log in to your EFSS Storage and click on your office documents.</div>
    <br><br><br><br><br><br><br><br><br><br><hr>
    <i>ScienceMesh WOPI Server %s at %s. Powered by Flask %s for Python %s</i>.
    </body>
    </html>
    """ % (WOPISERVERVERSION, socket.getfqdn(), flask.__version__, python_version())


@Wopi.app.route("/wopi/cbox/open", methods=['GET'])
def cboxOpen():
  '''Generates a WOPISrc target and an access token to be passed to a WOPI-compatible Office-like app
  for accessing a given file for a given user.
  Request arguments:
  - int ruid, rgid: user's real Unix identity (id:group)
  - bool canedit: True if full access should be given to the user, otherwise read-only access is granted
  - string username (optional): user's full name, typically shown by the Office app
  - string filename: the full path of the filename to be opened
  - string folderurl: the URL to come back to the containing folder for this file, typically shown by the Office app
  - string endpoint (optional): the storage endpoint to be used to look up the file, in case of
    multi-instance underlying storage; defaults to 'default'
  Note: this is the most sensitive call of this WOPI server as it provides direct
  access to any user's file, therefore it is protected both by IP and a shared secret. The shared
  secret protection is disabled when running in plain http mode for testing purposes.'''
  Wopi.refreshconfig()
  req = flask.request
  # if running in https mode, first check if the shared secret matches ours
  if Wopi.useHttps and ('Authorization' not in req.headers or req.headers['Authorization'] != 'Bearer ' + Wopi.iopsecret):
    Wopi.log.warning('msg="cboxOpen: unauthorized access attempt, missing authorization token" ' \
                     'client="%s"' % req.remote_addr)
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
  # then resolve the client and reject unauthorized ones
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
            Wopi.log.warning('msg="cboxOpen: forcing read-only mode on collaborative editing of a new file" ' \
                             'client="%s" user="%d:%d"' % (req.remote_addr, ruid, rgid))
            canedit = False
          try:
            Wopi.log.info('msg="cboxOpen: access granted, generating token" client="%s" user="%d:%d" ' \
                          'friendlyname="%s" canedit="%s" endpoint="%s"' % \
                          (req.remote_addr, ruid, rgid, username, canedit, endpoint))
            inode, acctok = utils.generateAccessToken(str(ruid), str(rgid), filename, canedit, \
                                                      username, folderurl, endpoint)
            # return an URL-encoded WOPISrc URL for the Office Online server
            return '%s&access_token=%s' % (utils.generateWopiSrc(inode), acctok)      # no need to URL-encode the JWT token
          except IOError:
            return 'Remote error or file not found', http.client.NOT_FOUND
    except socket.gaierror:
      Wopi.log.warning('msg="cboxOpen: %s found in configured allowed clients but unknown by DNS resolution, ignoring"' % c)
  # no match found, fail
  Wopi.log.warning('msg="cboxOpen: unauthorized access attempt, client IP not whitelisted" ' \
                   'client="%s"' % req.remote_addr)
  return 'Client not authorized', http.client.UNAUTHORIZED


@Wopi.app.route("/wopi/cbox/download", methods=['GET'])
def cboxDownload():
  '''Returns the file's content for a given valid access token. Used as a download URL,
     so that the file's path is never explicitly visible.'''
  # TODO this endpoint should be removed altogether: the download should be directly served by Reva
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
    return utils.logGeneralExceptionAndReturn(e, flask.request)


@Wopi.app.route("/wopi/cbox/endpoints", methods=['GET'])
def cboxEndPoints():
  '''Returns the office apps end-points registered with this WOPI server. This is used by the EFSS
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
  if 'Authorization' not in req.headers or req.headers['Authorization'] != 'Bearer ' + Wopi.iopsecret:
    Wopi.log.warning('msg="cboxGetOpenFiles: unauthorized access attempt, missing authorization token" ' \
                     'client="%s"' % req.remote_addr)
    return 'Client not authorized', http.client.UNAUTHORIZED
  # first convert the sets into lists, otherwise sets cannot be serialized in JSON format
  jl = {}
  for f in list(Wopi.openfiles.keys()):
    jl[f] = (Wopi.openfiles[f][0], tuple(Wopi.openfiles[f][1]))
  # dump the current list of opened files in JSON format
  Wopi.log.info('msg="cboxGetOpenFiles: returning list of open files" client="%s"' % req.remote_addr)
  return flask.Response(json.dumps(jl), mimetype='application/json')


@Wopi.app.route("/wopi/cbox/lock", methods=['GET', 'POST'])
def cboxLock():
  '''Lock a given filename so that a later WOPI lock call would detect a conflict.
  Used for OnlyOffice as they do not use WOPI: this way better interoperability is ensured.
  It creates a LibreOffice-compatible lock, which is checked by the WOPI lock call
  as well as by LibreOffice.
  Method: POST to create a lock, GET to query for it
  Request arguments:
  - string filename: the full path of the filename to be opened
  - string endpoint (optional): the storage endpoint to be used to look up the file, in case of
    multi-instance underlying storage; defaults to 'default'
  The call returns:
  - HTTP UNAUTHORIZED (401) if the 'Authorization: Bearer' secret is not provided in the header (cf. /wopi/cbox/open)
  - HTTP CONFLICT (409) if a previous lock already exists, or on query, if the file got modified since the lock was created
  - HTTP NOT_FOUND (404) if the file to be locked does not exist, or on query, if no lock exists
  - HTTP INTERNAL_ERROR (500) if writing the lock file failed, though no lock existed
  - HTTP OK (200) if the operation succeeded (on query, if no file modification took place since the lock was created)
  '''
  req = flask.request
  # first check if the shared secret matches ours
  if 'Authorization' not in req.headers or req.headers['Authorization'] != 'Bearer ' + Wopi.iopsecret:
    Wopi.log.warning('msg="cboxLock: unauthorized access attempt, missing authorization token" '
                     'client="%s"' % req.remote_addr)
    return 'Client not authorized', http.client.UNAUTHORIZED
  filename = req.args['filename']
  endpoint = req.args['endpoint'] if 'endpoint' in req.args else 'default'
  query = req.method == 'GET'
  lockstat = None
  try:
    # probe if a WOPI/LibreOffice lock already exists (a WOPI session always create a LibreOffice lock as well)
    lock = str(next(storage.readfile(endpoint, utils.getLibreOfficeLockName(filename), Wopi.lockruid, Wopi.lockrgid)))
    if 'ERROR on read' in lock:
      if query:
        Wopi.log.info('msg="cboxLock: lock to be queried not found" filename="%s"' % filename)
        return 'Previous lock not found', http.client.NOT_FOUND
      # in case of any read error (not only ENOENT), be optimistic and let it go: cf. _generateAccessToken()
      raise IOError
    if 'OnlyOffice Online Editor' in lock:
      # if the lock was created for OnlyOffice, let it go as well: OnlyOffice will handle the collaborative session
      # but keep lock stat for later comparison
      lockstat = storage.stat(endpoint, utils.getLibreOfficeLockName(filename), Wopi.lockruid, Wopi.lockrgid)
      raise IOError
    Wopi.log.info('msg="cboxLock: found existing LibreOffice lock" filename="%s" holder="%s"' % \
                  (filename, lock.split(',')[1]))
    return 'Previous lock exists', http.client.CONFLICT
  except IOError as e:
    pass
  try:
    # same for MS Office, but don't go beyond stat
    mslockstat = storage.stat(endpoint, utils.getMicrosoftOfficeLockName(filename), Wopi.lockruid, Wopi.lockrgid)
    Wopi.log.info('msg="cboxLock: found existing Microsoft Office lock" filename="%s" mtime="%ld"' % \
                  (filename, mslockstat['mtime']))
    return 'Previous lock exists', http.client.CONFLICT
  except IOError as e:
    pass
  # OK, no lock found or compatible lock exists: just make sure the file itself exists
  try:
    filestat = storage.stat(endpoint, filename, Wopi.lockruid, Wopi.lockrgid)
  except IOError as e:
    Wopi.log.warning('msg="cboxLock: file to be locked not found" filename="%s"' % filename)
    return 'File not found', http.client.NOT_FOUND

  # Now create a LibreOffice-compatible lock
  # TODO once OnlyOffice supports locking, we should create an OnlyOffice-compatible lock here (cf. CERNBOX-1051)
  try:
    if not query:
      locontent = ',OnlyOffice Online Editor,%s,%s,ExtWebApp;' % \
           (Wopi.wopiurl, time.strftime('%d.%m.%Y %H:%M', time.localtime(time.time())))
      storage.writefile(endpoint, utils.getLibreOfficeLockName(filename), Wopi.lockruid, Wopi.lockrgid, locontent, 1)
      Wopi.log.info('msg="cboxLock: created LibreOffice-compatible lock file" filename="%s"' % filename)
    if query and filestat['mtime'] > lockstat['mtime']:
      # we were asked to query an existing lock, but the file was modified in between (e.g. by a sync client):
      # notify potential conflict
      Wopi.log.info('msg="cboxLock: file got modified after LibreOffice-compatible lock file was created" ' \
                    'filename="%s"' % filename)
      return 'File modified since open time', http.client.CONFLICT
    return 'OK', http.client.OK
  except IOError as e:
    Wopi.log.error('msg="cboxLock: unable to store a LibreOffice-compatible lock" filename="%s" reason="%s"' % \
                   (filename, e))
    # return failure, though the caller should just try and go ahead
    return 'Error locking file', http.client.INTERNAL_SERVER_ERROR


@Wopi.app.route("/wopi/cbox/unlock", methods=['POST'])
def cboxUnlock():
  '''Unlock a given filename. Used for OnlyOffice as they do not use WOPI (see cboxLock).
  Request arguments:
  - string filename: the full path of the filename to be opened
  - string endpoint (optional): the storage endpoint to be used to look up the file, in case of
    multi-instance underlying storage; defaults to 'default'
  The call returns:
  - HTTP UNAUTHORIZED (401) if the 'Authorization: Bearer' secret is not provided in the header (cf. /wopi/cbox/open)
  - HTTP CONFLICT (409) if a lock exists, but held by another application
  - HTTP NOT_FOUND (404) if no lock was found for the given file
  - HTTP INTERNAL_ERROR (500) if some other I/O error occurred with the given lock file
  - HTTP OK (200) if a lock for OnlyOffice existed. In this case it is removed.
  '''
  req = flask.request
  # first check if the shared secret matches ours
  if 'Authorization' not in req.headers or req.headers['Authorization'] != 'Bearer ' + Wopi.iopsecret:
    Wopi.log.warning('msg="cboxUnlock: unauthorized access attempt, missing authorization token" ' \
                     'client="%s"' % req.remote_addr)
    return 'Client not authorized', http.client.UNAUTHORIZED
  filename = req.args['filename']
  endpoint = req.args['endpoint'] if 'endpoint' in req.args else 'default'
  try:
    # probe if a WOPI/LibreOffice lock exists with the expected signature
    lock = str(next(storage.readfile(endpoint, utils.getLibreOfficeLockName(filename), Wopi.lockruid, Wopi.lockrgid)))
    if 'OnlyOffice Online Editor' in lock:
      # remove the LibreOffice-compatible lock file
      storage.removefile(endpoint, utils.getLibreOfficeLockName(filename), Wopi.lockruid, Wopi.lockrgid, 1)
      Wopi.log.info('msg="cboxUnlock: successfully removed LibreOffice-compatible lock file" filename="%s"' % filename)
      return 'OK', http.client.OK
    if 'ERROR on read' in lock:
      # typically ENOENT, any other error is grouped here
      Wopi.log.warning('msg="cboxUnlock: lock file not found" filename="%s"' % filename)
      return 'Lock not found', http.client.NOT_FOUND
    # else another lock exists
    Wopi.log.info('msg="cboxUnlock: lock file held by another application" filename="%s"' % filename)
    return 'Lock held by another application', http.client.CONFLICT
  except IOError as e:
    Wopi.log.error('msg="cboxUnlock: I/O error with the requested LibreOffice-compatible lock" filename="%s" reason="%s"' % \
                   (filename, e))
    # return failure
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
    if acctok['exp'] < time.time():
      raise jwt.exceptions.ExpiredSignatureError
    Wopi.log.info('msg="CheckFileInfo" user="%s:%s" filename="%s" fileid="%s" token="%s"' % \
                  (acctok['ruid'], acctok['rgid'], acctok['filename'], fileid, flask.request.args['access_token'][-20:]))
    statInfo = storage.statx(acctok['endpoint'], acctok['filename'], acctok['ruid'], acctok['rgid'])
    # compute some entities for the response
    wopiSrc = 'WOPISrc=%s&access_token=%s' % (utils.generateWopiSrc(fileid), flask.request.args['access_token'])
    fExt = os.path.splitext(acctok['filename'])[1]
    # populate metadata for this file
    filemd = {}
    filemd['BaseFileName'] = filemd['BreadcrumbDocName'] = os.path.basename(acctok['filename'])
    if acctok['extlock']:
      # an external lock was found: let's somehow tell the user that the file is forced readonly
      # note that we strip the extension, otherwise Office would strip it (along with our comment!)
      filemd['BreadcrumbDocName'] = os.path.splitext(filemd['BaseFileName'])[0] + ' (locked by another app)'
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
    # the following is to enable the 'Edit in Word/Excel/PowerPoint' (desktop) action (probably broken)
    try:
      filemd['ClientUrl'] = Wopi.config.get('general', 'webdavurl') + '/' + acctok['filename']
    except configparser.NoOptionError:
      # if no WebDAV URL is provided, ignore this setting
      pass
    filemd['OwnerId'] = statInfo['ouid'] + ':' + statInfo['ogid']
    filemd['UserId'] = acctok['ruid'] + ':' + acctok['rgid']    # typically same as OwnerId
    filemd['Size'] = statInfo['size']
    filemd['Version'] = statInfo['mtime']   # mtime is used as version here
    filemd['LastModifiedTime'] = datetime.fromtimestamp(int(statInfo['mtime'])).isoformat()   # this is used by Collabora
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
    return utils.logGeneralExceptionAndReturn(e, flask.request)


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
    return utils.logGeneralExceptionAndReturn(e, flask.request)


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
    storage.removefile(acctok['endpoint'], utils.getLockName(acctok['filename']), Wopi.lockruid, Wopi.lockrgid, 1)
  except IOError:
    # ignore, it's not worth to report anything here
    pass
  try:
    storage.rmxattr(acctok['endpoint'], acctok['filename'], acctok['ruid'], acctok['rgid'], LASTSAVETIMEKEY)
  except IOError:
    # same as above
    pass
  try:
    # also remove the LibreOffice-compatible lock file
    storage.removefile(acctok['endpoint'], utils.getLibreOfficeLockName(acctok['filename']), Wopi.lockruid, Wopi.lockrgid, 1)
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
    Wopi.log.warning('msg="Lock: BLINDLY removed the existing lock to unblock client" op="%s" user="%s:%s" '\
                     'filename="%s" token="%s"' % \
                     (op, acctok['ruid'], acctok['rgid'], acctok['filename'], \
                      flask.request.args['access_token'][-20:]))
  # LOCK or REFRESH_LOCK: set the lock to the given one, including the expiration time
  utils.storeWopiLock(op, lock, acctok)
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


def wopiGetLock(fileid, _reqheaders_unused, acctok):
  '''Implements the GetLock WOPI call'''
  resp = flask.Response()
  # throws exception if no lock
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
  # else:
  # TODO check if a non-WOPI lock exists for this file
  return resp


def wopiPutRelative(fileid, reqheaders, acctok):
  '''Implements the PutRelative WOPI call. Corresponds to the 'Save as...' menu entry.'''
  # cf. http://wopi.readthedocs.io/projects/wopirest/en/latest/files/PutRelativeFile.html
  suggTarget = reqheaders['X-WOPI-SuggestedTarget'] if 'X-WOPI-SuggestedTarget' in reqheaders else ''
  relTarget = reqheaders['X-WOPI-RelativeTarget'] if 'X-WOPI-RelativeTarget' in reqheaders else ''
  overwriteTarget = 'X-WOPI-OverwriteRelativeTarget' in reqheaders and bool(reqheaders['X-WOPI-OverwriteRelativeTarget'])
  Wopi.log.info('msg="PutRelative" user="%s:%s" filename="%s" fileid="%s" suggTarget="%s" relTarget="%s" '
                'overwrite="%r" token="%s"' % \
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
        # we got another error with this file, fail
        Wopi.log.info('msg="PutRelative" user="%s:%s" filename="%s" token="%s" suggTarget="%s" error="%s"' % \
                      (acctok['ruid'], acctok['rgid'], targetName, flask.request.args['access_token'][-20:], \
                       suggTarget, str(e)))
        return 'Illegal filename %s: %s' % (targetName, e), http.client.BAD_REQUEST
  else:
    # the relative target is a filename to be respected, and that may overwrite an existing file
    relTarget = os.path.dirname(acctok['filename']) + os.path.sep + relTarget    # make full path
    try:
      # check for file existence + lock
      fileExists = retrievedLock = False
      fileExists = storage.stat(acctok['endpoint'], relTarget, acctok['ruid'], acctok['rgid'])
      retrievedLock = storage.stat(acctok['endpoint'], utils.getLockName(relTarget), Wopi.lockruid, Wopi.lockrgid)
    except IOError:
      pass
    if fileExists and (not overwriteTarget or retrievedLock):
      return utils.makeConflictResponse('PUTRELATIVE', retrievedLock, '', '', relTarget)
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
  Wopi.log.info('msg="PutRelative: generating new access token" user="%s:%s" filename="%s" canedit="True" friendlyname="%s"' % \
                (acctok['ruid'], acctok['rgid'], targetName, acctok['username']))
  inode, newacctok = utils.generateAccessToken(acctok['ruid'], acctok['rgid'], targetName, True, acctok['username'], \
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
    storage.removefile(acctok['endpoint'], acctok['filename'], acctok['ruid'], acctok['rgid'])
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
    Wopi.log.info('msg="RenameFile" user="%s:%s" filename="%s" token="%s" targetname="%s"' % \
                  (acctok['ruid'], acctok['rgid'], acctok['filename'], flask.request.args['access_token'][-20:], targetName))
    storage.renamefile(acctok['endpoint'], acctok['filename'], targetName, acctok['ruid'], acctok['rgid'])
    # also rename the locks
    storage.renamefile(acctok['endpoint'], utils.getLockName(acctok['filename']), utils.getLockName(targetName), \
                       Wopi.lockruid, Wopi.lockrgid)
    storage.renamefile(acctok['endpoint'], utils.getLibreOfficeLockName(acctok['filename']), \
                       utils.getLibreOfficeLockName(targetName), Wopi.lockruid, Wopi.lockrgid)
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
    utils.storeWopiFile(flask.request, acctok, LASTSAVETIMEKEY)
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
    if op != 'GET_LOCK' and not acctok['canedit']:
      # protect this call if the WOPI client does not have privileges
      return 'Attempting to perform a write operation using a read-only token', http.client.UNAUTHORIZED
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
    return utils.logGeneralExceptionAndReturn(e, flask.request)


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
      return utils.makeConflictResponse('PUTFILE', retrievedLock, lock, '', acctok['filename'])
    # OK, we can save the file now
    Wopi.log.info('msg="PutFile" user="%s:%s" filename="%s" fileid="%s" action="edit" token="%s"' % \
                  (acctok['ruid'], acctok['rgid'], acctok['filename'], fileid, flask.request.args['access_token'][-20:]))
    try:
      # check now the destination file against conflicts
      savetime = int(storage.getxattr(acctok['endpoint'], acctok['filename'], acctok['ruid'], acctok['rgid'], LASTSAVETIMEKEY))
      # we got our xattr: if mtime is greater, someone may have updated the file from a different source (e.g. FUSE or SMB mount)
      mtime = storage.stat(acctok['endpoint'], acctok['filename'], acctok['ruid'], acctok['rgid'])['mtime']
      if int(mtime) > int(savetime):
        # this is the case, force conflict. Note we can't get a time resolution better than one second!
        Wopi.log.info('msg="Forcing conflict based on lastWopiSaveTime" user="%s:%s" filename="%s" token="%s" ' \
                      'savetime="%ld" lastmtime="%ld"' % \
                      (acctok['ruid'], acctok['rgid'], acctok['filename'], \
                       flask.request.args['access_token'][-20:], savetime, mtime))
        raise IOError
      Wopi.log.info('msg="Got lastWopiSaveTime" user="%s:%s" filename="%s" token="%s" savetime="%ld" lastmtime="%ld"' % \
                    (acctok['ruid'], acctok['rgid'], acctok['filename'], \
                     flask.request.args['access_token'][-20:], savetime, mtime))
    except IOError:
      # either the file was deleted or it was updated/overwritten by others: force conflict
      newname, ext = os.path.splitext(acctok['filename'])
      # !!! typical EFSS formats are like '<filename>_conflict-<date>-<time>', but they're not synchronized back !!!
      newname = '%s-conflict-%s%s' % (newname, time.strftime('%Y%m%d-%H%M%S'), ext.strip())
      utils.storeWopiFile(flask.request, acctok, LASTSAVETIMEKEY, newname)
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
    # but the previous check still gives the opportunity of a race condition. We just live with it.
    # Anyhow, the EFSS should support versioning for such cases.
    utils.storeWopiFile(flask.request, acctok, LASTSAVETIMEKEY)
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
    return utils.logGeneralExceptionAndReturn(e, flask.request)


#
# Start the Flask endless listening loop if started in standalone mode
#
if __name__ == '__main__':
  Wopi.init()
  Wopi.initappsregistry()
  Wopi.run()
