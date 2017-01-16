#!/bin/python
#
# wopiserver.py
#
# Initial prototype for a Web-application Open Platform Interface (WOPI) gateway for CERNBox
#
# Giuseppe.LoPresti@cern.ch

import sys, os, time, socket, ConfigParser, platform
import urllib, httplib, json
import logging.handlers
import logging
try:
  import flask                 # Flask app server, python-flask-0.10.1-4.el7.noarch.rpm + pyOpenSSL-0.13.1-3.el7.x86_64.rpm
  import jwt                   # PyJWT Jason Web Token, python-jwt-1.4.0-2.el7.noarch.rpm
  import xrootiface as xrdcl   # a wrapper around the xrootd python bindings, xrootd-python-4.4.x.el7.x86_64.rpm
except:
  print "Missing modules, please install xrootd-python, python-flask, python-jwt"
  sys.exit(-1)

# the following constant is replaced on the fly when generating the RPM (cf. spec file)
WOPISERVERVERSION = 'git'

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
  loghandler = logging.FileHandler(config.get('general', 'logfile'))
  loghandler.setFormatter(logging.Formatter(fmt='%(asctime)s %(name)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%dT%H:%M:%S'))
  log.addHandler(loghandler)
  wopisecret = open(config.get('security', 'secretfile')).read()
  tokenvalidity = config.getint('general', 'tokenvalidity')
  xrdcl.init(config, log)                          # initialize the xroot client module
  config.get('general', 'allowedclients')          # read this to make sure it is configured
except Exception, e:
  # any error we got here with the configuration is fatal
  log.critical('msg="Failed to read config, bailing out" error=%s' % e)
  sys.exit(-1)


def doWopiOpen(req):
  '''Generate an access token for a given file of a given user, and returns a URL-encoded string
  suitable to be passed as a WOPISrc value to a Microsoft Office Online server.
  Access to this function is protected by source IP address.'''
  ruid = req.args['ruid']
  rgid = req.args['rgid']
  filename = req.args['filename']
  canedit = ('canedit' in req.args and req.args['canedit'].lower() == 'yes')
  try:
    # stat now the file to check for existence and handle sync conflicts afterwards
    statx = xrdcl.statx(filename, ruid, rgid)
    inode = statx[2]
    mtime = statx[12]
  except IOError, e:
    log.info('msg="Requested file not found" filename="%s" error="%s"' % (filename, e))
    return 'File not found', httplib.NOT_FOUND
  acctok = jwt.encode({'ruid': ruid, 'rgid': rgid, 'filename': filename, 'canedit': canedit, 'mtime': mtime,
                      'exp': (int(time.time())+tokenvalidity)}, wopisecret, algorithm='HS256')
  log.info('msg="Access token set" host="%s" user="%s:%s" filename="%s" canedit="%r" inode="%s" token="%s"' % \
           (req.remote_addr, ruid, rgid, filename, canedit, inode, acctok))
  # generate and return an URL-encoded URL for the Office Online server
  return urllib.quote_plus('http://%s:8080/wopi/files/%s' % (socket.gethostname(), inode)) + '&access_token=%s' %  urllib.quote_plus(acctok)


def refreshConfig():
  '''re-read the configuration file every 300 secs to catch any runtime parameter change'''
  global lastConfigReadTime
  if time.time() > lastConfigReadTime + 300:
    lastConfigReadTime = time.time()
    config.read('/etc/wopi/wopiserver.conf')
    # refresh some general parameters
    tokenvalidity = config.getint('general', 'tokenvalidity')
    log.setLevel(_loglevels[config.get('general', 'loglevel')])


# The Web Application starts here
@app.route("/")
def index():
  log.info('msg="Accessed root page" client="%s"' % flask.request.remote_addr)
  return """
    <div align="center" style="color:#000080; padding-top:50px; font-family:Verdana; size:11">This is the CERNBox <a href=http://wopi.readthedocs.io>WOPI</a> server for Microsoft Office Online.
    To use this service, please log in to your <a href=https://cernbox.cern.ch>CERNBox</a> account and click on the Open button next to your Microsoft Office documents.</div>
    <br><br><br><br><br><br><br><br><br><br><hr>
    <i>CERNBox WOPI Server %s. Powered by Flask %s for Python %s</i>.
    """ % (WOPISERVERVERSION, flask.__version__, platform.python_version())


@app.route("/wopi/cboxopen", methods=['GET'])
def wopiOpen():
  refreshConfig()
  # first resolve the client: only our OwnCloud servers shall use this API
  allowedclients = config.get('general', 'allowedclients').split()
  for c in allowedclients:
    for ip in socket.getaddrinfo(c, None):
      if ip[4][0] == flask.request.remote_addr:
        # we got a match, go for the open and generate the access token
        return doWopiOpen(flask.request)
  # no match found, fail
  log.info('msg="Unauthorized access attempt" client="%s"' % flask.request.remote_addr)
  return 'Client IP not authorized', httplib.UNAUTHORIZED


@app.route("/wopi/files/<fileid>", methods=['GET'])
def wopiCheckFileInfo(fileid):
  refreshConfig()
  try:
    acctok = jwt.decode(flask.request.args['access_token'], wopisecret, algorithms=['HS256'])
    if acctok['exp'] < time.time():
      raise jwt.exceptions.DecodeError
    log.info('msg="CheckFileInfo" user="%s:%s" filename"%s" fileid="%s" WopiSession="%s"' % \
             (acctok['ruid'], acctok['rgid'], acctok['filename'], fileid, flask.request.headers['X-WOPI-Session'] if 'X-WOPI-Session' in flask.request.headers else 'N/A'))
    statInfo = xrdcl.statx(acctok['filename'], acctok['ruid'], acctok['rgid'])
    # populate metadata for this file
    md = {}
    md['BaseFileName'] = os.path.basename(acctok['filename'])
    md['OwnerId'] = statInfo[5] + ':' + statInfo[6]
    md['UserId'] = acctok['ruid'] + ':' + acctok['rgid']
    md['Size'] = statInfo[8]
    md['Version'] = statInfo[12]
    md['SupportsUpdate'] = md['UserCanWrite'] = md['SupportsLocks'] = acctok['canedit']
    # send it in JSON format
    resp = flask.Response(json.dumps(md), mimetype='application/json')
    return resp
  except jwt.exceptions.DecodeError:
    log.warning('msg="Signature verification failed" token="%s"' % flask.request.args['access_token'])
    return 'Invalid access token', httplib.UNAUTHORIZED
  except IOError, e:
    log.info('msg="Requested file not found" filename="%s" error="%s"' % (acctok['filename'], e))
    return 'File not found', httplib.NOT_FOUND
  except KeyError, e:
    log.error('msg="Invalid access token, missing %s field"' % e)
    return 'Invalid access token', httplib.UNAUTHORIZED
  except Exception, e:
    log.error('msg="Unexpected exception caught" exception="%s"' % e)
    log.debug(sys.exc_info())
    return 'Internal error', httplib.INTERNAL_SERVER_ERROR


@app.route("/wopi/files/<fileid>/contents", methods=['GET'])
def wopiGetFile(fileid):
  refreshConfig()
  try:
    acctok = jwt.decode(flask.request.args['access_token'], wopisecret, algorithms=['HS256'])
    if acctok['exp'] < time.time():
      raise jwt.exceptions.DecodeError
    log.info('msg="GetFile" user="%s:%s" filename="%s" fileid="%s"' % (acctok['ruid'], acctok['rgid'], acctok['filename'], fileid))
    # stream file from storage to client
    resp = flask.Response(xrdcl.readFile(acctok['filename'], acctok['ruid'], acctok['rgid']), mimetype='application/octet-stream')
    resp.headers['X-WOPI-ItemVersion'] = acctok['mtime']
    return resp
  except jwt.exceptions.DecodeError:
    log.warning('msg="Signature verification failed" token="%s"' % flask.request.args['access_token'])
    return 'Invalid access token', httplib.UNAUTHORIZED
  except Exception, e:
    log.error('msg="Unexpected exception caught" exception="%s"' % e)
    log.debug(sys.exc_info())
    return 'Internal error', httplib.INTERNAL_SERVER_ERROR


# the following operations are all called on POST /wopi/files/<fileid>

def wopiLockUnlock(fileid, reqheaders, acctok):
  lock = reqheaders['X-WOPI-Lock']
  log.info('msg="%s" user="%s:%s" filename="%s" lock="%s"' % \
           (reqheaders['X-WOPI-Override'].title(), acctok['ruid'], acctok['rgid'], acctok['filename'], lock))
  return 'OK', httplib.OK

def wopiGetLock(fileid, reqheaders, acctok):
  log.info('msg="GetLock" user="%s:%s" filename="%s"' % (acctok['ruid'], acctok['rgid'], acctok['filename']))
  return 'Not supported', httplib.NOT_IMPLEMENTED

def wopiPutRelative(fileid, reqheaders, acctok):
  log.info('msg="PutRelative" user="%s:%s" filename="%s"' % (acctok['ruid'], acctok['rgid'], acctok['filename']))
  return 'Not supported', httplib.NOT_IMPLEMENTED

def deleteFile(fileid, reqheaders, acctok):
  log.info('msg="DeleteFile" user="%s:%s" filename="%s"' % (acctok['ruid'], acctok['rgid'], acctok['filename']))
  return 'Not supported', httplib.NOT_IMPLEMENTED

def renameFile(fileid, reqheaders, acctok):
  log.info('msg="RenameFile" user="%s:%s" filename="%s"' % (acctok['ruid'], acctok['rgid'], acctok['filename']))
  return 'Not supported', httplib.NOT_IMPLEMENTED

@app.route("/wopi/files/<fileid>", methods=['POST'])
def wopiPost(fileid):
  refreshConfig()
  try:
    acctok = jwt.decode(flask.request.args['access_token'], wopisecret, algorithms=['HS256'])
    if acctok['exp'] < time.time():
      raise jwt.exceptions.DecodeError
    headers = flask.request.headers
    op = headers['X-WOPI-Override']       # must be one of the following strings, throws KeyError if missing
    if op in ('LOCK', 'UNLOCK', 'REFRESH_LOCK'):
      return wopiLockUnlock(fileid, headers, acctok)
    elif op == 'GET_LOCK':
      return wopiGetLock(fileid, headers, acctok)
    elif op == 'PUT_RELATIVE':
      return wopiPutRelative(fileid, headers, acctok)
    elif op == 'DELETE_FILE':
      return wopiDeleteFile(fileid, headers, acctok)
    elif op == 'RENAME_FILE':
      return wopiRenameFile(fileid, headers, acctok)
    else:
      return 'Unknown operation %s found in header' % op, httplib.BAD_REQUEST
  except jwt.exceptions.DecodeError:
    log.warning('msg="Signature verification failed" token="%s"' % flask.request.args['access_token'])
    return 'Invalid access token', httplib.UNAUTHORIZED
  except KeyError, e:
    return 'Missing header %s in POST request' % e, httplib.BAD_REQUEST
  except Exception, e:
    log.error('msg="Unexpected exception caught" exception="%s"' % e)
    log.debug(sys.exc_info())
    return 'Internal error', httplib.INTERNAL_SERVER_ERROR


@app.route("/wopi/files/<fileid>/contents", methods=['POST'])
def wopiPutFile(fileid):
  refreshConfig()
  try:
    acctok = jwt.decode(flask.request.args['access_token'], wopisecret, algorithms=['HS256'])
    if acctok['exp'] < time.time():
      raise jwt.exceptions.DecodeError
    log.info('msg="PostContent" user="%s:%s" filename="%s"' % (acctok['ruid'], acctok['rgid'], acctok['filename']))
    # check the destination file now against conflicts
    try:
      mtime = xrdcl.stat(acctok['filename'], acctok['ruid'], acctok['rgid']).modtime
    except IOError:
      # the file got deleted meanwhile: force a conflict
      mtime = time.time()
    if mtime > int(acctok['mtime']):
      # someone else overwrote the file before us: we must therefore create a new conflict file
      newname, ext = os.path.splitext(acctok['filename'])
      newname = '%s_conflict-%s%s' % (newname, time.strftime('%Y%m%d-%H%M%S'), ext.strip())   # this is the OwnCloud format
      xrdcl.writeFile(newname, acctok['ruid'], acctok['rgid'], flask.request.get_data())
      log.info('msg="Conflicting copy found" user="%s:%s" filename="%s"' % (acctok['ruid'], acctok['rgid'], newname))
      return 'Conflicting copy found, mtime = %d' % mtime, httplib.PRECONDITION_FAILED    # return a failure so that the user can check
    else:
      # OK, nobody overwrote the file: attempt to overwrite it.
      # XXX Note that the entire check+write operation should be atomic, but the previous check
      # XXX still gives the opportunity of a race condition. For the time being we just live with it...
      xrdcl.writeFile(acctok['filename'], acctok['ruid'], acctok['rgid'], flask.request.get_data())
      log.info('msg="File successfully written" user="%s:%s" filename="%s"' % (acctok['ruid'], acctok['rgid'], acctok['filename']))
      return 'OK', httplib.OK
  except jwt.exceptions.DecodeError:
    log.warning('msg="Signature verification failed" token="%s"' % flask.request.args['access_token'])
    return 'Invalid access token', httplib.UNAUTHORIZED
  except IOError, e:
    log.info('msg="Error writing file" filename="%s" error="%s"' % (acctok['filename'], e))
    return 'I/O Error', httplib.INTERNAL_SERVER_ERROR
  except Exception, e:
    log.error('msg="Unexpected exception caught" exception="%s"' % e)
    log.debug(sys.exc_info())
    return 'Internal error', httplib.INTERNAL_SERVER_ERROR


app.run(host='0.0.0.0', port=8080, threaded=True, debug=(config.get('general', 'loglevel') == 'Debug'))
# XXX todo: enable https and then add:    ssl_context=(config.get('security', 'wopicert'), config.get('security', 'wopikey')))
