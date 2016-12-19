#!/bin/python
#
# wopiserver.py
#
# Initial prototype for a Web-application Open Platform Interface (WOPI) gateway for CERNBox
#
# Giuseppe.LoPresti@cern.ch

import sys, os, json
import logging.handlers
import logging
try:
  from XRootD import client as XrdClient   # the xroot bindings for python, xrootd-python-4.4.1-1.el7.x86_64.rpm
  from XRootD.client.flags import OpenFlags
  import flask                             # Flask app server, python-flask-0.10.1-4.el7.noarch.rpm
  import jwt                               # PyJWT Jason Web Token, python-jwt-1.4.0-2.el7.noarch.rpm
except:
  print "Missing modules, please install xrootd-python, python-flask, python-jwt"
  sys.exit(-1)

# prepare the Flask web app
app = flask.Flask("WOPIServer")
log = app.logger
log.setLevel(logging.DEBUG)
log.addHandler(logging.FileHandler('/var/tmp/wopiserver.log'))    # XXX todo put in a proper place
wopisecret = 'wopisecret'                          # XXX todo read secret from config file
# prepare the xroot client
storageserver = 'root://castorpps'                 # XXX todo read from config file
homedir = '/castor/cern.ch/user/i/itglp/'
xrdfs = XrdClient.FileSystem(storageserver)  
chunksize = 1048576                                # XXX todo read from config file

# some xrootd useful wrappers

def statXRootFile(filename):
  rc, statInfo = xrdfs.stat(homedir + filename)
  if statInfo is None:
    raise IOError(rc.message)
  return statInfo


def readXRootFile(filename):
  with XrdClient.File() as f:
    rc, _statInfo_unused = f.open(storageserver + '/' + homedir + filename, OpenFlags.READ)
    if rc.ok == False:
      # the file could not be opened: as this is a generator, we yield the error string instead of the file's contents
      log.info('msg="Requested file %s not found" error="%s"' % (filename, rc.message))
      yield rc.message
    else:
      # the actual read is buffered and managed by the Flask server
      for chunk in f.readchunks(offset=0, chunksize=chunksize):
        yield chunk


# The Web Application starts here
@app.route("/")
def index():
  log.info('msg="Accessed root page" client="%s"' % flask.request.remote_addr)
  return "This is the CERNBox WOPI server: access is performed via REST API, e.g. GET /api/wopi/files/fileid\n"


@app.route("/wopiopen", methods=['GET'])
def wopiopen():
  username = flask.request.args['username']
  filename = flask.request.args['filename']
  acctok = jwt.encode({'username': username, 'filename': filename}, wopisecret, algorithm='HS256')
  log.info('msg="Access token set" user="%s" filename="%s" token="%s"' % (username, filename, acctok))
  return acctok


@app.route("/api/wopi/files/<fileid>", methods=['GET'])
def wopiCheckFileInfo(fileid):
  try:
    acctok = jwt.decode(flask.request.args['access_token'], wopisecret, algorithms=['HS256'])
    log.info('msg="GET metadata" username="%s" filename"%s"' % (acctok['username'], acctok['filename']))
    md = {}
    statInfo = statXRootFile(acctok['filename'])
    md['BaseFileName'] = os.path.basename(acctok['filename'])
    md['OwnerId'] = acctok['username']                      # XXX todo get owner uid
    md['UserId'] = acctok['username']
    md['Size'] = statInfo.size                              # XXX todo check this is < request.headers['X-WOPI-MaxExpectedSize']
    md['Version'] = statInfo.modtimestr
    md['SupportsUpdate'] = md['UserCanWrite'] = md['SupportsLocks'] = True
    resp = flask.Response(json.dumps(md), mimetype='application/json')
    return resp
  except jwt.exceptions.DecodeError:
    log.warning('msg="Signature verification failed" token="%s"' % flask.request.args['access_token'])
    return 'Invalid access token', 401
  except IOError, e:
    log.info('msg="Requested file %s not found" error="%s"' % (acctok['filename'], e))
    return 'File not found', 404
  except Exception, e:
    log.error('msg="Unexpected exception caught" exception="%s"' % e)
    log.debug(sys.exc_info())
    return 'Internal error', 500


@app.route("/api/wopi/files/<fileid>/contents", methods=['GET'])
def wopiGetFile(fileid):
  try:
    acctok = jwt.decode(flask.request.args['access_token'], wopisecret, algorithms=['HS256'])
    log.info('msg="GET content" username="%s" filename="%s"' % (acctok['username'], acctok['filename']))
    # stream file from storage to client
    resp = flask.Response(readXRootFile(acctok['filename']), mimetype='application/octet-stream')
    resp.headers['X-WOPI-ItemVersion'] = '1.0'   # XXX todo get version from server
    return resp
  except jwt.exceptions.DecodeError:
    log.warning('msg="Signature verification failed" token="%s"' % flask.request.args['access_token'])
    return 'Invalid access token', 401
  except Exception, e:
    log.error('msg="Unexpected exception caught" exception="%s"' % e)
    log.debug(sys.exc_info())
    return 'Internal error', 500


@app.route("/api/wopi/files/<fileid>/contents", methods=['POST'])
def wopiPostContent(fileid):
  try:
    acctok = jwt.decode(flask.request.args['access_token'], wopisecret, algorithms=['HS256'])
    log.info("NOOP - POST content for file %s" % fileid)
  except jwt.exceptions.DecodeError:
    log.warning('msg="Signature verification failed" token="%s"' % flask.request.args['access_token'])
    return 'Invalid access token', 401
  except Exception, e:
    log.error('msg="Unexpected exception caught" exception="%s"' % e)
    log.debug(sys.exc_info())
    return 'Internal error', 500


app.run(host='0.0.0.0', port=8080)
