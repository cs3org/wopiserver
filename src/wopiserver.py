#!/bin/python
#
# wopiserver.py
#
# Initial prototype for a Web-application Open Platform Interface (WOPI) gateway for CERNBox
#
# Giuseppe.LoPresti@cern.ch

import sys, os, time, json
import logging.handlers
import logging
try:
  from XRootD import client as XrdClient   # the xroot bindings for python, xrootd-python-4.4.1-1.el7.x86_64.rpm
  from XRootD.client.flags import OpenFlags
  import flask                             # Flask app server, python-flask-0.10.1-4.el7.noarch.rpm + pyOpenSSL-0.13.1-3.el7.x86_64.rpm
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
tokenvalidity = 86400                              # XXX todo read from config file

# some xrootd useful wrappers
# XXX make a class/module out of this
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
      log.info('msg="Error opening the file for read" filename="%s" error="%s"' % (filename, rc.message))
      yield rc.message
    else:
      # the actual read is buffered and managed by the Flask server
      for chunk in f.readchunks(offset=0, chunksize=chunksize):
        yield chunk

def writeXRootFile(filename, content):
  f = XrdClient.File()
  # pass in the URL a special flag to enable the EOS atomic overwrite like the OwnCloud server
  rc, _statInfo_unused = f.open(storageserver + '/' + homedir + filename, OpenFlags.DELETE)   # overwrite previous version
  if rc.ok == False:
    log.info('msg="Error opening the file for write" filename="%s" error="%s"' % (filename, rc.message))
    raise IOError(rc.message)
  # XXX write the entire file - we should find a way to only update the required chunks...
  rc, _statInfo_unused = f.write(content, offset=0)
  if rc.ok == False:
    log.info('msg="Error writing the file" filename="%s" error="%s"' % (filename, rc.message))
    raise IOError(rc.message)
  rc, _statInfo_unused = f.close()
  if rc.ok == False:
    log.info('msg="Error closing the file" filename="%s" error="%s"' % (filename, rc.message))
    raise IOError(rc.message)


# The Web Application starts here
@app.route("/")
def index():
  log.info('msg="Accessed root page" client="%s"' % flask.request.remote_addr)
  return "This is the CERNBox WOPI server: access is performed via REST API, e.g. GET /api/wopi/files/fileid\n"


@app.route("/wopiopen", methods=['GET'])
def wopiopen():
  req = flask.request
  username = req.args['username']
  filename = req.args['filename']
  canedit = ('canedit' in req.args and req.args['canedit'] == 'yes')
  acctok = jwt.encode({'username': username, 'filename': filename, 'canedit': canedit, 'exp': (int(time.time())+tokenvalidity)},
                      wopisecret, algorithm='HS256')
  log.info('msg="Access token set" client="%s" user="%s" filename="%s" token="%s"' % (flask.request.remote_addr, username, filename, acctok))
  return acctok


@app.route("/api/wopi/files/<fileid>", methods=['GET'])
def wopiCheckFileInfo(fileid):
  try:
    acctok = jwt.decode(flask.request.args['access_token'], wopisecret, algorithms=['HS256'])
    if acctok['exp'] < time.time():
      raise jwt.exceptions.DecodeError
    log.info('msg="GET metadata" username="%s" filename"%s" fileid="%s"' % (acctok['username'], acctok['filename'], fileid))
    statInfo = statXRootFile(acctok['filename'])
    # populate metadata for this file
    md = {}
    md['BaseFileName'] = os.path.basename(acctok['filename'])
    md['OwnerId'] = acctok['username']                      # XXX todo get owner uid
    md['UserId'] = acctok['username']
    md['Size'] = statInfo.size                              # XXX todo check this is < request.headers['X-WOPI-MaxExpectedSize']
    md['Version'] = statInfo.modtimestr
    md['SupportsUpdate'] = md['UserCanWrite'] = md['SupportsLocks'] = acctok['canedit']
    # send it in JSON format
    resp = flask.Response(json.dumps(md), mimetype='application/json')
    return resp
  except jwt.exceptions.DecodeError:
    log.warning('msg="Signature verification failed" token="%s"' % flask.request.args['access_token'])
    return 'Invalid access token', 401
  except IOError, e:
    log.info('msg="Requested file not found" filename="%s" error="%s"' % (acctok['filename'], e))
    return 'File not found', 404
  except Exception, e:
    log.error('msg="Unexpected exception caught" exception="%s"' % e)
    log.debug(sys.exc_info())
    return 'Internal error', 500


@app.route("/api/wopi/files/<fileid>/contents", methods=['GET'])
def wopiGetFile(fileid):
  try:
    acctok = jwt.decode(flask.request.args['access_token'], wopisecret, algorithms=['HS256'])
    if acctok['exp'] < time.time():
      raise jwt.exceptions.DecodeError
    log.info('msg="GET content" username="%s" filename="%s" fileid="%s"' % (acctok['username'], acctok['filename'], fileid))
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
    if acctok['exp'] < time.time():
      raise jwt.exceptions.DecodeError
    log.info('msg="POST content" username="%s" filename="%s"' % (acctok['username'], acctok['filename']))
    writeXRootFile(acctok['filename'], flask.request.get_data())
    return 'OK', 200
  except jwt.exceptions.DecodeError:
    log.warning('msg="Signature verification failed" token="%s"' % flask.request.args['access_token'])
    return 'Invalid access token', 401
  except IOError, e:
    log.info('msg="Error writing file" filename="%s" error="%s"' % (acctok['filename'], e))
    return 'I/O Error', 500
  except Exception, e:
    log.error('msg="Unexpected exception caught" exception="%s"' % e)
    log.debug(sys.exc_info())
    return 'Internal error', 500


app.run(host='0.0.0.0', port=8080, threaded=True, debug=True) #, ssl_context=('wopicert.crt', 'wopikey.key'))
