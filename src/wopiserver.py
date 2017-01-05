#!/bin/python
#
# wopiserver.py
#
# Initial prototype for a Web-application Open Platform Interface (WOPI) gateway for CERNBox
#
# Giuseppe.LoPresti@cern.ch

import sys, os, time, json, httplib
import logging.handlers
import logging
try:
  import flask                  # Flask app server, python-flask-0.10.1-4.el7.noarch.rpm + pyOpenSSL-0.13.1-3.el7.x86_64.rpm
  import jwt                    # PyJWT Jason Web Token, python-jwt-1.4.0-2.el7.noarch.rpm
  from xrootiface import XrdCl  # a wrapper for the xrootd python bindings, xrootd-python-4.4.x.el7.x86_64.rpm
except:
  print "Missing modules, please install xrootd-python, python-flask, python-jwt"
  sys.exit(-1)

# prepare the Flask web app
app = flask.Flask("WOPIServer")
log = app.logger
log.setLevel(logging.DEBUG)
log.addHandler(logging.FileHandler('/var/tmp/wopiserver.log'))    # XXX todo put in a proper place
wopisecret = 'wopisecret'                          # XXX todo read secret from config file
tokenvalidity = 86400                              # XXX todo read from config file


# The Web Application starts here
@app.route("/")
def index():
  log.info('msg="Accessed root page" client="%s"' % flask.request.remote_addr)
  return "This is the CERNBox WOPI server. Access is performed via REST API, see <a href=http://wopi.readthedocs.io>http://wopi.readthedocs.io</a>."


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
    log.info('msg="CheckFileInfo" username="%s" filename"%s" fileid="%s"' % (acctok['username'], acctok['filename'], fileid))
    statInfo = XrdCl(log, acctok['filename']).stat()
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


@app.route("/api/wopi/files/<fileid>/contents", methods=['GET'])
def wopiGetFile(fileid):
  try:
    acctok = jwt.decode(flask.request.args['access_token'], wopisecret, algorithms=['HS256'])
    if acctok['exp'] < time.time():
      raise jwt.exceptions.DecodeError
    log.info('msg="GetFile" username="%s" filename="%s" fileid="%s"' % (acctok['username'], acctok['filename'], fileid))
    # stream file from storage to client
    resp = flask.Response(XrdCl(log, acctok['filename']).readFile(), mimetype='application/octet-stream')
    resp.headers['X-WOPI-ItemVersion'] = '1.0'   # XXX todo get version from server
    return resp
  except jwt.exceptions.DecodeError:
    log.warning('msg="Signature verification failed" token="%s"' % flask.request.args['access_token'])
    return 'Invalid access token', httplib.UNAUTHORIZED
  except Exception, e:
    log.error('msg="Unexpected exception caught" exception="%s"' % e)
    log.debug(sys.exc_info())
    return 'Internal error', httplib.INTERNAL_SERVER_ERROR


@app.route("/api/wopi/files/<fileid>", methods=['POST'])
def wopiLockUnlock(fileid):
  try:
    acctok = jwt.decode(flask.request.args['access_token'], wopisecret, algorithms=['HS256'])
    if acctok['exp'] < time.time():
      raise jwt.exceptions.DecodeError
    headers = flask.request.headers
    if('X-WOPI-Override' not in headers or 'X-WOPI-Lock' not in headers):
      return 'X-WOPI-Override or X-WOPI-Lock missing from the headers', httplib.BAD_REQUEST
    op = headers['X-WOPI-Override']   # must be one of LOCK, UNLOCK, REFRESH_LOCK
    if op not in ('LOCK', 'UNLOCK', 'REFRESH_LOCK'):
      return 'Lock operation %s not supported' % op, httplib.BAD_REQUEST
    lock = headers['X-WOPI-Lock']
    log.info('msg="%s" username="%s" filename="%s" lock="%s"' % (op.title(), acctok['username'], acctok['filename'], lock))
    return 'OK', httplib.OK
  except jwt.exceptions.DecodeError:
    log.warning('msg="Signature verification failed" token="%s"' % flask.request.args['access_token'])
    return 'Invalid access token', httplib.UNAUTHORIZED
  except Exception, e:
    log.error('msg="Unexpected exception caught" exception="%s"' % e)
    log.debug(sys.exc_info())
    return 'Internal error', httplib.INTERNAL_SERVER_ERROR


@app.route("/api/wopi/files/<fileid>/contents", methods=['POST'])
def wopiPostContent(fileid):
  try:
    acctok = jwt.decode(flask.request.args['access_token'], wopisecret, algorithms=['HS256'])
    if acctok['exp'] < time.time():
      raise jwt.exceptions.DecodeError
    log.info('msg="PostContent" username="%s" filename="%s"' % (acctok['username'], acctok['filename']))
    XrdCl(log, acctok['filename']).writeFile(flask.request.get_data())
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


app.run(host='0.0.0.0', port=8080, threaded=True, debug=True) #, ssl_context=('wopicert.crt', 'wopikey.key'))
