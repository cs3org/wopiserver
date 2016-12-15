#!/bin/python
#
# wopiserver.py
#
# Initial prototype for a Web-application Open Platform Interface (WOPI) gateway for CERNBox
#
# Giuseppe.LoPresti@cern.ch

import sys
import json
import logging.handlers
import logging
try:
  from XRootD import client as XrdClient   # the xroot bindings for python, xrootd-python-4.4.1-1.el7.x86_64.rpm
  import flask                             # Flask app server, python-flask-0.10.1-4.el7.noarch.rpm
  import jwt                               # PyJWT Jason Web Token, python-jwt-1.4.0-2.el7.noarch.rpm
except:
  print "Missing modules, please install xrootd-python, python-flask, python-jwt"
  sys.exit(-1)

app = flask.Flask("WOPI server")
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
app.logger.addHandler(logging.FileHandler('wopiserver.log'))
wopisecret = 'wopisecret'    # XXX todo read secret from config file

@app.route("/")
def index():
  return "This is the WOPI server. Access is performed via REST API, e.g. GET /api/wopi/files/<fileid>"

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
    md['Basefileid'] = fileid
    md['OwnerId'] = acctok['username']
    md['Size'] = 100
    md['SHA256'] = '1'
    md['Version'] = '1.0'
    md['SupportsUpdate'] = md['UserCanWrite'] = md['SupportsLocks'] = True
    jsonmd = json.dumps(md)
    return jsonmd
  except jwt.exceptions.DecodeError:
    log.warning("Signature verification failed for token %s" % flask.request.args['access_token'])

@app.route("/api/wopi/files/<fileid>/contents", methods=['GET'])
def wopiGetFile(fileid):
  try:
    acctok = jwt.decode(flask.request.args['access_token'], wopisecret, algorithms=['HS256'])
    log.info('msg="GET content" username="%s" filename="%s"' % (acctok['username'], acctok['filename']))
    # set response to application/x-octet-stream
    # open file from storage
  except jwt.exceptions.DecodeError:
    log.warning("Signature verification failed for token %s" % flask.request.args['access_token'])

@app.route("/api/wopi/files/<fileid>/contents", methods=['POST'])
def wopiPostContent(fileid):
  log.info("NOOP - POST content for %s, access token = %s" % (fileid, flask.request.args['access_token']))

app.run(host='0.0.0.0', port=8080)

