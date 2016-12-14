#!/bin/python
#
# wopiserver.py
#
# Initial prototype for a Web-application Open Platform Interface (WOPI) gateway for CERNBox
#
# Giuseppe.LoPresti@cern.ch

from XRootD import client as XrdClient
import flask
import json
import logging.handlers
import logging

app = flask.Flask("WOPI server")
tokens = {}
log = logging.FileHandler('wopiserver.log')
log.setLevel(logging.DEBUG)
app.logger.addHandler(log)

@app.route("/")
def index():
  return "This is the WOPI server. Access is performed via REST API, e.g. GET /api/wopi/files/<fileid>"

@app.route("/setAccessToken/<fileid>", methods=['GET', 'POST'])   # GET for debugging
def setAccessToken(fileid):
  uid = flask.request.args['uid']
  filename = flask.request.args['filename']
  tokens[flask.request.args['access_token']] = (fileid, uid, filename)
  log.info("Access token set for filename %s and user %s" % (filename, uid))
  return '{}'

@app.route("/api/wopi/files/<fileid>", methods=['GET'])
def wopiCheckFileInfo(fileid):
  try:
    fid, uid, filename = tokens[flask.request.args['access_token']]
    log.info("GET metadata for %d:%s, access token = %s" % (fileid, filename, flask.request.args['access_token']))
    md = {}
    md['Basefileid'] = fileid
    md['OwnerId'] = uid
    md['Size'] = 100
    md['SHA256'] = '1'
    md['Version'] = '1.0'
    md['SupportsUpdate'] = md['UserCanWrite'] = md['SupportsLocks'] = true
    jsonmd = json.dumps(md)
    return jsonmd
  except KeyError, e:
    log.warning("Unknown user/token %s" % flask.request.args['access_token'])
    log.warning(e)

@app.route("/api/wopi/files/<fileid>/contents", methods=['GET'])
def wopiGetFile(fileid):
  log.info("GET content for %s, access token = %s" % (fileid, flask.request.args['access_token']))

@app.route("/api/wopi/files/<fileid>/contents", methods=['POST'])
def wopiPostContent(fileid):
  log.info("NOOP - POST content for %s, access token = %s" % (fileid, flask.request.args['access_token']))

@app.route("/api/Files", methods=['POST'])
def wopiPostContent():
  log.info("NOOP - POST content, destinationBlobName = %s" % flask.request.args['destinationBlobName'])

app.run(host='0.0.0.0', port=8080)
