#!/bin/python
#
# wopiserver.py
#
# Initial prototype for an Office Web Apps gateway for CERNBox
#
# Giuseppe.LoPresti@cern.ch

import flask
app = flask.Flask(__name__)

@app.route("/")
def index():
	return "WOPI server top level page"

@app.route("/api/wopi/files/<filename>", methods=['GET'])
#
#{
#  "BaseFileName": "sample string 1",
#  "OwnerId": "sample string 2",
#  "Size": 3,
#  "SHA256": "sample string 4",
#  "Version": "sample string 5",
#  "SupportsUpdate": true,
#  "UserCanWrite": true,
#  "SupportsLocks": true
#}
def wopiGetMetadata(filename):
    return "GET metadata for %s, access token = %s" % (filename, flask.request.args['access_token'])

@app.route("/api/wopi/files/<filename>/contents", methods=['GET'])
def wopiGetContent(filename):
    return "GET content for %s, access token = %s" % (filename, flask.request.args['access_token'])

@app.route("/api/wopi/files/<filename>/contents", methods=['POST'])
def wopiPostContent(filename):
    return "POST content for %s" % filename

app.run(host='0.0.0.0', port=8080)
