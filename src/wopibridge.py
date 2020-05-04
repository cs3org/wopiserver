#!/usr/bin/python3
'''
wopibridge.py

The WOPI bridge for IOP. This PoC only integrates CodiMD.

Author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

import os
import sys
import time
import socket
import re
from platform import python_version
import logging
import logging.handlers
import urllib.parse
import http.client
import json
import io
import zipfile
try:
  import requests
  import flask                   # Flask app server
except ImportError:
  print("Missing modules, please install with `pip3 install flask requests`")
  raise

WBSERVERVERSION = '0.2'

class WB:
  '''A singleton container for all state information of the server'''
  app = flask.Flask("WOPIBridge")
  port = 0
  lastConfigReadTime = time.time()
  loglevels = {"Critical": logging.CRITICAL,  # 50
               "Error":    logging.ERROR,     # 40
               "Warning":  logging.WARNING,   # 30
               "Info":     logging.INFO,      # 20
               "Debug":    logging.DEBUG      # 10
              }
  log = app.logger
  openfiles = {}      # a map of all open codimd docs hashes -> list of active access tokens for each of them

  # the following is a template with seven (!) parameters. TODO need to convert to a Jinjia template
  frame_page_templated_html = """
    <html>
    <head>
    <title>%s | WOPI-enabled CodiMD PoC | %s</title>
    <style type="text/css">
      body, html
      {
        margin: 0; padding: 0; height: 100%%; overflow: hidden;
      }
    </style>
    <script src="http://code.jquery.com/jquery-latest.min.js"></script>
    <script>
      window.onbeforeunload = function() {
        $.get("%s/close",
          {WOPISrc: '%s',
           access_token: '%s',
           save: '%s'},
          function(data) {}
        );
      };
      $(document).ready(function() {
        $('a[rel!=ext]').click(function() { window.onbeforeunload = null; });
        $('form').submit(function() { window.onbeforeunload = null; });
      });
    </script>
    </head>
    <body>
    <iframe width="100%%" height="100%%" src="%s"></iframe>
    </body>
    </html>
    """

  @classmethod
  def init(cls):
    '''Initialises the application, bails out in case of failures. Note this is not a __init__ method'''
    try:
      # configure the logging
      loghandler = logging.FileHandler('/var/log/wopi/codimdtowopi.log')
      loghandler.setFormatter(logging.Formatter(fmt='%(asctime)s %(name)s[%(process)d] %(levelname)-8s %(message)s',
                                                datefmt='%Y-%m-%dT%H:%M:%S'))
      cls.log.addHandler(loghandler)
      # read the configuration - not needed for now
      #cls.config = configparser.ConfigParser()
      #cls.config.read_file(open('/etc/wopi/codimdtowopi.defaults.conf'))
      #cls.config.read('/etc/wopi/codimdtowopi.conf')
      # prepare the Flask web app
      cls.port = 8000
      cls.log.setLevel(cls.loglevels['Debug'])
      cls.codimdexturl = os.environ.get('CODIMD_EXT_URL')    # this is the external-facing URL
      cls.codimdurl = os.environ.get('CODIMD_INT_URL')       # this is the internal URL (e.g. as visible in a docker network)
      cls.codimdstore = os.environ.get('CODIMD_STORAGE_PATH')
      cls.useHttps = False
      _autodetected_server = '%s://%s:%d' % (('https' if cls.useHttps else 'http'), socket.getfqdn(), cls.port)
      cls.wopibridgeurl = os.environ.get('WOPIBRIDGE_URL')
      if not cls.wopibridgeurl:
        cls.wopibridgeurl = _autodetected_server
      cls.proxied = _autodetected_server != cls.wopibridgeurl
      # a regexp for uploads, that have links like '/uploads/upload_542a360ddefe1e21ad1b8c85207d9365.*'
      cls.upload_re = re.compile('(' + cls.codimdexturl.replace('/', '\\/').replace('.', '\\.') + \
                                 r'\/uploads\/upload_\w{32}\.\w+)', re.IGNORECASE)
    except Exception as e:
      # any error we get here with the configuration is fatal
      cls.log.fatal('msg="Failed to initialize the service, aborting" error="%s"' % e)
      sys.exit(-22)


  @classmethod
  def run(cls):
    '''Runs the Flask app in either secure (https) or test (http) mode'''
    if cls.useHttps:
      cls.log.info('msg="WOPI Bridge starting in secure mode" url="%s" proxied="%s"' % (cls.wopibridgeurl, cls.proxied))
      cls.app.run(host='0.0.0.0', port=cls.port, threaded=True, debug=True)
                  #ssl_context=(cls.config.get('security', 'wopicert'), cls.config.get('security', 'wopikey')))
    else:
      cls.log.info('msg="WOPI Bridge starting in test/unsecure mode" url="%s" proxied="%s"' % (cls.wopibridgeurl, cls.proxied))
      cls.app.run(host='0.0.0.0', port=cls.port, threaded=True, debug=True)


# The Web Application starts here
#############################################################################################################

@WB.app.route("/", methods=['GET'])
def index():
  '''Return a default index page with some user-friendly information about this service'''
  WB.log.info('msg="Accessed index page" client="%s"' % flask.request.remote_addr)
  return """
    <html><head><title>CodiMD to WOPI</title></head>
    <body>
    <div align="center" style="color:#000080; padding-top:50px; font-family:Verdana; size:11">
    This is a WOPI HTTP bridge, to be used in conjunction with a WOPI-enabled EFSS. This proof-of-concept supports CodiMD only.</div>
    <br><br><br><br><br><br><br><hr>
    <i>WOPI Bridge %s at %s. Powered by Flask %s for Python %s</i>.
    </body>
    </html>
    """ % (WBSERVERVERSION, socket.getfqdn(), flask.__version__, python_version())


@WB.app.route('/new', methods=['GET'])
def mdNew():
  '''Create a new MD doc to the given WOPISrc and allow user to start working on it'''
  pass


@WB.app.route("/open", methods=['GET'])
def mdOpen():
  '''Open a MD doc by contacting the provided WOPISrc with the given access_token'''
  wopiSrc = urllib.parse.unquote(flask.request.args['WOPISrc'])
  acctok = flask.request.args['access_token']
  WB.log.info('msg="Open called" client="%s" token="%s"' % (flask.request.remote_addr, acctok[-20:]))

  # WOPI GetFileInfo
  url = '%s?access_token=%s' % (wopiSrc, acctok)
  WB.log.debug('msg="Calling WOPI" url="%s"' % wopiSrc)
  try:
    filemd = requests.get(url).json()
  except ValueError as e:
    WB.log.warning('msg="Malformed JSON from WOPI" error="%s"' % e)
    raise

  # WOPI GetLock: if present, trigger the collaborative editing
  WB.log.debug('msg="Calling WOPI GetLock" url="%s"' % wopiSrc)
  res = requests.post(url, headers={'X-Wopi-Override': 'GET_LOCK'})
  if res.status_code != http.client.OK:
    raise ValueError(res.status_code)
  wopilock = res.headers.pop('X-WOPI-Lock', None)   # if present, the lock is a dict { docid, filename, tokens }

  if wopilock:
    try:
      wopilock = json.loads(wopilock)
      # file is already locked and it's a JSON: assume we hold it, and append this access token to it
      wopilock['tokens'].append(acctok[-20:])
      # remove duplicates
      wopilock['tokens'] = list(set(wopilock['tokens']))
      WB.log.info('msg="Lock already held" lock="%s"' % wopilock)
    except json.decoder.JSONDecodeError:
      # this lock cannot be parsed, it likely follows a different lock scheme: force read-only mode
      WB.log.error('msg="Lock already held by another app" lock="%s"' % wopilock)
      filemd['UserCanWrite'] = False
      if '(locked by another app)' not in filemd['BreadcrumbDocName']:
        filemd['BreadcrumbDocName'] += ' (locked by another app)'
      wopilock = None
    except KeyError:
      WB.log.error('msg="Lock already held, but missing tokens?" lock="%s"' % wopilock)
      wopilock['tokens'] = list()
      wopilock['tokens'].append(acctok[-20:])

  if not wopilock:
    # file is not locked, fetch it from storage
    # WOPI GetFile
    url = '%s/contents?access_token=%s' % (wopiSrc, acctok)
    WB.log.debug('msg="Calling WOPI GetFile" url="%s"' % wopiSrc)
    res = requests.get(url)
    if res.status_code != http.client.OK:
      raise ValueError(res.status_code)
    mddoc = res.content

    # then push the document to CodiMD:
    # if it's a bundled file, unzip it and push the attachments in the appropriate folder
    # NOTE: this assumes we have direct filesystem access to the CodiMD storage!

    res = requests.post(WB.codimdurl + '/new', data=mddoc, allow_redirects=False, \
                        headers={'Content-Type': 'text/markdown'})
    if res.status_code != http.client.FOUND:
      raise ValueError(res.status_code)
    # we got the hash of the document just created as a redirected URL, store it in our WOPI lock structure
    wopilock = {'docid': urllib.parse.urlsplit(res.next.url).path, \
                'filename': filemd['BaseFileName'], \
                'tokens': [acctok[-20:]]
               }
    WB.log.info('msg="Pushed document to CodiMD" url="%s" token="%s"' % (wopilock['docid'], acctok[-20:]))

  # use the 'UserCanWrite' attribute to decide whether the file is to be opened in read-only mode
  if filemd['UserCanWrite']:
    # WOPI Lock
    url = '%s?access_token=%s' % (wopiSrc, acctok)
    WB.log.debug('msg="Calling WOPI Lock" url="%s" lock="%s"' % (wopiSrc, wopilock))
    lockheaders = {'X-WOPI-Lock': json.dumps(wopilock), 'X-Wopi-Override': 'LOCK'}
    if len(wopilock['tokens']) > 1:
      # in this case we need to refresh an existing lock
      oldlock = json.loads(json.dumps(wopilock))    # this is a hack for a deep copy, to be redone in Go
      oldlock['tokens'].remove(acctok[-20:])
      lockheaders['X-WOPI-OldLock'] = json.dumps(oldlock)
    res = requests.post(url, headers=lockheaders)
    if res.status_code != http.client.OK:
      # TODO handle conflicts
      raise ValueError(res.status_code)

    # keep track of this open document for statistical purposes
    WB.openfiles[wopilock['docid']] = wopilock['tokens']
    redirecturl = WB.codimdexturl + wopilock['docid'] + '?both'

  else:
    # read-only mode, amend the redirection url to show the file in publish mode
    # TODO tell CodiMD to disable editing!
    redirecturl = WB.codimdexturl + wopilock['docid'] + '/publish'

  WB.log.debug('msg="Redirecting client to CodiMD" redirecturl="%s"' % redirecturl)
  # generate a hook for close and return an iframe to the client
  return WB.frame_page_templated_html % (filemd['BreadcrumbDocName'], filemd['UserFriendlyName'], \
                                          WB.wopibridgeurl, wopiSrc, acctok, filemd['UserCanWrite'], \
                                          redirecturl)


def _getattachments(mddoc, filename):
  '''Parse a markdown file and generate a zip file containing all included files'''
  return None
  zip_buffer = io.BytesIO()
  for attachment in WB.upload_re.findall(mddoc):
    WB.log.debug('msg="Fetching attachment" url="%s"' % attachment)
    res = requests.get(attachment)
    if res.status_code != http.client.OK:
      # TODO handle error
      continue
    with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
      zip_file.writestr(attachment.split('/')[-1], res.content)
  # also include the markdown file
  with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
    zip_file.writestr(filename, mddoc)
  return zip_buffer.getvalue()


@WB.app.route("/close", methods=['GET'])
def mdClose():
  '''Close a MD doc by saving it back to the previously given WOPI Src and using the provided access token'''
  try:
    acctok = flask.request.args['access_token']
    wopiSrc = flask.request.args['WOPISrc']
    if flask.request.args['save'] == 'False':
      WB.log.info('msg="Close called" save="False" client="%s" token="%s"' % \
                  (flask.request.remote_addr, acctok[-20:]))
      # TODO delete content from CodiMD - API is missing
      return 'OK', http.client.OK
  except KeyError as e:
    WB.log.error('msg="Close called" error="Unable to store the file, missing WOPI context: %s"' % e)
    return 'Missing arguments', http.client.BAD_REQUEST

  # get current lock to have extra context
  WB.log.debug('msg="Calling WOPI GetLock" url="%s"' % wopiSrc)
  url = '%s?access_token=%s' % (wopiSrc, acctok)
  res = requests.post(url, headers={'X-Wopi-Override': 'GET_LOCK'})
  if res.status_code != http.client.OK:
    raise ValueError(res.status_code)
  try:
    wopilock = json.loads(res.headers.pop('X-WOPI-Lock'))   # the lock is a dict { docid, filename, tokens }
  except (KeyError, json.decoder.JSONDecodeError) as e:
    WB.log.error('msg="Close called" error="Unable to store the file, malformed or missing WOPI lock"')
    return 'Missing lock', http.client.BAD_REQUEST

  # We must save and have all required context. Get document from CodiMD
  WB.log.info('msg="Close called, fetching file" save="True" client="%s" codimdurl="%s" token="%s"' % \
               (flask.request.remote_addr, WB.codimdurl + wopilock['docid'], acctok[-20:]))
  res = requests.get(WB.codimdurl + wopilock['docid'] + '/download')
  if res.status_code != http.client.OK:
    raise ValueError(res.status_code)
  mddoc = res.content

  # WOPI PutFile
  url = '%s/contents?access_token=%s' % (wopiSrc, acctok)
  WB.log.debug('msg="Calling WOPI PutFile" url="%s"' % wopiSrc)
  res = requests.post(url, headers={'X-WOPI-Lock': json.dumps(wopilock)}, data=mddoc)
  if res.status_code != http.client.OK:
    WB.log.warning('msg="Calling WOPI PutFile failed" url="%s" response="%s"' % (wopiSrc, res.status_code))
    return 'Error saving the file', res.status_code

  # WOPI PutRelative for the attachments
  bundlefile = _getattachments(mddoc, wopilock['filename'])
  if bundlefile:
    url = '%s?access_token=%s' % (wopiSrc, acctok)
    WB.log.debug('msg="Calling WOPI PutFile" url="%s"' % wopiSrc)
    res = requests.post(url, headers={
        'X-WOPI-Lock': json.dumps(wopilock),
        'X-WOPI-Override': 'PUT_RELATIVE',
        'X-WOPI-RelativeTarget': wopilock['filename'] + 'x',
        'X-WOPI-OverwriteRelativeTarget': 'true'
        }, data=bundlefile)
    if res.status_code != http.client.OK:
      WB.log.warning('msg="Calling WOPI PutFile failed" url="%s" response="%s"' % (wopiSrc, res.status_code))
      return 'Error saving attachments', res.status_code

  # is this the last editor for this file?
  if len(wopilock['tokens']) == 1 and wopilock['tokens'][0] == acctok[-20:]:
    # yes, call WOPI Unlock
    url = '%s?access_token=%s' % (wopiSrc, acctok)
    WB.log.debug('msg="Calling WOPI Unlock" url="%s"' % wopiSrc)
    res = requests.post(url, headers={'X-WOPI-Lock': json.dumps(wopilock), 'X-Wopi-Override': 'UNLOCK'})
    if res.status_code != http.client.OK:
      WB.log.warning('msg="Calling WOPI Unlock failed" url="%s" response="%s"' % (wopiSrc, res.status_code))
    # clean list of active documents
    del WB.openfiles[wopilock['docid']]
  else:
    # we're not the last: still need to update the lock and take this session out
    # WOPI Lock
    url = '%s?access_token=%s' % (wopiSrc, acctok)
    WB.log.debug('msg="Calling WOPI Lock" url="%s" lock="%s"' % (wopiSrc, wopilock))
    newlock = json.loads(json.dumps(wopilock))    # this is a hack for a deep copy, to be redone in Go
    newlock['tokens'].remove(acctok[-20:])
    lockheaders = {'X-Wopi-Override': 'REFRESH_LOCK',
                   'X-WOPI-OldLock': json.dumps(wopilock),
                   'X-WOPI-Lock': json.dumps(newlock)
                  }
    res = requests.post(url, headers=lockheaders)
    if res.status_code != http.client.OK:
      # TODO handle conflicts
      raise ValueError(res.status_code)
    # refresh list of active documents for statistical purposes
    WB.openfiles[wopilock['docid']] = wopilock['tokens']

    # TODO as we're the last, delete on CodiMD: it seems this API is still missing

  WB.log.info('msg="Close completed" save="True" client="%s" token="%s"' % \
               (flask.request.remote_addr, acctok[-20:]))
  return 'OK', http.client.OK


@WB.app.route("/list", methods=['GET'])
def mdList():
  '''Return a list of all currently opened files'''
  # TODO this API should be protected
  return flask.Response(json.dumps(WB.openfiles), mimetype='application/json')


#
# Start the Flask endless listening loop
#
if __name__ == '__main__':
  WB.init()
  WB.run()
