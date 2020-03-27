#!/usr/bin/python3
'''
codimdtowopi.py

The CodiMD to WOPI gateway for CERNBox

Author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

import sys
import time
import traceback
import socket
import configparser
from platform import python_version
import logging
import logging.handlers
import urllib.parse
import http.client
import requests
try:
  import flask                   # Flask app server
except ImportError:
  print("Missing modules, please install Flask with `pip3 install flask`")
  raise

MDWSERVERVERSION = '0.1'

class MDW:
  '''A singleton container for all state information of the server'''
  app = flask.Flask("CodiMDToWOPI")
  port = 0
  lastConfigReadTime = time.time()
  loglevels = {"Critical": logging.CRITICAL,  # 50
               "Error":    logging.ERROR,     # 40
               "Warning":  logging.WARNING,   # 30
               "Info":     logging.INFO,      # 20
               "Debug":    logging.DEBUG      # 10
              }
  log = app.logger
  openDocs = {}   # a map active access tokens -> (codimd doc url, WOPISrc url)
  locks = {}      # an "inverse" map codimd docs urls -> set of active access tokens for this file

  # the following is a template with six (!) parameters. TODO need to find a better solution for this
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
          {access_token: '%s',
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
      # read the configuration
      cls.config = configparser.ConfigParser()
      cls.config.read_file(open('/etc/wopi/codimdtowopi.defaults.conf'))
      cls.config.read('/etc/wopi/codimdtowopi.conf')
      # prepare the Flask web app
      cls.port = int(cls.config.get('general', 'port'))
      cls.log.setLevel(cls.loglevels[cls.config.get('general', 'loglevel')])
      cls.codimdurl = cls.config.get('general', 'codimdurl')
      cls.useHttps = False     # cls.config.get('security', 'usehttps').lower() == 'yes'
    except Exception as e:
      # any error we get here with the configuration is fatal
      cls.log.fatal('msg="Failed to initialize the service, aborting" error="%s"' % e)
      sys.exit(-22)


  @classmethod
  def run(cls):
    '''Runs the Flask app in either secure (https) or test (http) mode'''
    if cls.useHttps:
      cls.codiwopiurl = 'https://%s:%d' % (socket.getfqdn(), cls.port)
      cls.log.info('msg="CodiMD to WOPI Server starting in secure mode" url="%s"' % cls.codiwopiurl)
      cls.app.run(host='0.0.0.0', port=cls.port, threaded=True, debug=(cls.config.get('general', 'loglevel') == 'Debug'),
                  ssl_context=(cls.config.get('security', 'wopicert'), cls.config.get('security', 'wopikey')))
    else:
      cls.codiwopiurl = 'http://%s:%d' % (socket.getfqdn(), cls.port)
      cls.log.info('msg="CodiMD to WOPI Server starting in test/unsecure mode" url="%s"' % cls.codiwopiurl)
      cls.app.run(host='0.0.0.0', port=cls.port, threaded=True, debug=(cls.config.get('general', 'loglevel') == 'Debug'))


#############################################################################################################
#
# The Web Application starts here
#
#############################################################################################################

@MDW.app.route("/", methods=['GET'])
def index():
  '''Return a default index page with some user-friendly information about this service'''
  MDW.log.info('msg="Accessed index page" client="%s"' % flask.request.remote_addr)
  return """
    <html><head><title>CodiMD to WOPI</title></head>
    <body>
    <div align="center" style="color:#000080; padding-top:50px; font-family:Verdana; size:11">
    This is the CodiMD to WOPI bridge, to be used in conjunction with a WOPI-enabled EFSS.</div>
    <br><br><br><br><br><br><br><hr>
    <i>CERNBox CodiMD to WOPI Server %s at %s. Powered by Flask %s for Python %s</i>.
    </body>
    </html>
    """ % (MDWSERVERVERSION, socket.getfqdn(), flask.__version__, python_version())


@MDW.app.route("/open", methods=['GET'])
def mdOpen():
  '''Open a md doc by contacting the provided WOPISrc with the given access_token'''
  wopiSrc = urllib.parse.unquote(flask.request.args['WOPISrc'])
  acctok = flask.request.args['access_token']
  MDW.log.info('msg="Open called" client="%s" token="%s"' % (flask.request.remote_addr, acctok[-20:]))

  # WOPI GetFileInfo
  url = '%s?access_token=%s' % (wopiSrc, acctok)
  MDW.log.debug('msg="Calling WOPI" url="%s"' % wopiSrc)
  try:
    filemd = requests.get(url).json()
  except ValueError as e:
    # TODO handle failures
    raise

  # WOPI GetLock: if present, trigger the collaborative editing
  MDW.log.debug('msg="Calling WOPI GetLock" url="%s"' % wopiSrc)
  res = requests.post(url, headers={'X-Wopi-Override': 'GET_LOCK'})
  if res.status_code != http.client.OK:
    raise ValueError(res.status_code)
  lockurl = res.headers.pop('X-WOPI-Lock', None)   # if present, the lock is the URL of the document in CodiMD

  if lockurl:
    # file is already locked, check that it's held in this instance
    MDW.log.info('msg="Lock already held" lock="%s"' % lockurl)
    lockurl = urllib.parse.urlparse(lockurl)
    if ('%s://%s:%d' % (lockurl.scheme, lockurl.hostname, lockurl.port)) != MDW.codimdurl:
      # file was locked by another CodiMD instance or with a different lock scheme, cannot use it
      return 'File already locked', http.client.CONFLICT
    # yes, store some context in memory
    MDW.openDocs[acctok] = {'codimd': lockurl.geturl(), 'wopiSrc': wopiSrc}

  else:
    # file is not locked, fetch it from storage
    # WOPI GetFile
    url = '%s/contents?access_token=%s' % (wopiSrc, acctok)
    MDW.log.debug('msg="Calling WOPI GetFile" url="%s"' % wopiSrc)
    res = requests.get(url)
    if res.status_code != http.client.OK:
      raise ValueError(res.status_code)
    mddoc = res.content

    # then push the document to CodiMD
    res = requests.post(MDW.codimdurl + '/new', data=mddoc, allow_redirects=False, \
                        headers={'Content-Type': 'text/markdown'})
    if res.status_code != http.client.FOUND:
      raise ValueError(res.status_code)
    MDW.openDocs[acctok] = {'codimd': res.next.url, 'wopiSrc': wopiSrc}   # this is the redirect with the hash of the document just created
    MDW.log.info('msg="Pushed document to CodiMD" url="%s" token="%s"' % (MDW.openDocs[acctok]['codimd'], acctok[-20:]))

  # use the 'UserCanWrite' attribute to decide whether the file is to be opened in read-only mode
  if filemd['UserCanWrite']:
    # WOPI Lock
    url = '%s?access_token=%s' % (wopiSrc, acctok)
    MDW.log.debug('msg="Calling WOPI Lock" url="%s"' % wopiSrc)
    res = requests.post(url, headers={'X-WOPI-Lock': MDW.openDocs[acctok]['codimd'], 'X-Wopi-Override': 'LOCK'})
    if res.status_code != http.client.OK:
      # TODO handle conflicts
      raise ValueError(res.status_code)
    try:
      # keep track of this lock
      MDW.locks[MDW.openDocs[acctok]['codimd']] = MDW.locks[MDW.openDocs[acctok]['codimd']] | set(acctok)
    except KeyError:
      # this may happen if this bridge service is restarted... TODO need to store more context in the lock to be stateless
      MDW.locks[MDW.openDocs[acctok]['codimd']] = set(acctok)

  else:
    # read-only mode, amend the redirection url to show the file in publish mode
    # TODO tell CodiMD to disable editing!
    MDW.openDocs[acctok]['codimd'] += '/publish'

  MDW.log.debug('msg="Redirecting client to CodiMD"')
  # generate a hook for close and return an iframe to the client
  return MDW.frame_page_templated_html % (filemd['BaseFileName'], filemd['UserFriendlyName'], \
                                          MDW.codiwopiurl, acctok, filemd['UserCanWrite'], \
                                          MDW.openDocs[acctok]['codimd'])


@MDW.app.route("/close", methods=['GET'])
def mdClose():
  acctok = flask.request.args['access_token']
  if flask.request.args['save'] == 'False':
    MDW.log.info('msg="Close called" save="False" client="%s" token="%s"' % \
                 (flask.request.remote_addr, acctok[-20:]))
    return 'OK', http.client.OK

  try:
    wopiSrc = MDW.openDocs[acctok]['wopiSrc']
  except KeyError:
    # this may happen if this bridge service is restarted... TODO need to store more context to be stateless
    MDW.log.error('msg="Close called" token="%s" error="Unable to store the file, missing WOPI context"' % acctok[-20:])
    return 'WOPI source not found', http.client.NOT_FOUND

  # Get document from CodiMD
  res = requests.get(MDW.openDocs[acctok]['codimd'] + '/download')
  if res.status_code != http.client.OK:
    raise ValueError(res.status_code)
  mddoc = res.content

  # WOPI PutFile
  lockurl = MDW.openDocs[acctok]['codimd']
  url = '%s/contents?access_token=%s' % (wopiSrc, acctok)
  MDW.log.debug('msg="Calling WOPI PutFile" url="%s"' % wopiSrc)
  res = requests.post(url, headers={'X-WOPI-Lock': lockurl}, data=mddoc)
  if res.status_code != http.client.OK:
    # TODO handle conflicts
    raise ValueError(res.status_code)

  # remove this acctok from the set of active ones
  MDW.locks[lockurl] -= set(acctok)
  if len(MDW.locks[lockurl]) == 0:
    del MDW.locks[lockurl]
    # we're the last editor for this file, call WOPI Unlock
    url = '%s?access_token=%s' % (wopiSrc, acctok)
    MDW.log.debug('msg="Calling WOPI Unlock" url="%s"' % wopiSrc)
    res = requests.post(url, headers={'X-WOPI-Lock': lockurl, 'X-Wopi-Override': 'UNLOCK'})
    if res.status_code != http.client.OK:
      # TODO handle conflicts
      raise ValueError(res.status_code)

    # TODO as we're the last, delete on codimd: it seems this API is still missing

  # clean up internal state
  del MDW.openDocs[acctok]

  MDW.log.info('msg="Close called" save="True" client="%s" token="%s"' % \
               (flask.request.remote_addr, acctok[-20:]))
  return 'OK', http.client.OK


#
# Start the Flask endless listening loop
#
if __name__ == '__main__':
  MDW.init()
  MDW.run()
