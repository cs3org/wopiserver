#!/usr/bin/python3
'''
wopibridge.py

The WOPI bridge for IOP. This PoC only integrates CodiMD.

Author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

import os
import sys
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
import hashlib
try:
  import requests
  import flask                   # Flask app server
except ImportError:
  print("Missing modules, please install with `pip3 install flask requests`")
  raise

WBVERSION = '0.3'

class WB:
  '''A singleton container for all state information of the server'''
  app = flask.Flask("WOPIBridge")
  port = 0
  loglevels = {"Critical": logging.CRITICAL,  # 50
               "Error":    logging.ERROR,     # 40
               "Warning":  logging.WARNING,   # 30
               "Info":     logging.INFO,      # 20
               "Debug":    logging.DEBUG      # 10
              }
  log = app.logger
  openfiles = {}      # a map of all open codimd docs hashes -> list of active access tokens for each of them


  @classmethod
  def init(cls):
    '''Initialises the application, bails out in case of failures. Note this is not a __init__ method'''
    try:
      # configure the logging
      loghandler = logging.FileHandler('/var/log/wopi/wopibridge.log')
      loghandler.setFormatter(logging.Formatter(fmt='%(asctime)s %(name)s[%(process)d] %(levelname)-8s %(message)s',
                                                datefmt='%Y-%m-%dT%H:%M:%S'))
      cls.log.addHandler(loghandler)
      # prepare the Flask web app
      cls.port = 8000
      cls.log.setLevel(cls.loglevels['Debug'])
      cls.codimdexturl = os.environ.get('CODIMD_EXT_URL')    # this is the external-facing URL
      cls.codimdurl = os.environ.get('CODIMD_INT_URL')       # this is the internal URL (e.g. as visible in a docker network)
      cls.codimdstore = os.environ.get('CODIMD_STORAGE_PATH')
      _autodetected_server = 'http://%s:%d' % (socket.getfqdn(), cls.port)
      cls.wopibridgeurl = os.environ.get('WOPIBRIDGE_URL')
      if not cls.wopibridgeurl:
        cls.wopibridgeurl = _autodetected_server
      cls.proxied = _autodetected_server != cls.wopibridgeurl
      # a regexp for uploads, that have links like '/uploads/upload_542a360ddefe1e21ad1b8c85207d9365.*'
      cls.upload_re = re.compile(r'\/uploads\/upload_\w{32}\.\w+')
    except Exception as e:
      # any error we get here with the configuration is fatal
      cls.log.fatal('msg="Failed to initialize the service, aborting" error="%s"' % e)
      sys.exit(-22)


  @classmethod
  def run(cls):
    '''Runs the Flask app in secure (standalone) or unsecure mode depending on the context.
       Secure https mode typically is to be provided by the infrastructure (k8s ingress, nginx...)'''
    if os.path.isfile('/var/run/secrets/cert.pem'):
      cls.log.info('msg="WOPI Bridge starting in secure mode" url="%s" proxied="%s"' % (cls.wopibridgeurl, cls.proxied))
      cls.app.run(host='0.0.0.0', port=cls.port, threaded=True, debug=True,
                  ssl_context=('/var/run/secrets/cert.pem', '/var/run/secrets/key.pem'))
    else:
      cls.log.info('msg="WOPI Bridge starting in unsecure mode" url="%s" proxied="%s"' % (cls.wopibridgeurl, cls.proxied))
      cls.app.run(host='0.0.0.0', port=cls.port, threaded=True, debug=True)


# The Web Application starts here
#############################################################################################################

@WB.app.route("/", methods=['GET'])
def index():
  '''Return a default index page with some user-friendly information about this service'''
  #WB.log.debug('msg="Accessed index page" client="%s"' % flask.request.remote_addr)
  return """
    <html><head><title>ScienceMesh WOPI Bridge</title></head>
    <body>
    <div align="center" style="color:#000080; padding-top:50px; font-family:Verdana; size:11">
    This is a WOPI HTTP bridge, to be used in conjunction with a WOPI-enabled EFSS.<br>This proof-of-concept supports CodiMD for now.</div>
    <div style="position: absolute; bottom: 10px; left: 10px; width: 99%%;"><hr>
    <i>ScienceMesh WOPI Bridge %s at %s. Powered by Flask %s for Python %s</i>.</div>
    </body>
    </html>
    """ % (WBVERSION, socket.getfqdn(), flask.__version__, python_version())


def _getattachments(mddoc, docfilename):
  '''Parse a markdown file and generate a zip file containing all included files'''
  if WB.upload_re.search(mddoc) is None:
    # no attachments
    return None
  zip_buffer = io.BytesIO()
  for attachment in WB.upload_re.findall(mddoc):
    WB.log.debug('msg="Fetching attachment" url="%s"' % attachment)
    res = requests.get(WB.codimdurl + attachment, verify=False)
    if res.status_code != http.client.OK:
      WB.log.error('msg="Failed to fetch included file" path="%s" returncode="%d"' % (attachment, res.status_code))
      continue
    with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_STORED, allowZip64=False) as zip_file:
      zip_file.writestr(attachment.split('/')[-1], res.content)
  # also include the markdown file itself
  with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_STORED, allowZip64=False) as zip_file:
    zip_file.writestr(docfilename, mddoc)
  return zip_buffer.getvalue()


def _unzipattachments(inputbuf, targetpath):
  '''Unzip the given input buffer to targetpath and return the contained .md file
  XXX this requires direct access to the storage, need to use HTTP instead'''
  inputzip = zipfile.ZipFile(io.BytesIO(inputbuf), compression=zipfile.ZIP_STORED)
  mddoc = None
  for fname in inputzip.namelist():
    WB.log.debug('msg="Extracting attachment" name="%s"' % fname)
    if os.path.splitext(fname)[1] == '.md':
      mddoc = inputzip.read(fname)
    else:
      # TODO perform upload via HTTP as opposed to the following
      inputzip.extract(fname, path=targetpath)
      #blob = inputzip.read(fname)
      #url = WB.codimdurl + '/uploads/' + fname
      #WB.log.debug('msg="Pushing attachment" url="%s"' % url)
      #res = requests.post(url)
      #if res.status_code != http.client.OK:
      #  WB.log.error('msg="Failed to push included file" path="%s" returncode="%d"' % (url, res.status_code))
  return mddoc


def _wopicall(wopisrc, acctok, method, contents=False, headers=None):
  '''Execute a WOPI call with the given parameters and headers'''
  wopiurl = '%s%s' % (wopisrc, ('/contents' if contents and \
            (not headers or 'X-WOPI-Override' not in headers or headers['X-WOPI-Override'] != 'PUT_RELATIVE') else ''))
  WB.log.debug('msg="Calling WOPI" url="%s" headers="%s" acctok="%s"' % \
               (wopiurl, headers, acctok[-20:]))
  if method == 'GET':
    return requests.get('%s?access_token=%s' % (wopiurl, acctok), verify=False)
  if method == 'POST':
    return requests.post('%s?access_token=%s' % (wopiurl, acctok), verify=False, headers=headers, data=contents)
  return None


def _storagetocodimd(filemd, wopisrc, acctok):
  '''Copy document from storage to CodiMD'''
  # WOPI GetFile
  res = _wopicall(wopisrc, acctok, 'GET', contents=True)
  if res.status_code != http.client.OK:
    raise ValueError(res.status_code)
  mdfile = res.content
  wasbundle = os.path.splitext(filemd['BaseFileName'])[1] == '.zmd'

  # if it's a bundled file, unzip it and push the attachments in the appropriate folder
  if wasbundle:
    mddoc = _unzipattachments(mdfile, WB.codimdstore)
  else:
    mddoc = mdfile
  h = hashlib.sha1()
  h.update(mddoc)
  newparams = None
  if not filemd['UserCanWrite']:
    newparams = {'mode': 'locked'}     # this is an extended feature in CodiMD

  # push the document to CodiMD
  res = requests.post(WB.codimdurl + '/new', data=mddoc, allow_redirects=False, params=newparams,
                      headers={'Content-Type': 'text/markdown'}, verify=False)
  if res.status_code != http.client.FOUND:
    raise ValueError(res.status_code)
  WB.log.debug('msg="Got redirect from CodiMD" url="%s"' % res.next.url)
  # we got the hash of the document just created as a redirected URL, store it in our WOPI lock structure
  # the lock is a dict { docid, filename, digest, app }
  wopilock = {'docid': '/' + urllib.parse.urlsplit(res.next.url).path.split('/')[-1],
              'filename': filemd['BaseFileName'],
              'digest': h.hexdigest(),
              'app': 'slide' if mddoc.decode().find('---\ntitle:') == 0 else 'md',
              }
  WB.log.info('msg="Pushed document to CodiMD" url="%s" token="%s"' % (wopilock['docid'], acctok[-20:]))
  return wopilock


def _codimdtostorage(wopisrc, acctok, isclose):
  # get current lock to have extra context
  try:
    res = _wopicall(wopisrc, acctok, 'POST', headers={'X-Wopi-Override': 'GET_LOCK'})
    if res.status_code != http.client.OK:
      raise ValueError(res.status_code)
    wopilock = json.loads(res.headers.pop('X-WOPI-Lock'))   # the lock is a dict { docid, filename, digest, app }
  except (ValueError, KeyError, json.decoder.JSONDecodeError) as e:
    WB.log.error('msg="Save: unable to store the file, malformed or missing WOPI lock" exception="%s" error="%s"' % (type(e), e))
    return 'Failed to fetch WOPI context', http.client.NOT_FOUND

  # We must save and have all required context. Get document from CodiMD
  WB.log.info('msg="Save called, fetching file" close="%s" client="%s" codimdurl="%s" token="%s"' % \
               (isclose, flask.request.remote_addr, WB.codimdurl + wopilock['docid'], acctok[-20:]))
  res = requests.get(WB.codimdurl + wopilock['docid'] + '/download', verify=False)
  if res.status_code != http.client.OK:
    return 'Failed to fetch document from CodiMD', res.status_code
  mddoc = res.content
  bundlefile = _getattachments(mddoc.decode(), wopilock['filename'].replace('.zmd', '.md'))
  wasbundle = os.path.splitext(wopilock['filename'])[1] == '.zmd'

  save = (wopilock['digest'] == 'dirty')
  if isclose and not save:
    # so far the file was not touched and we are closing: before forcing a put let's validate the contents
    h = hashlib.sha1()
    h.update(mddoc)
    if h.hexdigest() != wopilock['digest']:
      save = True
    else:
      WB.log.info('msg="File unchanged, skipping save" token="%s"' % acctok[-20:])


  # WOPI PutFile for the file or the bundle if it already existed
  if save:
    if (wasbundle or not bundlefile):
      res = _wopicall(wopisrc, acctok, 'POST', headers={'X-WOPI-Lock': json.dumps(wopilock)},
                      contents=(bundlefile if wasbundle else mddoc))
    # WOPI PutRelative for the new bundle (not touching the original file), if this is the first time we have attachments
    else:
      putrelheaders = {'X-WOPI-Lock': json.dumps(wopilock),
                       'X-WOPI-Override': 'PUT_RELATIVE',
                       # SuggestedTarget to not overwrite a possibly existing file
                       'X-WOPI-SuggestedTarget': os.path.splitext(wopilock['filename'])[0] + '.zmd'
                      }
      res = _wopicall(wopisrc, acctok, 'POST', headers=putrelheaders, contents=bundlefile)

    if res.status_code != http.client.OK:
      WB.log.warning('msg="Calling WOPI PutFile/PutRelative failed" url="%s" response="%s"' % (wopisrc, res.status_code))
      return 'Error saving the file', res.status_code
    WB.log.debug('msg="Save completed successfully"')

  if isclose:
    # this the last editor for this file, unlock document
    res = _wopicall(wopisrc, acctok, 'POST', headers={'X-WOPI-Lock': json.dumps(wopilock), 'X-Wopi-Override': 'UNLOCK'})
    if res.status_code != http.client.OK:
      WB.log.warning('msg="Calling WOPI Unlock failed" url="%s" response="%s"' % (wopisrc, res.status_code))
    # clean list of active documents
    #del WB.openfiles[wopilock['docid']]

  else:
    # regular save, also refresh the lock
    newlock = json.loads(json.dumps(wopilock))    # this is a hack for a deep copy, to be redone in Go
    newlock['digest'] = 'dirty'
    lockheaders = {'X-Wopi-Override': 'REFRESH_LOCK',
                   'X-WOPI-OldLock': json.dumps(wopilock),
                   'X-WOPI-Lock': json.dumps(newlock)
                  }
    res = _wopicall(wopisrc, acctok, 'POST', headers=lockheaders)
    if res.status_code != http.client.OK:
      WB.log.warning('msg="Calling WOPI RefreshLock failed" url="%s" response="%s"' % (wopisrc, res.status_code))

    # refresh list of active documents for statistical purposes
    #WB.openfiles[wopilock['docid']] = newlock['tokens']

  WB.log.info('msg="Save completed" client="%s" token="%s"' % \
               (flask.request.remote_addr, acctok[-20:]))
  return 'OK', http.client.OK


#
# The REST methods start here
#
@WB.app.route("/open", methods=['GET'])
def mdOpen():
  '''Open a MD doc by contacting the provided WOPISrc with the given access_token'''
  try:
    wopisrc = urllib.parse.unquote(flask.request.args['WOPISrc'])
    acctok = flask.request.args['access_token']
    WB.log.info('msg="Open called" client="%s" token="%s"' % (flask.request.remote_addr, acctok[-20:]))
  except KeyError as e:
    WB.log.error('msg="Open: unable to open the file, missing WOPI context" error="%s"' % e)
    return 'Missing arguments', http.client.BAD_REQUEST

  # WOPI GetFileInfo
  try:
    res = _wopicall(wopisrc, acctok, 'GET')
    filemd = res.json()
  except (ValueError, json.decoder.JSONDecodeError) as e:
    WB.log.warning('msg="Malformed JSON from WOPI" error="%s" returncode="%d"' % (e, res.status_code))
    return 'Invalid WOPI context', http.client.NOT_FOUND

  # use the 'UserCanWrite' attribute to decide whether the file is to be opened in read-only mode
  if filemd['UserCanWrite']:
    # WOPI GetLock
    res = _wopicall(wopisrc, acctok, 'POST', headers={'X-Wopi-Override': 'GET_LOCK'})
    if res.status_code != http.client.OK:
      raise ValueError(res.status_code)
    wopilock = res.headers.pop('X-WOPI-Lock', None)   # if present, the lock is a dict { docid, filename, digest, app }

    if wopilock:
      try:
        wopilock = json.loads(wopilock)
        # file is already locked and it's a JSON: assume we hold it
        WB.log.info('msg="Lock already held" lock="%s"' % wopilock)
      except json.decoder.JSONDecodeError:
        # this lock cannot be parsed, probably got corrupted: force read-only mode
        WB.log.error('msg="Lock already held by another app" lock="%s"' % wopilock)
        filemd['UserCanWrite'] = False
        #filemd['BreadcrumbDocName'] += ' (locked by another app)'
        wopilock = None

    if not wopilock:
      # file is not locked or lock is unreadable, fetch the file from storage
      wopilock = _storagetocodimd(filemd, wopisrc, acctok)

    # WOPI Lock
    lockheaders = {'X-WOPI-Lock': json.dumps(wopilock), 'X-Wopi-Override': 'LOCK'}
    res = _wopicall(wopisrc, acctok, 'POST', headers=lockheaders)
    if res.status_code != http.client.OK:
      # Failed to lock the file: open in read-only mode
      WB.log.warning('msg="Failed to lock the file" token="%s" returncode="%d"' % (acctok[-20:], res.status_code))
      filemd['UserCanWrite'] = False

  else:
    # user has no write privileges, just fetch document and push it to CodiMD
    wopilock = _storagetocodimd(filemd, wopisrc, acctok)

  if filemd['UserCanWrite']:
    # keep track of this open document for statistical purposes
    #WB.openfiles[wopilock['docid']] = wopilock['tokens']
    # create the external redirect URL to be returned to the client:
    # metadata will be used for autosave (this is an extended feature of CodiMD)
    redirecturl = WB.codimdexturl + wopilock['docid'] + '?metadata=' + urllib.parse.quote_plus('%s?t=%s' % (wopisrc, acctok)) + '&'
  else:
    # read-only mode: in this case redirect to publish mode or slide mode depending on the content
    if wopilock['app'] == 'slide':
      redirecturl = WB.codimdexturl + wopilock['docid'] + '/slide?'
    else:
      redirecturl = WB.codimdexturl + wopilock['docid'] + '/publish?'
  # append displayName (again this is an extended feature of CodiMD)
  redirecturl += 'displayName=' + urllib.parse.quote_plus(filemd['UserFriendlyName'])

  WB.log.info('msg="Redirecting client to CodiMD" redirecturl="%s"' % redirecturl)
  return flask.redirect(redirecturl)


@WB.app.route("/save", methods=['POST'])
def mdSave():
  '''Saves an MD doc given its WOPI context'''
  meta = None
  try:
    meta = urllib.parse.unquote(flask.request.headers['X-CERNBox-Metadata'])
    wopisrc = meta[:meta.index('?t=')]
    acctok = meta[meta.index('?t=')+3:]
    isclose = 'close' in flask.request.args and flask.request.args['close'] == 'true'
  except (KeyError, ValueError) as e:
    WB.log.error('msg="Save: malformed or missing metadata" client="%s" headers="%s" exception="%s" error="%s"' % \
      (flask.request.remote_addr, flask.request.headers, type(e), e))
    return 'Malformed or missing metadata', http.client.BAD_REQUEST
  # enqueue the request, it will be processed asynchronously
  _codimdtostorage(wopisrc, acctok, isclose)
  # return latest known state for this document
  return http.client.OK if True else 'Error', http.client.PRECONDITION_FAILED


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
