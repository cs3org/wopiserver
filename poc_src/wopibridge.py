#!/usr/bin/python3
'''
wopibridge.py

The WOPI bridge for IOP. This PoC only integrates CodiMD.

Author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

import os
import sys
import time
import traceback
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
from random import randint
import hashlib
import threading
import atexit
try:
  import requests
  import flask                   # Flask app server
except ImportError:
  print("Missing modules, please install with `pip3 install flask requests`")
  raise

WBVERSION = '1.0'

class InvalidLock(Exception):
  '''A custom exception to represent an invalid or missing WOPI lock'''

class CodiMDFailure(Exception):
  '''A custom exception to represent a fatal failure when contacting CodiMD'''

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
  active = True
  openfiles = {}      # a map of all open documents: wopisrc -> (acctok, isclose, tosave, lastsave)
  saveresponses = {}  # a map of responses: wopisrc -> (http code, message)
  savecv = threading.Condition()    # a condition variable to synchronize the save thread and the main Flask threads

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
      cls.codimdurl = os.environ.get('CODIMD_INT_URL')       # this is the internal URL (e.g. as visible in docker/K8s)
      try:
        cls.saveinterval = int(os.environ.get('APP_SAVE_INTERVAL'))
      except TypeError:
        cls.saveinterval = 300                               # defaults to 5 minutes
      _autodetected_server = 'http://%s:%d' % (socket.getfqdn(), cls.port)
      cls.wopibridgeurl = os.environ.get('WOPIBRIDGE_URL')
      if not cls.wopibridgeurl:
        cls.wopibridgeurl = _autodetected_server
      cls.proxied = _autodetected_server != cls.wopibridgeurl
      # a regexp for uploads, that have links like '/uploads/upload_542a360ddefe1e21ad1b8c85207d9365.*'
      cls.upload_re = re.compile(r'\/uploads\/upload_\w{32}\.\w+')

      # start the thread to perform async save operations
      cls.savethread = threading.Thread(target=dosavetostorage)
      cls.savethread.start()
    except Exception as e:    # pylint: disable=broad-except
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

@WB.app.errorhandler(Exception)
def handleexception(ex):
  '''Generic method to log any uncaught exception'''
  if 'favicon.ico' in flask.request.url:
    # ignore harmless favicon requests
    return 'Not exist', http.client.NOT_FOUND
  ex_type, ex_value, ex_traceback = sys.exc_info()
  WB.log.error('msg="Unexpected exception caught" exception="%s" type="%s" traceback="%s"' % \
               (ex, ex_type, traceback.format_exception(ex_type, ex_value, ex_traceback)))
  return 'Internal error, please contact support', http.client.INTERNAL_SERVER_ERROR


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


def _refreshlock(wopisrc, acctok, isdirty, wopilock):
  '''Refresh an existing WOPI lock. Returns True if successful, False otherwise'''
  if isdirty and wopilock['digest'] != 'dirty':
    newlock = json.loads(json.dumps(wopilock))    # this is a hack for a deep copy, to be redone in Go
    newlock['digest'] = 'dirty'
  else:
    newlock = wopilock
  lockheaders = {'X-Wopi-Override': 'REFRESH_LOCK',
                 'X-WOPI-OldLock': json.dumps(wopilock),
                 'X-WOPI-Lock': json.dumps(newlock)
                }
  res = _wopicall(wopisrc, acctok, 'POST', headers=lockheaders)
  if res.status_code != http.client.OK:
    WB.log.warning('msg="Calling WOPI RefreshLock failed" url="%s" response="%s"' % (wopisrc, res.status_code))


def _getattachments(mddoc, docfilename, forcezip=False):
  '''Parse a markdown file and generate a zip file containing all included files'''
  if not forcezip and WB.upload_re.search(mddoc) is None:
    # no attachments
    return None
  zip_buffer = io.BytesIO()
  for attachment in WB.upload_re.findall(mddoc):
    WB.log.debug('msg="Fetching attachment" url="%s"' % attachment)
    res = requests.get(WB.codimdurl + attachment, verify=False)
    if res.status_code != http.client.OK:
      WB.log.error('msg="Failed to fetch included file" path="%s" response="%d"' % (attachment, res.status_code))
      continue
    with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_STORED, allowZip64=False) as zip_file:
      zip_file.writestr(attachment.split('/')[-1], res.content)
  # also include the markdown file itself
  with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_STORED, allowZip64=False) as zip_file:
    zip_file.writestr(docfilename, mddoc)
  return zip_buffer.getvalue()


def _unzipattachments(inputbuf):
  '''Unzip the given input buffer uploading the content to CodiMD and return the contained .md file'''
  inputzip = zipfile.ZipFile(io.BytesIO(inputbuf), compression=zipfile.ZIP_STORED)
  mddoc = None
  for zipinfo in inputzip.infolist():
    WB.log.debug('msg="Extracting attachment" name="%s"' % zipinfo.filename)
    if os.path.splitext(zipinfo.filename)[1] == '.md':
      mddoc = inputzip.read(zipinfo)
    else:
      # first check if the file already exists in CodiMD:
      fname = zipinfo.filename
      res = requests.head(WB.codimdurl + '/uploads/' + fname, verify=False)
      if res.status_code == http.client.OK and int(res.headers['Content-Length']) == zipinfo.file_size:
        # yes (assume that hashed filename AND size matching is a good enough content match!)
        WB.log.debug('msg="Skipped existing attachment" filename="%s"' % fname)
        continue
      # check for collision
      if res.status_code == http.client.OK:
        WB.log.warning('msg="Attachment collision detected" filename="%s"' % fname)
        # append a random letter to the filename
        name, ext = os.path.splitext(fname)
        fname = name + chr(randint(65, 65+26)) + ext
        # and replace its reference in the document (this creates a copy, not very efficient)
        mddoc = mddoc.replace(zipinfo.filename, fname)
      # OK, let's upload
      WB.log.debug('msg="Pushing attachment" filename="%s"' % fname)
      res = requests.post(WB.codimdurl + '/uploadimage', params={'generateFilename': 'false'},
                          files={'image': (fname, inputzip.read(zipinfo))}, verify=False)
      if res.status_code != http.client.OK:
        WB.log.error('msg="Failed to push included file" filename="%s" httpcode="%d"' % (fname, res.status_code))
  return mddoc


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
    mddoc = _unzipattachments(mdfile)
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
    WB.log.error('msg="Unable to push document to CodiMD" token="%s" response="%s: %s"' % \
                 (acctok[-20:], res.status_code, res.content))
    raise CodiMDFailure
  WB.log.debug('msg="Got redirect from CodiMD" url="%s"' % res.next.url)
  # we got the hash of the document just created as a redirected URL, store it in our WOPI lock structure
  # the lock is a dict { docid, filename, digest, app }
  wopilock = {'docid': '/' + urllib.parse.urlsplit(res.next.url).path.split('/')[-1],
              'filename': filemd['BaseFileName'],
              'digest': h.hexdigest(),
              'app': 'slide' if mddoc[:10].decode() == '---\ntitle:' else 'md',
              }
  WB.log.info('msg="Pushed document to CodiMD" url="%s" token="%s"' % (wopilock['docid'], acctok[-20:]))
  return wopilock


def _codimdtostorage(wopisrc, acctok, isclose, wopilock):
  '''Copy document from CodiMD back to storage'''
  # get document from CodiMD
  WB.log.info('msg="Fetching file from CodiMD" isclose="%s" codimdurl="%s" token="%s"' % \
              (isclose, WB.codimdurl + wopilock['docid'], acctok[-20:]))
  res = requests.get(WB.codimdurl + wopilock['docid'] + '/download', verify=False)
  if res.status_code != http.client.OK:
    return 'Failed to fetch document from CodiMD', res.status_code
  mddoc = res.content

  if isclose and wopilock['digest'] != 'dirty':
    # so far the file was not touched and we are about to close: before forcing a put let's validate the contents
    h = hashlib.sha1()
    h.update(mddoc)
    if h.hexdigest() == wopilock['digest']:
      WB.log.info('msg="File unchanged, skipping save" token="%s"' % acctok[-20:])
      return 'OK', http.client.OK

  # check if we have attachments
  wasbundle = os.path.splitext(wopilock['filename'])[1] == '.zmd'
  bundlefile = _getattachments(mddoc.decode(), wopilock['filename'].replace('.zmd', '.md'), (wasbundle and not isclose))

  # WOPI PutFile for the file or the bundle if it already existed
  if (wasbundle ^ (not bundlefile)) or not isclose:
    res = _wopicall(wopisrc, acctok, 'POST', headers={'X-WOPI-Lock': json.dumps(wopilock)},
                    contents=(bundlefile if wasbundle else mddoc))
    if res.status_code != http.client.OK:
      WB.log.error('msg="Calling WOPI PutFile failed" url="%s" response="%s"' % (wopisrc, res.status_code))
      return 'Error saving the file', res.status_code
    # and refresh the WOPI lock
    _refreshlock(wopisrc, acctok, True, wopilock)
    WB.log.info('msg="Save completed" token="%s"' % acctok[-20:])
    return 'OK', http.client.OK

  # On close, use WOPI PutRelative for either the new bundle, if this is the first time we have attachments,
  # or the single md file, if there are no more attachments.
  putrelheaders = {'X-WOPI-Lock': json.dumps(wopilock),
                   'X-WOPI-Override': 'PUT_RELATIVE',
                   # SuggestedTarget to not overwrite a possibly existing file
                   'X-WOPI-SuggestedTarget': os.path.splitext(wopilock['filename'])[0] + ('.zmd' if bundlefile else '.md')
                  }
  res = _wopicall(wopisrc, acctok, 'POST', headers=putrelheaders, contents=(bundlefile if bundlefile else mddoc))
  if res.status_code != http.client.OK:
    WB.log.error('msg="Calling WOPI PutRelative failed" url="%s" response="%s"' % (wopisrc, res.status_code))
    return 'Error saving the file', res.status_code

  # use the new file's metadata from PutRelative to remove the previous file: we can do that only on close
  # because we need to keep using the current wopisrc/acctok until the session is alive in CodiMD
  res = res.json()
  newwopi = urllib.parse.unquote(res['Url'])
  newwopisrc = newwopi[:newwopi.find('?')]
  newacctok = newwopi[newwopi.find('access_token=')+13:]
  newlock = json.loads(json.dumps(wopilock))    # this is a hack for a deep copy, to be redone in Go
  newlock['filename'] = res['Name']
  res = _wopicall(newwopisrc, newacctok, 'POST', headers={'X-WOPI-Lock': json.dumps(newlock), 'X-Wopi-Override': 'LOCK'})
  if res.status_code != http.client.OK:
    # Failed to lock the new file just written, not a big deal as we're closing
    WB.log.warning('msg="Failed to lock the new file" token="%s" response="%d"' % (newacctok[-20:], res.status_code))

  # unlock and delete original file
  res = _wopicall(wopisrc, acctok, 'POST', headers={'X-WOPI-Lock': json.dumps(wopilock), 'X-Wopi-Override': 'UNLOCK'})
  if res.status_code != http.client.OK:
    WB.log.warning('msg="Failed to unlock the previous file" token="%s" response="%d"' % (acctok[-20:], res.status_code))
  else:
    res = _wopicall(wopisrc, acctok, 'POST', headers={'X-Wopi-Override': 'DELETE'})
    if res.status_code == http.client.OK:
      WB.log.info('msg="Previous file unlocked and removed successfully" token="%s"' % acctok[-20:])

  # update our metadata: note we already hold the condition variable as we're called within the save thread
  WB.openfiles[newwopisrc] = {'acctok': newacctok, 'isclose': isclose, 'tosave': False, 'lastsave': int(time.time())}
  del WB.openfiles[wopisrc]

  WB.log.info('msg="Final save completed" token="%s"' % acctok[-20:])
  return 'OK', http.client.OK


#
# The REST methods start here
#
@WB.app.route("/open", methods=['GET'])
def appopen():
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
  except json.decoder.JSONDecodeError as e:
    WB.log.warning('msg="Malformed JSON from WOPI" error="%s" response="%d"' % (e, res.status_code))
    return 'Invalid WOPI context', http.client.NOT_FOUND

  try:
    # use the 'UserCanWrite' attribute to decide whether the file is to be opened in read-only mode
    if filemd['UserCanWrite']:
      # WOPI GetLock (ignore failures)
      res = _wopicall(wopisrc, acctok, 'POST', headers={'X-Wopi-Override': 'GET_LOCK'})
      wopilock = res.headers.pop('X-WOPI-Lock', None)   # if present, the lock is a dict { docid, filename, digest, app }
      if wopilock:
        try:
          wopilock = json.loads(wopilock)
          # file is already locked and it's a JSON: assume we hold it
          WB.log.info('msg="Lock already held" lock="%s"' % wopilock)
        except json.decoder.JSONDecodeError:
          # this lock cannot be parsed, probably got corrupted: force read-only mode
          WB.log.warning('msg="Malformed lock, forcing read-only mode" lock="%s"' % wopilock)
          filemd['UserCanWrite'] = False
          wopilock = None

      if not wopilock:
        # file is not locked or lock is unreadable, fetch the file from storage and populate wopilock
        wopilock = _storagetocodimd(filemd, wopisrc, acctok)
      # WOPI Lock
      lockheaders = {'X-WOPI-Lock': json.dumps(wopilock), 'X-Wopi-Override': 'LOCK'}
      res = _wopicall(wopisrc, acctok, 'POST', headers=lockheaders)
      if res.status_code != http.client.OK:
        # Failed to lock the file: open in read-only mode
        WB.log.warning('msg="Failed to lock the file" token="%s" response="%d"' % (acctok[-20:], res.status_code))
        filemd['UserCanWrite'] = False

    else:
      # user has no write privileges, just fetch document and push it to CodiMD
      wopilock = _storagetocodimd(filemd, wopisrc, acctok)

    if filemd['UserCanWrite']:
      # keep track of this open document for the save thread and statistical purposes
      # if it was already opened, this will overwrite the previous metadata: that's fine
      WB.openfiles[wopisrc] = {'acctok': acctok, 'isclose': False, 'tosave': False,
                               'lastsave': int(time.time()) - WB.saveinterval}
      # create the external redirect URL to be returned to the client:
      # metadata will be used for autosave (this is an extended feature of CodiMD)
      redirecturl = WB.codimdexturl + wopilock['docid'] + \
                    '?metadata=' + urllib.parse.quote_plus('%s?t=%s' % (wopisrc, acctok)) + '&'
    else:
      # read-only mode: in this case redirect to publish mode or slide mode depending on the content
      redirecturl = WB.codimdexturl + wopilock['docid'] + ('/slide?' if wopilock['app'] == 'slide' else '/publish?')
    # append displayName (again this is an extended feature of CodiMD)
    redirecturl += 'displayName=' + urllib.parse.quote_plus(filemd['UserFriendlyName'])

    WB.log.info('msg="Redirecting client to CodiMD" redirecturl="%s"' % redirecturl)
    return flask.redirect(redirecturl)

  except CodiMDFailure:
    # this can be risen by _storagetocodimd
    return 'Unable to contact CodiMD, please try again later', http.client.INTERNAL_SERVER_ERROR


@WB.app.route("/save", methods=['POST'])
def appsave():
  '''Save a MD doc given its WOPI context. The actual save is asynchronous.'''
  # fetch metadata from request
  try:
    meta = urllib.parse.unquote(flask.request.headers['X-EFSS-Metadata'])
    wopisrc = meta[:meta.index('?t=')]
    acctok = meta[meta.index('?t=')+3:]
    isclose = 'close' in flask.request.args and flask.request.args['close'] == 'true'
  except (KeyError, ValueError) as e:
    WB.log.error('msg="Save: malformed or missing metadata" client="%s" headers="%s" exception="%s" error="%s"' % \
      (flask.request.remote_addr, flask.request.headers, type(e), e))
    return 'Malformed or missing metadata', http.client.BAD_REQUEST

  # decide whether to notify the save thread
  donotify = isclose or wopisrc not in WB.openfiles or WB.openfiles[wopisrc]['lastsave'] < time.time() - WB.saveinterval
  # enqueue the request, it will be processed asynchronously
  with WB.savecv:
    if wopisrc in WB.openfiles:
      WB.openfiles[wopisrc]['tosave'] = True
      WB.openfiles[wopisrc]['isclose'] = isclose
    else:
      WB.log.debug('msg="Save: repopulating missing metadata" token="%s"' % acctok[-20:])
      WB.openfiles[wopisrc] = {'acctok': acctok, 'isclose': isclose, 'tosave': True,
                               'lastsave': int(time.time() - WB.saveinterval)}
    if donotify:
      WB.savecv.notify()   # note that the save thread stays locked until we release the context, after return!
    # return latest known state for this document
    if wopisrc in WB.saveresponses:
      resp = WB.saveresponses[wopisrc]
      WB.log.info('msg="Save: returned response" client="%s" response="%s"' % \
                  (flask.request.remote_addr, resp))
      del WB.saveresponses[wopisrc]
      return resp
    WB.log.info('msg="Save: enqueued action" wopisrc="%s"' % wopisrc)
    return 'Enqueued', http.client.ACCEPTED


@WB.app.route("/list", methods=['GET'])
def applist():
  '''Return a list of all currently opened files'''
  # TODO this API should be protected
  return flask.Response(json.dumps(WB.openfiles), mimetype='application/json')


#
## Code for the async thread for save operations
#
def _getwopilock(wopisrc, acctok):
  '''Get the currently held WOPI lock, and return None if not found'''
  try:
    res = _wopicall(wopisrc, acctok, 'POST', headers={'X-Wopi-Override': 'GET_LOCK'})
    if res.status_code != http.client.OK:
      # lock got lost
      raise ValueError(res.status_code)
    return json.loads(res.headers.pop('X-WOPI-Lock'))   # the lock is expected to be a dict { docid, filename, digest, app }
  except (ValueError, KeyError, json.decoder.JSONDecodeError) as e:
    WB.log.error('msg="Malformed or missing WOPI lock" exception="%s" error="%s"' % (type(e), e))
    raise InvalidLock


def dosavetostorage():
  '''Perform the pending save to storage operations'''
  while WB.active:
    with WB.savecv:
      # sleep for one minute or until awaken
      WB.savecv.wait(60)

      # execute a round of sync to storage; list is needed as we may delete entries from the dict
      for wopisrc, openfile in list(WB.openfiles.items()):
        try:
          wopilock = None
          # save documents that are dirty for more than `saveinterval` or that are being closed
          if openfile['tosave'] and (openfile['isclose'] or (openfile['lastsave'] < time.time() - WB.saveinterval)):
            wopilock = _getwopilock(wopisrc, openfile['acctok'])
            WB.saveresponses[wopisrc] = _codimdtostorage(wopisrc, openfile['acctok'], openfile['isclose'], wopilock)
            openfile['lastsave'] = int(time.time())
            openfile['tosave'] = False

          # refresh locks of idle documents every 30 minutes
          if openfile['lastsave'] < time.time() - (1800 + WB.saveinterval):
            wopilock = _getwopilock(wopisrc, openfile['acctok']) if not wopilock else wopilock
            _refreshlock(wopisrc, openfile['acctok'], False, wopilock)
            # in case we get soon a save callback, we want to honor it immediately
            openfile['lastsave'] = int(time.time()) - WB.saveinterval

          # remove state for closed documents after some time
          if openfile['isclose'] and not openfile['tosave'] and (openfile['lastsave'] < time.time() - WB.saveinterval):
            # unlock document
            wopilock = _getwopilock(wopisrc, openfile['acctok']) if not wopilock else wopilock
            res = _wopicall(wopisrc, openfile['acctok'], 'POST',
                            headers={'X-WOPI-Lock': json.dumps(wopilock), 'X-Wopi-Override': 'UNLOCK'})
            if res.status_code != http.client.OK:
              WB.log.warning('msg="dosavetostorage: calling WOPI Unlock failed" url="%s" response="%s"' % \
                             (wopisrc, res.status_code))
            else:
              WB.log.info('msg="dosavetostorage: unlocked document" metadata="%s"' % openfile)
            del WB.openfiles[wopisrc]

        except InvalidLock as e:
          # WOPI lock got lost
          WB.saveresponses[wopisrc] = 'Failed to save document, malformed or missing lock', http.client.NOT_FOUND
          del WB.openfiles[wopisrc]

        except Exception as e:    # pylint: disable=broad-except
          ex_type, ex_value, ex_traceback = sys.exc_info()
          WB.log.error('msg="dosyncstorage: unexpected exception caught" exception="%s" type="%s" traceback="%s"' % \
                       (e, ex_type, traceback.format_exception(ex_type, ex_value, ex_traceback)))


@atexit.register
def stopsavethread():
  '''Exit handler to cleanly stop the storage sync thread'''
  WB.log.info('msg="Waiting for storage sync thread to complete"')
  print('msg="Waiting for storage sync thread to complete"\n')
  WB.savecv.acquire()
  WB.active = False
  WB.savecv.notify()
  WB.savecv.release()
  WB.savethread.join()
  WB.log.info('msg="Terminating WOPI Bridge service"')


#
# Start the Flask endless listening loop and the background sync thread
#
if __name__ == '__main__':
  WB.init()
  WB.run()
