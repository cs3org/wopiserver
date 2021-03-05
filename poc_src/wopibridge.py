#!/usr/bin/python3
'''
wopibridge.py

The WOPI bridge for IOP. This PoC only integrates CodiMD
and for now the code is not fully abstracted to support other integrations.

Author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

import os
import sys
import time
import traceback
import socket
from platform import python_version
import logging
import logging.handlers
import urllib.parse
import http.client
import json
import threading
import atexit
import functools
try:
    import flask
    from werkzeug.exceptions import NotFound as Flask_NotFound
    from werkzeug.exceptions import MethodNotAllowed as Flask_MethodNotAllowed
    import wopiclient as wopi
except ImportError:
    print("Missing modules, please install with `pip3 install flask requests`")
    raise
import codimd

WBVERSION = 'git'

# this is the default location of secrets in docker
CERTPATH = '/var/run/secrets/cert.pem'

# path to a secret used to hash noteids and protect the /list endpoint
SECRETPATH = '/var/run/secrets/wbsecret'

# a standard message to be displayed by the app when some content might be lost: this would only
# appear in case of uncaught exceptions or bugs handling the CodiMD webhook
RECOVER_MSG = 'Please copy the content in a safe place and reopen the document afresh to paste it back.'


class WB:
    '''A singleton container for all state information of the server'''
    approot = os.getenv(
        'APP_ROOT', '/wopib')               # application root path
    bpr = flask.Blueprint('WOPIBridge', __name__, url_prefix=approot)
    app = flask.Flask('WOPIBridge')
    log = app.logger
    port = 8000
    skipsslverify = False
    loglevels = {"Critical": logging.CRITICAL,  # 50
                 "Error":    logging.ERROR,     # 40
                 "Warning":  logging.WARNING,   # 30
                 "Info":     logging.INFO,      # 20
                 "Debug":    logging.DEBUG      # 10
                }
    active = True
    # a map of all open documents: wopisrc -> (acctok, tosave, lastsave, toclose)
    openfiles = {}
    # where acctok is one of the access tokens for the given doc, and
    # toclose is a dict {shorttok -> isclose} with shorttok = 20 last chars of all known tokens
    saveresponses = {}  # a map of responses: wopisrc -> (http code, message)
    # a condition variable to synchronize the save thread and the main Flask threads
    savecv = threading.Condition()

    @classmethod
    def init(cls):
        '''Initialises the application, bails out in case of failures. Note this is not a __init__ method'''
        cls.app.register_blueprint(cls.bpr)
        try:
            # configuration
            loghandler = logging.FileHandler('/var/log/wopi/wopibridge.log')
            loghandler.setFormatter(logging.Formatter(fmt='%(asctime)s %(name)s[%(process)d] %(levelname)-8s %(message)s',
                                                      datefmt='%Y-%m-%dT%H:%M:%S'))
            cls.log.addHandler(loghandler)
            cls.log.setLevel(cls.loglevels['Debug'])
            # this is the external-facing URL
            codimd.codimdexturl = os.environ.get('CODIMD_EXT_URL')
            # this is the internal URL (e.g. as visible in docker/K8s)
            codimd.codimdurl = os.environ.get('CODIMD_INT_URL')
            skipsslverify = os.environ.get('SKIP_SSL_VERIFY')
            if isinstance(skipsslverify, str):
                cls.skipsslverify = skipsslverify.upper() in ('TRUE', 'YES')
            else:
                cls.skipsslverify = False
            if not codimd.codimdurl:
                # defaults to the external
                codimd.codimdurl = codimd.codimdexturl
            if not codimd.codimdurl:
                # this is the only mandatory option
                raise ValueError("Missing CODIMD_EXT_URL configuration")
            try:
                cls.saveinterval = int(os.environ.get('APP_SAVE_INTERVAL'))
            except TypeError:
                cls.saveinterval = 200
            try:
                cls.saveinterval = int(os.environ.get('APP_UNLOCK_INTERVAL'))
            except TypeError:
                cls.unlockinterval = 120
            # init modules
            codimd.log = wopi.log = cls.log
            codimd.skipsslverify = wopi.skipsslverify = cls.skipsslverify
            with open(SECRETPATH) as f:
                cls.hashsecret = f.readline().strip('\n')
                codimd.hashsecret = cls.hashsecret.encode()

            # start the thread to perform async save operations
            cls.savethread = SaveThread()
            cls.savethread.start()

        except Exception as e:    # pylint: disable=broad-except
            # any error we get here with the configuration is fatal
            cls.log.fatal('msg="Failed to initialize the service, aborting" error="%s"' % e)
            sys.exit(-22)

    @classmethod
    def run(cls):
        '''Runs the Flask app in secure (standalone) or unsecure mode depending on the context.
           Secure https mode typically is to be provided by the infrastructure (k8s ingress, nginx...)'''
        if os.path.isfile(CERTPATH):
            cls.log.info('msg="WOPI Bridge starting in secure mode" baseUrl="%s"' % cls.approot)
            cls.app.run(host='0.0.0.0', port=cls.port, threaded=True, debug=True,
                        ssl_context=(CERTPATH, CERTPATH.replace('cert', 'key')))
        else:
            cls.log.info('msg="WOPI Bridge starting in unsecure mode" baseUrl="%s"' % cls.approot)
            cls.app.run(host='0.0.0.0', port=cls.port, threaded=True, debug=True)


def _guireturn(msg):
    '''One-liner to better render messages that may be visible in the user UI'''
    return '<div align="center" style="color:#A0A0A0; padding-top:50px; font-family:Verdana">%s</div>' % msg


# The Web Application starts here
#############################################################################################################

@WB.app.errorhandler(Exception)
def handleexception(ex):
    '''Generic method to log any uncaught exception'''
    if isinstance(ex, (Flask_NotFound, Flask_MethodNotAllowed)):
        return ex
    ex_type, ex_value, ex_traceback = sys.exc_info()
    WB.log.error('msg="Unexpected exception caught" exception="%s" type="%s" traceback="%s"' %
                 (ex, ex_type, traceback.format_exception(ex_type, ex_value, ex_traceback)))
    return codimd.jsonify('Internal error, please contact support. %s' % RECOVER_MSG), http.client.INTERNAL_SERVER_ERROR


@WB.app.route("/", methods=['GET'])
def redir():
    '''A simple redirect to the page below'''
    return flask.redirect(WB.approot + '/')


@WB.bpr.route("/", methods=['GET'])
def index():
    '''Return a default index page with some user-friendly information about this service'''
    #WB.log.debug('msg="Accessed index page" client="%s"' % flask.request.remote_addr)
    return """
    <html><head><title>ScienceMesh WOPI Bridge</title></head>
    <body>
    <div align="center" style="color:#000080; padding-top:50px; font-family:Verdana; size:11">
    This is a WOPI HTTP bridge, to be used in conjunction with a WOPI-enabled EFSS.<br>Only CodiMD is supported for now.<br>
    To use this service, please log in to your EFSS Storage and click on a supported document.</div>
    <div style="position: absolute; bottom: 10px; left: 10px; width: 99%%;"><hr>
    <i>ScienceMesh WOPI Bridge %s at %s. Powered by Flask %s for Python %s</i>.</div>
    </body>
    </html>
    """ % (WBVERSION, socket.getfqdn(), flask.__version__, python_version())


@WB.bpr.route("/open", methods=['GET'])
def appopen():
    '''Open a MD doc by contacting the provided WOPISrc with the given access_token'''
    try:
        wopisrc = urllib.parse.unquote(flask.request.args['WOPISrc'])
        acctok = flask.request.args['access_token']
        WB.log.info('msg="Open called" client="%s" token="%s"' %
                    (flask.request.remote_addr, acctok[-20:]))
    except KeyError as e:
        WB.log.error('msg="Open: unable to open the file, missing WOPI context" error="%s"' % e)
        return _guireturn('Missing arguments'), http.client.BAD_REQUEST

    # WOPI GetFileInfo
    res = wopi.request(wopisrc, acctok, 'GET')
    if res.status_code != http.client.OK:
        WB.log.warning('msg="Open: unable to fetch file WOPI metadata" response="%d"' % res.status_code)
        return _guireturn('Invalid WOPI context'), http.client.NOT_FOUND
    filemd = res.json()

    try:
        # use the 'UserCanWrite' attribute to decide whether the file is to be opened in read-only mode
        if filemd['UserCanWrite']:
            try:
                # was it already being worked on?
                wopilock = wopi.getlock(wopisrc, acctok)
                WB.log.info('msg="Lock already held" lock="%s"' % wopilock)
                # add this token to the list, if not already in
                if acctok[-20:] not in wopilock['toclose']:
                    wopilock = wopi.refreshlock(wopisrc, acctok, wopilock)
            except wopi.InvalidLock as e:
                if str(e) != str(int(http.client.NOT_FOUND)):
                    # lock is invalid/corrupted: force read-only mode
                    WB.log.info('msg="Invalid lock, forcing read-only mode" token="%s" error="%s"' % (acctok[-20:], e))
                    filemd['UserCanWrite'] = False

                # otherwise, this is the first user opening the file; in both cases, fetch it
                wopilock = codimd.loadfromstorage(filemd, wopisrc, acctok)
                # and WOPI Lock it
                res = wopi.request(wopisrc, acctok, 'POST', headers={'X-WOPI-Lock': json.dumps(wopilock),
                                                                     'X-Wopi-Override': 'LOCK'})
                if res.status_code != http.client.OK:
                    # failed to lock the file: open in read-only mode
                    WB.log.warning('msg="Failed to lock the file" response="%d" token="%s"' %
                                   (res.status_code, acctok[-20:]))
                    filemd['UserCanWrite'] = False

        else:
            # user has no write privileges, just fetch document and push it to CodiMD
            wopilock = codimd.loadfromstorage(filemd, wopisrc, acctok)
    except codimd.CodiMDFailure:
        # this can be raised by loadfromstorage
        return _guireturn('Unable to contact CodiMD, please try again later'), http.client.INTERNAL_SERVER_ERROR

    redirecturl = _redirecttocodimd(filemd['UserCanWrite'], wopisrc, acctok, wopilock) + \
                  'displayName=' + urllib.parse.quote_plus(filemd['UserFriendlyName'])
    WB.log.info('msg="Redirecting client to CodiMD" redirecturl="%s"' % redirecturl)
    return flask.redirect(redirecturl)


def _redirecttocodimd(isreadwrite, wopisrc, acctok, wopilock):
    '''Updates internal metadata and returns the correct redirect URL to CodiMD'''
    if isreadwrite:
        # keep track of this open document for the save thread and for statistical purposes
        if wopisrc in WB.openfiles:
            # use the new acctok and the new/current wopilock content
            WB.openfiles[wopisrc]['acctok'] = acctok
            WB.openfiles[wopisrc]['toclose'] = wopilock['toclose']
        else:
            WB.openfiles[wopisrc] = {'acctok': acctok, 'tosave': False,
                                     'lastsave': int(time.time()) - WB.saveinterval,
                                     'toclose': {acctok[-20:]: False},
                                     'docid': wopilock['docid'],
                                    }
        # also clear any potential stale response for this document
        try:
            del WB.saveresponses[wopisrc]
        except KeyError:
            pass
        # create the external redirect URL to be returned to the client:
        # metadata will be used for autosave (this is an extended feature of CodiMD)
        redirecturl = codimd.codimdexturl + wopilock['docid'] + '?metadata=' + \
                      urllib.parse.quote_plus('%s?t=%s' % (wopisrc, acctok)) + '&'
    else:
        # read-only mode: in this case redirect to publish mode or normal view
        # to quickly jump in slide mode depending on the content
        redirecturl = codimd.codimdexturl + wopilock['docid'] + \
                      ('/publish?' if wopilock['app'] != 'slide' else '?')
    return redirecturl


@WB.bpr.route("/save", methods=['POST'])
def appsave():
    '''Save a MD doc given its WOPI context, and return a JSON-formatted message. The actual save is asynchronous.'''
    # fetch metadata from request
    try:
        meta = urllib.parse.unquote(flask.request.headers['X-EFSS-Metadata'])
        wopisrc = meta[:meta.index('?t=')]
        acctok = meta[meta.index('?t=')+3:]
        isclose = flask.request.args.get('close') == 'true'
        docid = flask.request.args.get('id')
        WB.log.info('msg="Save: requested action" isclose="%s" docid="%s" wopisrc="%s" token="%s"' %
                    (isclose, docid, wopisrc, acctok[-20:]))
    except (KeyError, ValueError) as e:
        WB.log.error('msg="Save: malformed or missing metadata" client="%s" headers="%s" exception="%s" error="%s"' %
                     (flask.request.remote_addr, flask.request.headers, type(e), e))
        return codimd.jsonify('Malformed or missing metadata, could not save. %s' % RECOVER_MSG), http.client.BAD_REQUEST

    # decide whether to notify the save thread
    donotify = isclose or wopisrc not in WB.openfiles or WB.openfiles[wopisrc]['lastsave'] < time.time() - WB.saveinterval
    # enqueue the request, it will be processed asynchronously
    with WB.savecv:
        if wopisrc in WB.openfiles:
            WB.openfiles[wopisrc]['tosave'] = True
            WB.openfiles[wopisrc]['toclose'][acctok[-20:]] = isclose
        else:
            WB.log.info('msg="Save: repopulating missing metadata" wopisrc="%s" token="%s"' % (wopisrc, acctok[-20:]))
            WB.openfiles[wopisrc] = {'acctok': acctok, 'tosave': True,
                                     'lastsave': int(time.time() - WB.saveinterval),
                                     'toclose': {acctok[-20:]: isclose},
                                     'docid': docid,
                                    }
            # if it's the first time we heard about this wopisrc, remove any potential stale response
            try:
                del WB.saveresponses[wopisrc]
            except KeyError:
                pass
        if donotify:
            # note that the save thread stays locked until we release the context, after return!
            WB.savecv.notify()
        # return latest known state for this document
        if wopisrc in WB.saveresponses:
            resp = WB.saveresponses[wopisrc]
            WB.log.info('msg="Save: returned response" response="%s" token="%s"' % (resp, acctok[-20:]))
            del WB.saveresponses[wopisrc]
            return resp
        WB.log.info('msg="Save: enqueued action" token="%s"' % acctok[-20:])
        return '{}', http.client.ACCEPTED


@WB.bpr.route("/list", methods=['GET'])
def applist():
    '''Return a list of all currently opened files'''
    if (flask.request.headers.get('Authorization') != 'Bearer ' + WB.hashsecret) and \
       (flask.request.args.get('auth') != WB.hashsecret):     # added for convenience for the time being
        WB.log.warning('msg="List: unauthorized access attempt, missing authorization token" '
                       'client="%s"' % flask.request.remote_addr)
        return 'Client not authorized', http.client.UNAUTHORIZED
    WB.log.info('msg="List: returned all open files metadata"')
    return flask.Response(json.dumps(WB.openfiles), mimetype='application/json')


#############################################################################################################

def _intersection(boolsd):
    '''Given a dictionary of booleans, returns the intersection (AND) of all'''
    return functools.reduce(lambda x, y: x and y, list(boolsd.values()))

def _union(boolsd):
    '''Given a dictionary of booleans, returns the union (OR) of all'''
    return functools.reduce(lambda x, y: x or y, list(boolsd.values()))

class SaveThread(threading.Thread):
    '''Async thread for save operations'''

    def run(self):
        '''Perform all pending save to storage operations'''
        WB.log.info('msg="SaveThread starting"')
        while True:
            with WB.savecv:
                # sleep for one minute or until awaken
                WB.savecv.wait(60)
                if not WB.active:
                    break
                # execute a round of sync to storage; list is needed as entries are eventually deleted from the dict
                for wopisrc, openfile in list(WB.openfiles.items()):
                    try:
                        wopilock = self.savedirty(openfile, wopisrc)
                        wopilock = self.closewhenidle(openfile, wopisrc, wopilock)
                        self.cleanup(openfile, wopisrc, wopilock)
                    except Exception as e:    # pylint: disable=broad-except
                        ex_type, ex_value, ex_traceback = sys.exc_info()
                        WB.log.error('msg="SaveThread: unexpected exception caught" ex="%s" type="%s" traceback="%s"' %
                                     (e, ex_type, traceback.format_exception(ex_type, ex_value, ex_traceback)))
        WB.log.info('msg="SaveThread terminated, shutting down"')

    def savedirty(self, openfile, wopisrc):
        '''save documents that are dirty for more than `saveinterval` or that are being closed'''
        wopilock = None
        if openfile['tosave'] and (_intersection(openfile['toclose'])
                                   or (openfile['lastsave'] < time.time() - WB.saveinterval)):
            try:
                wopilock = wopi.getlock(wopisrc, openfile['acctok'])
            except wopi.InvalidLock:
                WB.log.info('msg="SaveThread: attempting to relock file" token="%s" docid="%s"' %
                            (openfile['acctok'][-20:], openfile['docid']))
                try:
                    wopilock = WB.saveresponses[wopisrc] = wopi.relock(
                        wopisrc, openfile['acctok'], openfile['docid'], _intersection(openfile['toclose']))
                except wopi.InvalidLock as ile:
                    # even this attempt failed, give up
                    # TODO here we should save the file on a local storage to help later recovery
                    WB.saveresponses[wopisrc] = codimd.jsonify(str(ile)), http.client.NOT_FOUND
                    # set some 'fake' metadata, will be automatically cleaned up later
                    openfile['lastsave'] = int(time.time())
                    openfile['tosave'] = False
                    openfile['toclose'] = {'invalid-lock': True}
                    return None
            WB.log.info('msg="SaveThread: saving file" token="%s" docid="%s"' %
                        (openfile['acctok'][-20:], openfile['docid']))
            WB.saveresponses[wopisrc] = codimd.savetostorage(
                wopisrc, openfile['acctok'], _intersection(openfile['toclose']), wopilock)
            openfile['lastsave'] = int(time.time())
            openfile['tosave'] = False
        return wopilock

    def closewhenidle(self, openfile, wopisrc, wopilock):
        '''close and unlock documents tha are idle for more than 60 minutes.
        They will transparently be relocked when/if the session resumes, but we seem to miss some close notifications,
        therefore this also works as a cleanup step'''
        if openfile['lastsave'] < int(time.time()) - 3600:
            try:
                wopilock = wopi.getlock(wopisrc, openfile['acctok']) if not wopilock else wopilock
                # this will force a close in the cleanup step
                openfile['toclose'] = {t: True for t in openfile['toclose']}
                WB.log.info('msg="SaveThread: force-closing document" lastsavetime="%s" toclosetokens="%s"' %
                            (openfile['lastsave'], openfile['toclose']))
            except wopi.InvalidLock:
                # lock is gone, just cleanup our metadata
                WB.log.warning('msg="SaveThread: cleaning up metadata, detected missed close event" url="%s"' % wopisrc)
                del WB.openfiles[wopisrc]
        return wopilock

    def cleanup(self, openfile, wopisrc, wopilock):
        '''remove state for closed documents after some time'''
        if _union(openfile['toclose']) and not openfile['tosave']:
            # check lock
            try:
                wopilock = wopi.getlock(wopisrc, openfile['acctok']) if not wopilock else wopilock
            except wopi.InvalidLock:
                # nothing to do here, this document may have been closed by another wopibridge
                if openfile['lastsave'] < time.time() - WB.unlockinterval:
                    # yet cleanup only after the unlockinterval time, cf. the InvalidLock handling in savedirty()
                    WB.log.info('msg="SaveThread: cleaning up metadata, file already unlocked" url="%s"' % wopisrc)
                    del WB.openfiles[wopisrc]
                return

            # reconcile list of toclose tokens
            openfile['toclose'] = {t: wopilock['toclose'][t] or (t in openfile['toclose'] and openfile['toclose'][t])
                                   for t in wopilock['toclose']}
            if _intersection(openfile['toclose']):
                if openfile['lastsave'] < int(time.time()) - WB.unlockinterval:
                    # nobody is still on this document and some time has passed, unlock
                    res = wopi.request(wopisrc, openfile['acctok'], 'POST',
                                       headers={'X-WOPI-Lock': json.dumps(wopilock), 'X-Wopi-Override': 'UNLOCK'})
                    if res.status_code != http.client.OK:
                        WB.log.warning('msg="SaveThread: failed to unlock" lastsavetime="%s" token="%s" response="%s"' %
                                       (openfile['lastsave'], openfile['acctok'][-20:], res.status_code))
                    else:
                        WB.log.info('msg="SaveThread: unlocked document" lastsavetime="%s" token="%s"' %
                                    (openfile['lastsave'], openfile['acctok'][-20:]))
                    del WB.openfiles[wopisrc]
            elif openfile['toclose'] != wopilock['toclose']:
                # some user still on it, refresh lock if the toclose part has changed
                wopi.refreshlock(wopisrc, openfile['acctok'], wopilock, toclose=openfile['toclose'])


@atexit.register
def stopsavethread():
    '''Exit handler to cleanly stop the storage sync thread'''
    WB.log.info('msg="Waiting for SaveThread to complete"')
    with WB.savecv:
        WB.active = False
        WB.savecv.notify()


#
# Start the Flask endless listening loop and the background sync thread
#
if __name__ == '__main__':
    WB.init()
    WB.run()
