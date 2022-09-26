'''
The WOPI bridge extension for IOP. This connector service supports CodiMD and Etherpad.

Main author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

import sys
import time
import traceback
import threading
import atexit
import functools
import urllib.parse as urlparse
import http.client
import json
import hashlib
import hmac
from base64 import urlsafe_b64encode
import flask
import bridge.wopiclient as wopic
import core.wopiutils as utils


# The supported plugins integrated with the WOPI Bridge extensions
BRIDGE_EXT_PLUGINS = {'md': 'codimd', 'txt': 'codimd', 'zmd': 'codimd', 'epd': 'etherpad', 'zep': 'etherpad'}

# The header that bridged apps are expected to send to the save endpoint
BRIDGED_APP_HEADER = 'X-Efss-Bridged-App'

# a standard message to be displayed by the app when some content might be lost: this would only
# appear in case of uncaught exceptions or bugs handling the webhook callbacks
RECOVER_MSG = 'Please copy the content to a safe place and reopen the document again to paste it back.'


class FailedOpen(Exception):
    '''A custom exception raised by appopen() in case of failures'''

    def __init__(self, msg, statuscode):
        '''Initialize the exception with the arguments for an HTTP Response'''
        super().__init__()
        self.msg = msg
        self.statuscode = statuscode
        self.args = (msg, statuscode)


class WB:
    '''A singleton container for all state information of the server'''
    log = None
    hashsecret = None
    sslverify = True
    active = False
    # a map of all open documents: wopisrc -> (acctok, tosave, lastsave, toclose)
    # where acctok is one of the access tokens for the given doc, and
    # toclose is a dict {shorttok -> isclose} with shorttok = 20 last chars of all known tokens
    openfiles = {}
    # a map of responses: wopisrc -> (http code, message)
    saveresponses = {}
    # the save thread, to asynchronously save dirty or closed files
    savethread = None
    # a condition variable to synchronize the save thread and the main Flask threads
    savecv = threading.Condition()
    # a map file-extension -> application plugin
    plugins = {}

    @classmethod
    def init(cls, config, log, secret):
        '''Initialises the application, bails out in case of failures. Note this is not a __init__ method'''
        cls.sslverify = config.get('bridge', 'sslverify', fallback='True').upper() in ('TRUE', 'YES')
        cls.saveinterval = int(config.get('bridge', 'saveinterval', fallback='200'))
        cls.unlockinterval = int(config.get('bridge', 'unlockinterval', fallback='90'))
        cls.disablezip = config.get('bridge', 'disablezip', fallback='False').upper() in ('TRUE', 'YES')
        cls.hashsecret = secret
        cls.log = wopic.log = log
        wopic.sslverify = cls.sslverify

    @classmethod
    def loadplugin(cls, appname, appurl, appinturl, apikey):
        '''Load plugin for the given appname, if supported by the bridge service'''
        p = appname.lower()
        if p in cls.plugins:
            # already initialized
            return
        if not issupported(appname):
            raise ValueError(appname)
        try:
            cls.plugins[p] = __import__('bridge.' + p, globals(), locals(), [p])
            cls.plugins[p].log = cls.log
            cls.plugins[p].sslverify = cls.sslverify
            cls.plugins[p].disablezip = cls.disablezip
            cls.plugins[p].appname = appname
            cls.plugins[p].init(appurl, appinturl, apikey)
            cls.log.info('msg="Imported plugin for application" app="%s" plugin="%s"' % (p, cls.plugins[p]))
        except Exception as e:
            cls.log.info('msg="Failed to initialize plugin" app="%s" URL="%s" exception="%s"' %
                         (p, appinturl, e))
            cls.plugins.pop(p, None)   # regardless which step failed, this will remove the failed plugin
            raise ValueError(appname)

        # start the thread to perform async save operations if not yet started
        if not cls.savethread:
            cls.active = True
            cls.savethread = SaveThread()
            cls.savethread.start()


def issupported(appname):
    '''One-liner to return if a given application is supported by one of the bridge extensions'''
    return appname.lower() in set(BRIDGE_EXT_PLUGINS.values())


def isextsupported(fileext):
    '''One-liner to return if a given file extension is supported by one of the bridge extensions'''
    return fileext.lower() in set(BRIDGE_EXT_PLUGINS.keys())


def _validateappname(appname):
    '''Return the plugin's appname if one of the registered plugins matches (case-insensitive) the given appname'''
    for p in WB.plugins.values():
        if appname.lower() in p.appname.lower():
            return p.appname
    raise ValueError


def _gendocid(wopisrc):
    '''Generate a URL safe hash of the wopisrc to be used as document id by the app'''
    dig = hmac.new(WB.hashsecret.encode(), msg=wopisrc.split('/')[-1].encode(), digestmod=hashlib.sha1).digest()
    return urlsafe_b64encode(dig).decode()[:-1]


# The Bridge endpoints start here
#############################################################################################################

def appopen(wopisrc, acctok, appname, viewmode):
    '''Open a doc by contacting the provided WOPISrc with the given access_token.
    Returns a (app-url, params{}) pair if successful, raises a FailedOpen exception otherwise'''
    wopisrc = urlparse.unquote_plus(wopisrc)
    if not isinstance(acctok, str):
        # TODO when using the wopiopen.py tool, the access token has to be decoded, to be clarified
        acctok = acctok.decode()
    # WOPI GetFileInfo
    res = wopic.request(wopisrc, acctok, 'GET')
    if res.status_code != http.client.OK:
        WB.log.warning('msg="BridgeOpen: unable to fetch file WOPI metadata" response="%d"' % res.status_code)
        raise FailedOpen('Invalid WOPI context', http.client.NOT_FOUND)
    filemd = res.json()
    app = WB.plugins.get(appname.lower())
    if not app:
        WB.log.warning('msg="Open: appname not supported or missing plugin" filename="%s" appname="%s" token="%s"' %
                       (filemd['BaseFileName'], appname, acctok[-20:]))
        raise FailedOpen('File type not supported', http.client.BAD_REQUEST)
    WB.log.debug('msg="Processing open in supported app" appname="%s" plugin="%s"' % (appname, app))

    try:
        # use the 'UserCanWrite' attribute to decide whether the file is to be opened in read-only mode
        if filemd['UserCanWrite']:
            try:
                # was it already being worked on?
                wopilock = wopic.getlock(wopisrc, acctok)
                WB.log.info('msg="Lock already held" lock="%s" token="%s"' % (wopilock, acctok[-20:]))
                # add this token to the list, if not already in
                if acctok[-20:] not in wopilock['tocl']:
                    wopilock = wopic.refreshlock(wopisrc, acctok, wopilock)
            except wopic.InvalidLock as e:
                if str(e) != str(int(http.client.NOT_FOUND)):
                    # lock is invalid/corrupted: force read-only mode
                    WB.log.info('msg="Invalid lock, forcing read-only mode" error="%s" token="%s"' % (e, acctok[-20:]))
                    filemd['UserCanWrite'] = False

                # otherwise, this is the first user opening the file; in both cases, fetch it
                wopilock = app.loadfromstorage(filemd, wopisrc, acctok, _gendocid(wopisrc))
                # and WOPI Lock it
                res = wopic.request(wopisrc, acctok, 'POST', headers={'X-WOPI-Lock': json.dumps(wopilock),
                                                                      'X-Wopi-Override': 'LOCK'})
                if res.status_code != http.client.OK:
                    # failed to lock the file: open in read-only mode
                    WB.log.warning('msg="Failed to lock the file" response="%d" token="%s"' %
                                   (res.status_code, acctok[-20:]))
                    filemd['UserCanWrite'] = False

            # keep track of this open document for the save thread and for statistical purposes
            if wopisrc in WB.openfiles:
                # use the new acctok and the new/current wopilock content
                WB.openfiles[wopisrc]['acctok'] = acctok
                WB.openfiles[wopisrc]['toclose'] = wopilock['tocl']
            else:
                WB.openfiles[wopisrc] = {
                    'acctok': acctok,
                    'tosave': False,
                    'lastsave': int(time.time()) - WB.saveinterval,
                    'toclose': {acctok[-20:]: False},
                    'docid': wopilock['doc'],
                    'app': app.appname,
                }
            # also clear any potential stale response for this document
            try:
                del WB.saveresponses[wopisrc]
            except KeyError:
                pass
        else:
            # user has no write privileges, just fetch the document and push it to the app on a random docid
            wopilock = app.loadfromstorage(filemd, wopisrc, acctok, None)

        redirurl = app.getredirecturl(viewmode, wopisrc, acctok, wopilock['doc'][1:], filemd['BaseFileName'],
                                      urlparse.quote_plus(filemd['UserFriendlyName']))
    except app.AppFailure as e:
        # this can be raised by loadfromstorage or getredirecturl
        usermsg = str(e) if str(e) else 'Unable to load the app, please try again later or contact support'
        raise FailedOpen(usermsg, http.client.INTERNAL_SERVER_ERROR)

    # TODO in the future we should pass some metadata (including access tokens) as a form parameter
    return redirurl, {}


def appsave(docid):
    '''Save a doc given its WOPI context, and return a JSON-formatted message. The actual save is asynchronous.'''
    try:
        # fetch required metadata from request, return BAD_REQUEST if missing
        wopisrc = urlparse.unquote(flask.request.args['WOPISrc'])
        acctok = flask.request.args['access_token']
        isclose = flask.request.args.get('close') == 'true'

        # ensure a save request comes from known/registered applications:
        # this is done via a specific header
        appname = _validateappname(flask.request.headers[BRIDGED_APP_HEADER])
        WB.log.info('msg="BridgeSave: requested action" isclose="%s" docid="%s" app="%s" wopisrc="%s" token="%s"' %
                    (isclose, docid, appname, wopisrc, acctok[-20:]))
    except KeyError as e:
        WB.log.error('msg="BridgeSave: missing metadata" address="%s" headers="%s" args="%s" error="%s"' %
                     (flask.request.remote_addr, flask.request.headers, flask.request.args, e))
        return wopic.jsonify('Missing metadata, could not save. %s' % RECOVER_MSG), http.client.BAD_REQUEST
    except ValueError as e:
        WB.log.error('msg="BridgeSave: unknown application" address="%s" appheader="%s" args="%s"' %
                     (flask.request.remote_addr, flask.request.headers.get(BRIDGED_APP_HEADER), flask.request.args))
        # temporary override
        appname = 'CodiMD'
        #return wopic.jsonify('Unknown application, could not save. %s' % RECOVER_MSG), http.client.UNAUTHORIZED

    # decide whether to notify the save thread
    donotify = isclose or wopisrc not in WB.openfiles or WB.openfiles[wopisrc]['lastsave'] < time.time() - WB.saveinterval
    # enqueue the request, it will be processed asynchronously
    with WB.savecv:
        if wopisrc in WB.openfiles:
            WB.openfiles[wopisrc]['tosave'] = True
            WB.openfiles[wopisrc]['toclose'][acctok[-20:]] = isclose
        else:
            WB.log.info('msg="Save: repopulating missing metadata" wopisrc="%s" token="%s"' % (wopisrc, acctok[-20:]))
            WB.openfiles[wopisrc] = {
                'acctok': acctok, 'tosave': True,
                'lastsave': int(time.time() - WB.saveinterval),
                'toclose': {acctok[-20:]: isclose},
                'docid': docid,
                'app': appname,
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
            WB.log.info('msg="BridgeSave: returned response" response="%s" token="%s"' % (resp, acctok[-20:]))
            del WB.saveresponses[wopisrc]
            return resp
        WB.log.info('msg="BridgeSave: enqueued action" immediate="%s" token="%s"' % (donotify, acctok[-20:]))
        return '{}', http.client.ACCEPTED


def applist():
    '''Return a list of all currently opened files, for operators only'''
    if (flask.request.headers.get('Authorization') != 'Bearer ' + WB.hashsecret) and \
       (flask.request.args.get('apikey') != WB.hashsecret):     # added for convenience
        WB.log.warning('msg="BridgeList: unauthorized access attempt, missing authorization token" '
                       'client="%s"' % flask.request.remote_addr)
        return 'Client not authorized', http.client.UNAUTHORIZED
    WB.log.info('msg="BridgeList: returning list of open files" client="%s"' % flask.request.remote_addr)
    return flask.Response(json.dumps(WB.openfiles), mimetype='application/json')


#############################################################################################################

def _intersection(boolsdict):
    '''Given a dictionary of booleans, returns the intersection (AND) of all'''
    return functools.reduce(lambda x, y: x and y, list(boolsdict.values()))


def _union(boolsdict):
    '''Given a dictionary of booleans, returns the union (OR) of all'''
    return functools.reduce(lambda x, y: x or y, list(boolsdict.values()))


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
                        WB.log.critical('msg="SaveThread: unexpected exception caught" ex="%s" type="%s" traceback="%s"' %
                                        (e, ex_type, traceback.format_exception(ex_type, ex_value, ex_traceback)))

    def savedirty(self, openfile, wopisrc):
        '''save documents that are dirty for more than `saveinterval` or that are being closed'''
        wopilock = None
        if openfile['tosave'] and (_intersection(openfile['toclose'])
                                   or (openfile['lastsave'] < time.time() - WB.saveinterval)):
            appname = openfile['app'].lower()
            try:
                wopilock = wopic.getlock(wopisrc, openfile['acctok'])
            except wopic.InvalidLock:
                WB.log.info('msg="SaveThread: attempting to relock file" token="%s" docid="%s"' %
                            (openfile['acctok'][-20:], openfile['docid']))
                try:
                    wopilock = WB.saveresponses[wopisrc] = wopic.relock(
                        wopisrc, openfile['acctok'], openfile['docid'], _intersection(openfile['toclose']))
                except wopic.InvalidLock as ile:
                    # even this attempt failed, give up
                    WB.saveresponses[wopisrc] = wopic.jsonify(str(ile)), http.client.INTERNAL_SERVER_ERROR
                    # attempt to save to local storage to help for later recovery: this is a feature of the core wopiserver
                    content, rc = WB.plugins[appname].savetostorage(wopisrc, openfile['acctok'],
                                                                    False, {'doc': openfile['docid']}, onlyfetch=True)
                    if rc == http.client.OK:
                        utils.storeForRecovery(content, 'unknown', wopisrc[wopisrc.rfind('/') + 1:],
                                               openfile['acctok'][-20:], ile)
                    else:
                        WB.log.error('msg="SaveThread: failed to fetch file for recovery to local storage" '
                                     + 'token="%s" docid="%s" app="%s" response="%s"' %
                                     (openfile['acctok'][-20:], openfile['docid'], appname, rc))
                    # set some 'fake' metadata, will be automatically cleaned up later
                    openfile['lastsave'] = int(time.time())
                    openfile['tosave'] = False
                    openfile['toclose'] = {'invalid-lock': True}
                    return None

            # now save and log
            WB.saveresponses[wopisrc] = WB.plugins[appname].savetostorage(wopisrc, openfile['acctok'],
                                                                          _intersection(openfile['toclose']), wopilock)
            openfile['lastsave'] = int(time.time())
            if WB.saveresponses[wopisrc][1] >= http.client.BAD_REQUEST:
                # this is hopefully transient, yet we need to try until we get the file back to storage:
                # the updated lastsave time ensures next retry will happen after the saveinterval time
                if 'still-dirty' not in openfile['toclose']:
                    # add a special key that will prevent close/unlock and refresh lock. If the refresh fails,
                    # the whole process will be retried at next round
                    openfile['toclose']['still-dirty'] = False
                    wopilock = wopic.refreshlock(wopisrc, openfile['acctok'], wopilock, toclose=openfile['toclose'])
                WB.log.warning('msg="SaveThread: failed to save, will retry" token="%s" docid="%s" lasterror="%s" tocl="%s"' %
                               (openfile['acctok'][-20:], openfile['docid'], WB.saveresponses[wopisrc], wopilock['tocl']))
            else:
                openfile['tosave'] = False
                if 'still-dirty' in openfile['toclose']:     # remove the special key above if present
                    openfile['toclose'].pop('still-dirty')
                    wopilock = wopic.refreshlock(wopisrc, openfile['acctok'], wopilock, toclose=openfile['toclose'])
                WB.log.info('msg="SaveThread: file saved successfully" token="%s" docid="%s" tocl="%s"' %
                            (openfile['acctok'][-20:], openfile['docid'], wopilock['tocl']))
        return wopilock

    def closewhenidle(self, openfile, wopisrc, wopilock):
        '''close and unlock documents tha are idle for more than 4x the save interval (about 14 minutes by default).
        They will transparently be relocked when/if the session resumes, but we seem to miss some close notifications,
        therefore this also works as a cleanup step'''
        if openfile['lastsave'] < int(time.time()) - 4 * WB.saveinterval:
            try:
                wopilock = wopic.getlock(wopisrc, openfile['acctok']) if not wopilock else wopilock
                # this will force a close in the cleanup step
                openfile['toclose'] = {t: True for t in openfile['toclose']}
                WB.log.info('msg="SaveThread: force-closing document" lastsavetime="%s" toclosetokens="%s"' %
                            (openfile['lastsave'], openfile['toclose']))
            except wopic.InvalidLock:
                # lock is gone, just cleanup our metadata
                WB.log.warning('msg="SaveThread: cleaning up metadata, detected missed close event" url="%s"' % wopisrc)
                del WB.openfiles[wopisrc]
        return wopilock

    def cleanup(self, openfile, wopisrc, wopilock):
        '''remove state for closed documents after some time'''
        if _union(openfile['toclose']) and not openfile['tosave']:
            # check lock
            try:
                wopilock = wopic.getlock(wopisrc, openfile['acctok']) if not wopilock else wopilock
            except wopic.InvalidLock:
                # nothing to do here, this document may have been closed by another wopibridge
                if openfile['lastsave'] < time.time() - WB.unlockinterval:
                    # yet cleanup only after the unlockinterval time, cf. the InvalidLock handling in savedirty()
                    WB.log.info('msg="SaveThread: cleaning up metadata, file already unlocked" url="%s"' % wopisrc)
                    try:
                        del WB.openfiles[wopisrc]
                    except KeyError:
                        pass
                return

            # reconcile list of toclose tokens
            openfile['toclose'] = {t: wopilock['tocl'][t] or (t in openfile['toclose'] and openfile['toclose'][t])
                                   for t in wopilock['tocl']}
            if _intersection(openfile['toclose']):
                if openfile['lastsave'] < int(time.time()) - WB.unlockinterval:
                    # nobody is still on this document and some time has passed, unlock
                    res = wopic.request(wopisrc, openfile['acctok'], 'POST',
                                        headers={'X-WOPI-Lock': json.dumps(wopilock), 'X-Wopi-Override': 'UNLOCK'})
                    if res.status_code != http.client.OK:
                        WB.log.warning('msg="SaveThread: failed to unlock" lastsavetime="%s" token="%s" response="%s"' %
                                       (openfile['lastsave'], openfile['acctok'][-20:], res.status_code))
                    else:
                        WB.log.info('msg="SaveThread: unlocked document" lastsavetime="%s" token="%s"' %
                                    (openfile['lastsave'], openfile['acctok'][-20:]))
                    del WB.openfiles[wopisrc]
            elif openfile['toclose'] != wopilock['tocl']:
                # some user still on it, refresh lock if the toclose part has changed
                try:
                    wopic.refreshlock(wopisrc, openfile['acctok'], wopilock, toclose=openfile['toclose'])
                except wopic.InvalidLock:
                    WB.log.warning('msg="SaveThread: failed to refresh lock, will retry" url="%s"' % wopisrc)


@atexit.register
def stopsavethread():
    '''Exit handler to cleanly stop the storage sync thread'''
    if WB.savethread:
        # TODO when this handler is called, the logger is not accessible any longer
        WB.log.info('msg="Waiting for SaveThread to complete"')
        with WB.savecv:
            WB.active = False
            WB.savecv.notify()
