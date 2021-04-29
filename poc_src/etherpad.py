'''
etherpad.py

The Etherpad-specific code used by the WOPI bridge.

Author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

from random import choice
from string import ascii_lowercase
import json
import hashlib
import http.client
import urllib.parse as urlparse
import requests
import wopiclient as wopi


class AppFailure(Exception):
    '''A custom exception to represent a fatal failure when contacting Etherpad'''

# initialized by the main class or by the init method
appurl = None
appexturl = None
apikey = None
log = None
skipsslverify = None


def init(env, apipath):
    '''Initialize global vars from the environment'''
    global appurl
    global appexturl
    global apikey
    appexturl = env.get('ETHERPAD_EXT_URL')
    appurl = env.get('ETHERPAD_URL')
    if not appurl:
        # defaults to the external
        appurl = appexturl
    if not appurl:
        raise ValueError("Missing ETHERPAD_EXT_URL env var")
    appurl += '/api/1'
    with open(apipath + 'etherpad_apikey') as f:
        apikey = f.readline().strip('\n')


def jsonify(msg):
    '''One-liner to consistently json-ify a given message'''
    return '{"message": "%s"}' % msg


def getredirecturl(isreadwrite, wopisrc, acctok, wopilock, displayname):
    '''Return a valid URL to the app for the given WOPI context'''
    if isreadwrite:
        url = appexturl + '/p' + wopilock['docid'] + '?metadata=' + \
              urlparse.quote_plus('%s?t=%s' % (wopisrc, acctok)) + '&'
    else:
        # read-only mode: first obtain a read-only link
        # TODO /getReadOnly
        url = appexturl # + res....
    # set the displayname
    # TODO /setUser
    # return the URL with the API key
    return url + 'apikey=' + apikey


# Cloud storage to Etherpad
###########################

def _fetchfrometherpad(wopilock, acctok):
    '''Fetch a given document from from Etherpad, raise AppFailure in case of errors'''
    try:
        res = requests.get(appurl + '/p' + wopilock['docid'] + '/export/etherpad',
                           verify=not skipsslverify)
        if res.status_code != http.client.OK:
            log.error('msg="Unable to fetch document from Etherpad" token="%s" response="%d: %s"' %
                      (acctok[-20:], res.status_code, res.content))
            raise AppFailure
        return res.content
    except requests.exceptions.ConnectionError as e:
        log.error('msg="Exception raised attempting to connect to Etherpad" exception="%s"' % e)
        raise AppFailure


def loadfromstorage(filemd, wopisrc, acctok, docid):
    '''Copy document from storage to Etherpad'''
    # WOPI GetFile
    res = wopi.request(wopisrc, acctok, 'GET', contents=True)
    if res.status_code != http.client.OK:
        raise ValueError(res.status_code)
    epfile = res.content
    # compute its SHA1 hash for later checks if the file was modified
    h = hashlib.sha1()
    h.update(epfile)
    try:
        if not filemd['UserCanWrite']:
            # read-only case: push the doc to a newly generated note with a random padid
            docid = ''.join([choice(ascii_lowercase) for _ in range(20)])
            res = requests.post(appurl + '/createPad',
                                data={'text': epfile},
                                params={'apikey': apikey, 'padID': docid},
                                verify=not skipsslverify)
            if res.status_code != http.client.OK:
                log.error('msg="Unable to push read-only document to Etherpad" token="%s" response="%d"' %
                          (acctok[-20:], res.status_code))
                raise AppFailure
            log.info('msg="Pushed read-only document to Etherpad" docid="%s" token="%s"' % (docid, acctok[-20:]))
        else:
            # generate a deterministic note hash and use it in Etherpad
            res = requests.post(appurl + '/createPad',
                                data={'text': epfile},
                                params={'apikey': apikey, 'padID': docid},
                                verify=not skipsslverify)
            if res.status_code != http.client.OK:
                log.error('msg="Unable to push document to Etherpad" token="%s" response="%d: %s"' %
                          (acctok[-20:], res.status_code, res.content))
                raise AppFailure
            if res.json()['code'] == 1:
                # already exists, update text
                res = requests.post(appurl + '/setText',
                                    data={'text': epfile},
                                    params={'apikey': apikey, 'padID': docid},
                                    verify=not skipsslverify)
            log.info('msg="Pushed document to Etherpad" docid="%s" token="%s"' % (docid, acctok[-20:]))
    except requests.exceptions.ConnectionError as e:
        log.error('msg="Exception raised attempting to connect to Etherpad" exception="%s"' % e)
        raise AppFailure
    # generate and return a WOPI lock structure for this document
    return wopi.generatelock(docid, filemd, h.hexdigest(), None, acctok, False)


# Etherpad to cloud storage
###########################

def savetostorage(wopisrc, acctok, isclose, wopilock):
    '''Copy document from Etherpad back to storage'''
    # get document from Etherpad
    try:
        log.info('msg="Fetching file from Etherpad" isclose="%s" appurl="%s" token="%s"' %
                 (isclose, appurl + wopilock['docid'], acctok[-20:]))
        epfile = _fetchfrometherpad(wopilock, acctok)
    except AppFailure:
        return jsonify('Could not save file, failed to fetch document from Etherpad'), http.client.INTERNAL_SERVER_ERROR

    if wopilock['digest'] != 'dirty':
        # so far the file was not touched: before forcing a put let's validate the contents
        h = hashlib.sha1()
        h.update(epfile.encode())
        if h.hexdigest() == wopilock['digest']:
            log.info('msg="File unchanged, skipping save" token="%s"' % acctok[-20:])
            return '{}', http.client.ACCEPTED

    # WOPI PutFile
    res = wopi.request(wopisrc, acctok, 'POST', headers={'X-WOPI-Lock': json.dumps(wopilock)},
                        contents=epfile)
    reply = wopi.handleputfile('PutFile', wopisrc, res)
    if reply:
        return jsonify(reply), http.client.INTERNAL_SERVER_ERROR
    wopi.refreshlock(wopisrc, acctok, wopilock, isdirty=True)
    log.info('msg="Save completed" filename="%s" isclose="%s" token="%s"' %
                (wopilock['filename'], isclose, acctok[-20:]))
    return jsonify('File saved successfully'), http.client.OK
