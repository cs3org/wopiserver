'''
etherpad.py

The Etherpad-specific code used by the WOPI bridge.

Author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

from random import choice
from string import ascii_lowercase
import time
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
groupid = None


def init(env, apipath):
    '''Initialize global vars from the environment'''
    global appurl
    global appexturl
    global apikey
    global groupid
    appexturl = env.get('ETHERPAD_EXT_URL')
    if not appexturl:
        raise ValueError("Missing ETHERPAD_EXT_URL env var")
    appurl = env.get('ETHERPAD_URL')
    if not appurl:
        # defaults to the external
        appurl = appexturl
    with open(apipath + 'etherpad_apikey') as f:
        apikey = f.readline().strip('\n')
    # create a general group to attach all pads
    groupid = _apicall('createGroupIfNotExistsFor', {'groupMapper': 1})
    groupid = groupid['data']['groupID']
    log.info('msg="Got Etherpad global groupid" groupid="%s"' % groupid)


def jsonify(msg):
    '''One-liner to consistently json-ify a given message'''
    return '{"message": "%s"}' % msg


def _padid(padname):
    '''One-liner to generate a padID from a padName'''
    return groupid + '$' + padname


def _apicall(method, params, data=None, acctok=None, raiseonnonzerocode=True):
    '''Generic method to call the Etherpad REST API'''
    params['apikey'] = apikey
    res = requests.post(appurl + '/api/1/' + method, params=params, data=data, verify=not skipsslverify)
    if res.status_code != http.client.OK:
        log.error('msg="Failed to call Etherpad" method="%s" token="%s" response="%d: %s"' %
                    (method, acctok[-20:] if acctok else 'N/A', res.status_code, res.content.decode()))
        raise AppFailure
    res = res.json()
    if res['code'] != 0 and raiseonnonzerocode:
        log.error('msg="Error response from Etherpad" method="%s" token="%s" response="%s"' %
                    (method, acctok[-20:] if acctok else 'N/A', res['message']))
        raise AppFailure
    return res


def getredirecturl(isreadwrite, wopisrc, acctok, wopilock, displayname):
    '''Return a valid URL to the app for the given WOPI context'''
    if not isreadwrite:
        # read-only mode: first generate a read-only link
        res = _apicall('getReadOnlyID', {'padID': wopilock['docid'][1:]}, acctok=acctok)
        return appexturl + '/p/' + res['data']['readOnlyID']
    # associate the displayname to an author
    res = _apicall('createAuthorIfNotExistsFor', {'name': displayname, 'authorMapper': displayname}, acctok=acctok)
    authorid = res['data']['authorID']
    # create session
    validity = int(time.time() + 86400)
    res = _apicall('createSession', {'groupID': groupid, 'authorID': authorid, 'validUntil': validity}, acctok=acctok)
    # return an url to the auth_session plugin
    return appexturl + '/auth_session?sessionID=' + res['data']['sessionID'] + '&padName=' + wopilock['docid'][1:] + \
           '&metadata=' + urlparse.quote_plus('%s?t=%s' % (wopisrc, acctok))


# Cloud storage to Etherpad
###########################

def _fetchfrometherpad(wopilock, acctok):
    '''Fetch a given document from from Etherpad, raise AppFailure in case of errors'''
    try:
        # this request does not use the API, so we strip the `/api/1` part
        res = requests.get(appurl + '/p/' + _padid(wopilock['docid'][1:]) + '/export/etherpad',
                           verify=not skipsslverify)
        if res.status_code != http.client.OK:
            log.error('msg="Unable to fetch document from Etherpad" token="%s" response="%d: %s"' %
                      (acctok[-20:], res.status_code, res.content.decode()))
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
            docid = ''.join([choice(ascii_lowercase) for _ in range(20)])
            log.debug('msg="Generated random padID for read-only document" docid="%s" token="%s"' % (docid, acctok[-20:]))
        # create pad with the given docid as name (the padID will be `groupid$docid`)
        res = _apicall('createGroupPad', {'groupID': groupid, 'padName': docid, 'text': 'placeholder'},
                        acctok=acctok, raiseonnonzerocode=False)
        log.debug('msg="Got pad" token="%s" docid="%s" response="%s"' % (acctok[-20:], docid, res))
        # push content
        res = requests.post(appurl + '/p/' + _padid(docid) + '/import',
                            files={'file': (docid + '.etherpad', epfile)},    # a .etherpad file is imported as raw (JSON) content
                            verify=not skipsslverify)
        if res.status_code != http.client.OK:
            log.error('msg="Unable to push document to Etherpad" token="%s" response="%d: %s"' %
                        (acctok[-20:], res.status_code, res.content.decode()))
            raise AppFailure
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
                 (isclose, appurl + '/p' + _padid(wopilock['docid'][1:]), acctok[-20:]))
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
