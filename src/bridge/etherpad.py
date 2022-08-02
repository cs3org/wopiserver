'''
etherpad.py

The Etherpad-specific code used by the WOPI bridge.

Main author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

from random import choice
from string import ascii_lowercase
import json
import http.client
import urllib.parse as urlparse
import requests
import bridge.wopiclient as wopic


# initialized by the main class or by the init method
appurl = None
appexturl = None
apikey = None
log = None
sslverify = None
groupid = None


class AppFailure(Exception):
    '''A custom exception to represent a fatal failure when contacting Etherpad'''


def init(_appurl, _appinturl, _apikey):
    '''Initialize global vars from the environment'''
    global appurl
    global appexturl
    global apikey
    global groupid
    appexturl = _appurl
    appurl = _appinturl
    apikey = _apikey
    # create a general group to attach all pads; can raise AppFailure
    groupid = _apicall('createGroupIfNotExistsFor', {'groupMapper': 1})
    groupid = groupid['data']['groupID']
    log.info('msg="Got Etherpad global groupid" groupid="%s"' % groupid)


def _apicall(method, params, data=None, acctok=None, raiseonnonzerocode=True):
    '''Generic method to call the Etherpad REST API'''
    params['apikey'] = apikey
    try:
        res = requests.post(appurl + '/api/1/' + method, params=params, data=data, verify=sslverify)
        if res.status_code != http.client.OK:
            log.error('msg="Failed to call Etherpad" method="%s" token="%s" response="%d: %s"' %
                      (method, acctok[-20:] if acctok else 'N/A', res.status_code, res.content.decode()))
            raise AppFailure
    except requests.exceptions.ConnectionError as e:
        log.error('msg="Exception raised attempting to connect to Etherpad" method="%s" exception="%s"' % (method, e))
        raise AppFailure
    res = res.json()
    if res['code'] != 0 and raiseonnonzerocode:
        log.error('msg="Error response from Etherpad" method="%s" token="%s" response="%s"' %
                  (method, acctok[-20:] if acctok else 'N/A', res['message']))
        raise AppFailure
    log.debug('msg="Called Etherpad API" method="%s" token="%s" result="%s"' %
              (method, acctok[-20:] if acctok else 'N/A', res))
    return res


def getredirecturl(isreadwrite, wopisrc, acctok, docid, displayname):
    '''Return a valid URL to the app for the given WOPI context'''
    # first create an author ID if not existing (assume the displayname to be unique)
    author = _apicall('createAuthorIfNotExistsFor', {'authorMapper': displayname, 'name': displayname}, acctok=acctok)
    # then pass to Etherpad the required metadata for the save webhook
    try:
        res = requests.post(appurl + '/setEFSSMetadata',
                            params={'authorID': author['data']['authorID'], 'padID': docid[1:],
                                    'metadata': urlparse.quote_plus('%s?t=%s' % (wopisrc, acctok))},
                            verify=sslverify)
        if res.status_code != http.client.OK:
            log.error('msg="Failed to call Etherpad" method="setEFSSMetadata" token="%s" response="%d: %s"' %
                      (acctok[-20:], res.status_code, res.content.decode()))
            raise AppFailure
    except requests.exceptions.ConnectionError as e:
        log.error('msg="Exception raised attempting to connect to Etherpad" method="setEFSSMetadata" exception="%s"' % e)
        raise AppFailure

    if not isreadwrite:
        # for read-only mode generate a read-only link
        res = _apicall('getReadOnlyID', {'padID': docid[1:]}, acctok=acctok)
        return appexturl + '/p/%s' % res['data']['readOnlyID']
    # return the URL to the pad
    return appexturl + '/p/%s' % docid[1:]


# Cloud storage to Etherpad
###########################

def loadfromstorage(filemd, wopisrc, acctok, docid):
    '''Copy document from storage to Etherpad'''
    # WOPI GetFile
    res = wopic.request(wopisrc, acctok, 'GET', contents=True)
    if res.status_code != http.client.OK:
        raise AppFailure('Unable to fetch file from storage, got HTTP %d' % res.status_code)
    epfile = res.content
    try:
        if not docid:
            docid = ''.join([choice(ascii_lowercase) for _ in range(20)])
            log.debug('msg="Generated random padID for read-only document" docid="%s" token="%s"' % (docid, acctok[-20:]))
        # first drop previous pad if it exists
        _apicall('deletePad', {'padID': docid}, acctok=acctok, raiseonnonzerocode=False)
        # create pad with the given docid as name
        _apicall('createGroupPad', {'groupID': groupid, 'padName': docid, 'text': 'placeholder'},
                 acctok=acctok, raiseonnonzerocode=False)
        if len(epfile) > 0:
            # push content: a .etherpad file is imported as raw (JSON) content
            res = requests.post(appurl + '/p/' + docid + '/import',
                                files={'file': (docid + '.etherpad', epfile, 'application/json')},
                                params={'apikey': apikey},
                                verify=sslverify)
            if res.status_code != http.client.OK:
                log.error('msg="Unable to push document to Etherpad" token="%s" response="%d: %s"' %
                        (acctok[-20:], res.status_code, res.content.decode()))
                raise AppFailure
            log.info('msg="Pushed document to Etherpad" docid="%s" token="%s"' % (docid, acctok[-20:]))
        else:
            log.info('msg="Empty document created in Etherpad" docid="%s" token="%s"' % (docid, acctok[-20:]))
    except requests.exceptions.ConnectionError as e:
        log.error('msg="Exception raised attempting to connect to Etherpad" method="import" exception="%s"' % e)
        raise AppFailure
    # generate and return a WOPI lock structure for this document
    return wopic.generatelock(docid, filemd, epfile, acctok, False)


# Etherpad to cloud storage
###########################

def _fetchfrometherpad(wopilock, acctok):
    '''Fetch a given document from from Etherpad, raise AppFailure in case of errors'''
    try:
        # this operation does not use the API (and it is NOT protected by the API key!), so we use a plain GET
        res = requests.get(appurl + '/p' + wopilock['doc'] + '/export/etherpad',
                           verify=sslverify)
        if res.status_code != http.client.OK:
            log.error('msg="Unable to fetch document from Etherpad" token="%s" response="%d: %s"' %
                      (acctok[-20:], res.status_code, res.content.decode()))
            raise AppFailure
        return res.content
    except requests.exceptions.ConnectionError as e:
        log.error('msg="Exception raised attempting to connect to Etherpad" exception="%s"' % e)
        raise AppFailure


def savetostorage(wopisrc, acctok, isclose, wopilock, onlyfetch=False):
    '''Copy document from Etherpad back to storage'''
    # get document from Etherpad
    try:
        log.info('msg="Fetching file from Etherpad" isclose="%s" appurl="%s" token="%s"' %
                 (isclose, appurl + '/p' + wopilock['doc'], acctok[-20:]))
        epfile = _fetchfrometherpad(wopilock, acctok)
        if onlyfetch:
            # this flag is only used in case of recovery to local storage
            return epfile, http.client.OK
    except AppFailure:
        # return a non-fatal error
        return wopic.jsonify('File not saved, error in fetching document from Etherpad. Will try again later'), \
               http.client.FAILED_DEPENDENCY

    if isclose and wopic.checkfornochanges(epfile, wopilock, acctok):
        return '{}', http.client.ACCEPTED

    # WOPI PutFile
    res = wopic.request(wopisrc, acctok, 'POST', headers={'X-WOPI-Lock': json.dumps(wopilock)},
                        contents=epfile)
    reply = wopic.handleputfile('PutFile', wopisrc, res)
    if reply:
        return reply
    return wopic.refreshdigestandlock(wopisrc, acctok, wopilock, epfile)
