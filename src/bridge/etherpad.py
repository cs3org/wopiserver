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
import core.wopiutils as utils

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
    log.info(f'msg="Got Etherpad global groupid" groupid="{groupid}"')


def _apicall(method, params, data=None, acctok=None, raiseonnonzerocode=True):
    '''Generic method to call the Etherpad REST API'''
    params['apikey'] = apikey
    try:
        res = requests.post(appurl + '/api/1/' + method, params=params, data=data, verify=sslverify, timeout=10)
        if res.status_code != http.client.OK:
            log.error('msg="Failed to call Etherpad" method="%s" token="%s" response="%d: %s"' %
                      (method, acctok[-20:] if acctok else 'N/A', res.status_code, res.content.decode()))
            raise AppFailure('Failed to connect to Etherpad')
    except requests.exceptions.RequestException as e:
        log.error(f'msg="Exception raised attempting to connect to Etherpad" method="{method}" exception="{e}"')
        raise AppFailure('Failed to connect to Etherpad') from e
    res = res.json()
    if res['code'] != 0 and raiseonnonzerocode:
        log.error('msg="Error response from Etherpad" method="%s" token="%s" response="%s"' %
                  (method, acctok[-20:] if acctok else 'N/A', res['message']))
        raise AppFailure('Error response from Etherpad')
    log.debug('msg="Called Etherpad API" method="%s" token="%s" result="%s"' %
              (method, acctok[-20:] if acctok else 'N/A', res))
    return res


def getredirecturl(viewmode, wopisrc, acctok, docid, _filename, displayname, _revatok):
    '''Return a valid URL to the app for the given WOPI context'''
    if viewmode in (utils.ViewMode.READ_ONLY, utils.ViewMode.VIEW_ONLY):
        # for read-only mode generate a read-only link
        res = _apicall('getReadOnlyID', {'padID': docid}, acctok=acctok)
        return appexturl + f"/p/{res['data']['readOnlyID']}?userName={urlparse.quote_plus(displayname)}"

    # pass to Etherpad the required metadata for the save webhook
    try:
        res = requests.post(appurl + '/setEFSSMetadata',
                            params={'padID': docid, 'wopiSrc': urlparse.quote_plus(wopisrc),
                                    'accessToken': acctok, 'apikey': apikey},
                            verify=sslverify,
                            timeout=10)
        if res.status_code != http.client.OK or res.json()['code'] != 0:
            log.error('msg="Failed to call Etherpad" method="setEFSSMetadata" token="%s" response="%d: %s"' %
                      (acctok[-20:], res.status_code, res.content.decode().replace('"', "'")))
            raise AppFailure('Error response from Etherpad')
        log.debug(f'msg="Called Etherpad" method="setEFSSMetadata" token="{acctok[-20:]}"')
    except requests.exceptions.RequestException as e:
        log.error(f'msg="Exception raised attempting to connect to Etherpad" method="setEFSSMetadata" exception="{e}"')
        raise AppFailure('Failed to connect to Etherpad') from e

    # return the URL to the pad for editing (a PREVIEW viewmode is not supported)
    return appexturl + f'/p/{docid}?userName={urlparse.quote_plus(displayname)}'


# Cloud storage to Etherpad
###########################

def loadfromstorage(filemd, wopisrc, acctok, docid):
    '''Copy document from storage to Etherpad'''
    # WOPI GetFile
    res = wopic.request(wopisrc, acctok, 'GET', contents=True)
    if res.status_code != http.client.OK:
        raise AppFailure('Unable to fetch file from storage, got HTTP %d' % res.status_code)
    epfile = res.content
    if not epfile:
        epfile = b'{}'
    try:
        if not docid:
            docid = ''.join([choice(ascii_lowercase) for _ in range(20)])
            log.debug(f'msg="Generated random padID for read-only document" padid="{docid}" token="{acctok[-20:]}"')
        # first drop previous pad if it exists
        _apicall('deletePad', {'padID': docid}, acctok=acctok, raiseonnonzerocode=False)
        # create pad with the given docid as name
        _apicall('createGroupPad', {'groupID': groupid, 'padName': docid, 'text': 'placeholder'},
                 acctok=acctok, raiseonnonzerocode=False)
        # push content: a .etherpad file is imported as raw (JSON) content
        res = requests.post(appurl + '/p/' + docid + '/import',
                            files={'file': (docid + '.etherpad', epfile, 'application/json')},
                            params={'apikey': apikey},
                            verify=sslverify,
                            timeout=10)
        if res.status_code != http.client.OK:
            log.error('msg="Unable to push document to Etherpad" token="%s" padid="%s" response="%d: %s"' %
                      (acctok[-20:], docid, res.status_code, res.content.decode()))
            raise AppFailure('Error response from Etherpad')
        log.info(f'msg="Pushed document to Etherpad" padid="{docid}" token="{acctok[-20:]}"')
    except requests.exceptions.RequestException as e:
        log.error(f'msg="Exception raised attempting to connect to Etherpad" method="import" exception="{e}"')
        raise AppFailure('Failed to connect to Etherpad') from e
    # generate and return a WOPI lock structure for this document
    return wopic.generatelock(docid, filemd, epfile, acctok, False)


# Etherpad to cloud storage
###########################

def _fetchfrometherpad(wopilock, acctok):
    '''Fetch a given document from from Etherpad, raise AppFailure in case of errors'''
    try:
        # this operation does not use the API (and it is NOT protected by the API key!), so we use a plain GET
        res = requests.get(appurl + '/p' + wopilock['doc'] + '/export/etherpad',
                           verify=sslverify,
                           timeout=10)
        if res.status_code != http.client.OK:
            log.error('msg="Unable to fetch document from Etherpad" token="%s" response="%d: %s"' %
                      (acctok[-20:], res.status_code, res.content.decode()[:50]))
            raise AppFailure
        return res.content
    except requests.exceptions.RequestException as e:
        log.error(f'msg="Exception raised attempting to connect to Etherpad" exception="{e}"')
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
