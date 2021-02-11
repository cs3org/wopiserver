'''
wopiclient.py

A set of WOPI functions for the WOPI bridge.

Author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

import json
import http.client
import requests
from flask import Response

class InvalidLock(Exception):
    '''A custom exception to represent an invalid or missing WOPI lock'''

# initialized by the main class
log = None
skipsslverify = None


def request(wopisrc, acctok, method, contents=None, headers=None):
    '''Execute a WOPI request with the given parameters and headers'''
    try:
        wopiurl = '%s%s' % (wopisrc, ('/contents' if contents is not None and
                                      (not headers or headers.get('X-WOPI-Override') != 'PUT_RELATIVE')
                                      else ''))
        log.debug('msg="Calling WOPI" url="%s" headers="%s" acctok="%s"' %
                  (wopiurl, headers, acctok[-20:]))
        if method == 'GET':
            return requests.get('%s?access_token=%s' % (wopiurl, acctok), verify=not skipsslverify)
        if method == 'POST':
            return requests.post('%s?access_token=%s' % (wopiurl, acctok), verify=not skipsslverify,
                                 headers=headers, data=contents)
    except requests.exceptions.ConnectionError as e:
        log.error('msg="Unable to contact WOPI" wopiurl="%s" acctok="%s" response="%s"' % (wopiurl, acctok, e))
        res = Response()
        res.status_code = http.client.INTERNAL_SERVER_ERROR
        return res
    return None


def generatelock(docid, filemd, digest, app, acctok, isclose):
    '''return a dict to be used as WOPI lock, in the format { docid, filename, digest, app, toclose },
       where toclose is like in the openfiles map'''
    return {'docid': '/' + docid.strip('/'),
            'filename': filemd['BaseFileName'],
            'digest': digest,
            'app': app,
            'toclose': {acctok[-20:]: isclose},
           }


def refreshlock(wopisrc, acctok, wopilock, isdirty=False, toclose=None):
    '''Refresh an existing WOPI lock. Returns the new lock if successful, None otherwise'''
    newlock = json.loads(json.dumps(wopilock))    # this is a hack for a deep copy, to be redone in Go
    if toclose:
        # we got the full 'toclose' dict, push it as is
        newlock['toclose'] = toclose
    elif acctok[-20:] not in wopilock['toclose']:
        # if missing, just append the short token to the 'toclose' dict, similarly to the openfiles map
        newlock['toclose'][acctok[-20:]] = False
    if isdirty and wopilock['digest'] != 'dirty':
        newlock['digest'] = 'dirty'
    lockheaders = {'X-Wopi-Override': 'REFRESH_LOCK',
                   'X-WOPI-OldLock': json.dumps(wopilock),
                   'X-WOPI-Lock': json.dumps(newlock)
                  }
    res = request(wopisrc, acctok, 'POST', headers=lockheaders)
    if res.status_code == http.client.OK:
        return newlock
    if res.status_code == http.client.CONFLICT:
        # we have a race condition, another thread has updated the lock before us
        log.warning('msg="Got conflict in refreshing lock, retrying" url="%s"' % wopisrc)
        currlock = getlock(wopisrc, acctok)
        if toclose:
            # merge toclose token lists
            for t in currlock['toclose']:
                toclose[t] = currlock['toclose'][t] or (t in toclose and toclose[t])
        # recursively retry, the recursion is going to stop in one round
        return refreshlock(wopisrc, acctok, currlock, isdirty, toclose)
    log.error('msg="Calling WOPI RefreshLock failed" url="%s" response="%s" reason="%s"' % (
        wopisrc, res.status_code, res.headers.get('X-WOPI-LockFailureReason')))
    return None


def getlock(wopisrc, acctok):
    '''Return the currently held WOPI lock, or raise InvalidLock otherwise'''
    try:
        res = request(wopisrc, acctok, 'POST', headers={'X-Wopi-Override': 'GET_LOCK'})
        if res.status_code != http.client.OK:
            # lock got lost or any other error
            raise InvalidLock(res.status_code)
        # the lock is expected to be a JSON dict, see generatelock()
        return json.loads(res.headers.get('X-WOPI-Lock'))
    except (ValueError, KeyError, json.decoder.JSONDecodeError) as e:
        log.warning('msg="Missing or malformed WOPI lock" exception="%s" error="%s"' % (type(e), e))
        raise InvalidLock(e)


def relock(wopisrc, acctok, docid, isclose):
    '''Relock again a given document and return a valid WOPI lock, or raise InvalidLock otherwise (cf. SaveThread)'''
    # first get again the file metadata
    try:
        res = request(wopisrc, acctok, 'GET')
        if res.status_code in [http.client.NOT_FOUND, http.client.UNAUTHORIZED, http.client.INTERNAL_SERVER_ERROR]:
            log.warning('msg="Expired session attempting to relock file" response="%d"' % res.status_code)
            raise InvalidLock('Session expired, please refresh this page')
        filemd = res.json()
    except json.decoder.JSONDecodeError as e:
        log.warning('msg="Unexpected non-JSON response from WOPI" error="%s" response="%d"' % (e, res.status_code))
        raise InvalidLock('Invalid WOPI context on save')

    # lock the file again: we assume we are alone as the previous lock had been released
    wopilock = generatelock(docid, filemd, 'relock', 'md', acctok, isclose)
    res = request(wopisrc, acctok, 'POST', headers={'X-WOPI-Lock': json.dumps(wopilock), 'X-Wopi-Override': 'LOCK'})
    if res.status_code != http.client.OK:
        log.warning('msg="Failed to relock the file" response="%d" token="%s" reason="%s"' % (
            res.status_code, acctok[-20:], res.headers.get('X-WOPI-LockFailureReason')))
        raise InvalidLock('Failed to relock the file on save')
    # relock was successful, return it
    return wopilock
