#!/usr/bin/python3
'''
wopiclient.py

A set of WOPI functions for the WOPI bridge.

Author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

import json
import http.client
import requests


class InvalidLock(Exception):
    '''A custom exception to represent an invalid or missing WOPI lock'''

# initialized by the main class
log = None
skipsslverify = None


def request(wopisrc, acctok, method, contents=None, headers=None):
    '''Execute a WOPI request with the given parameters and headers'''
    wopiurl = '%s%s' % (wopisrc, ('/contents' if contents is not None and
                                  (not headers or 'X-WOPI-Override' not in headers or headers['X-WOPI-Override'] != 'PUT_RELATIVE') else ''))
    log.debug('msg="Calling WOPI" url="%s" headers="%s" acctok="%s"' %
                 (wopiurl, headers, acctok[-20:]))
    if method == 'GET':
        return requests.get('%s?access_token=%s' % (wopiurl, acctok), verify=not skipsslverify)
    if method == 'POST':
        return requests.post('%s?access_token=%s' % (wopiurl, acctok), verify=not skipsslverify,
                             headers=headers, data=contents)
    return None


def refreshlock(wopisrc, acctok, wopilock, isdirty=False, toclose=None):
    '''Refresh an existing WOPI lock. Returns the new lock if successful, None otherwise'''
    newlock = json.loads(json.dumps(wopilock))    # this is a hack for a deep copy, to be redone in Go
    if toclose:
        # we got the full 'toclose' dict, push it and keep only the active tokens
        newlock['toclose'] = {t: False for t in toclose if not toclose[t]}
        if not newlock['toclose']:
            # exception when no active tokens remain, i.e. everybody has closed: keep them until next round
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
    log.error('msg="Calling WOPI RefreshLock failed" url="%s" response="%s"' % (wopisrc, res.status_code))
    return None


def getlock(wopisrc, acctok, raiseifmissing=True):
    '''Return the currently held WOPI lock (None if missing and raiseifmissing is False), and raise InvalidLock otherwise'''
    try:
        res = request(wopisrc, acctok, 'POST', headers={'X-Wopi-Override': 'GET_LOCK'})
        if res.status_code != http.client.OK:
            # lock got lost
            raise ValueError(res.status_code)
        if not raiseifmissing and 'X-WOPI-Lock' not in res.headers:
            return None
        # the lock is expected to be a dict { docid, filename, digest, app, toclose }
        return json.loads(res.headers.pop('X-WOPI-Lock'))
    except (ValueError, KeyError, json.decoder.JSONDecodeError) as e:
        log.warning('msg="Malformed WOPI lock" exception="%s" error="%s"' % (type(e), e))
        raise InvalidLock
