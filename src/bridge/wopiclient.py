'''
wopiclient.py

A set of WOPI functions for the WOPI bridge service.

Author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

import os
import json
import http.client
import requests
from flask import Response


class InvalidLock(Exception):
    '''A custom exception to represent an invalid or missing WOPI lock'''

# initialized by the main class
log = None
sslverify = None


def jsonify(msg):
    '''One-liner to consistently json-ify a given message and pass a delay.
    If delay = 0 means the user has to click on it to dismiss it, good for longer messages'''
    # this is part of the EFSS webhook specs (to be) implemented by the bridged apps
    return '{"message": "%s", "delay": "%.1f"}' % (msg, 0 if len(msg) > 60 else 0.5 + len(msg)/20)


def request(wopisrc, acctok, method, contents=None, headers=None):
    '''Execute a WOPI request with the given parameters and headers'''
    try:
        wopiurl = '%s%s' % (wopisrc, ('/contents' if contents is not None and
                                      (not headers or headers.get('X-WOPI-Override') != 'PUT_RELATIVE')
                                      else ''))
        log.debug('msg="Calling WOPI" url="%s" headers="%s" acctok="%s" ssl="%s"' %
                  (wopiurl, headers, acctok[-20:], sslverify))
        if method == 'GET':
            return requests.get('%s?access_token=%s' % (wopiurl, acctok), verify=sslverify)
        if method == 'POST':
            return requests.post('%s?access_token=%s' % (wopiurl, acctok), verify=sslverify,
                                 headers=headers, data=contents)
    except (requests.exceptions.ConnectionError, IOError) as e:
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
            'app': app if app else os.path.splitext(filemd['BaseFileName'])[1][1:],
            'toclose': {acctok[-20:]: isclose},
           }


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


def _getheadersforrefreshlock(acctok, wopilock, digest, toclose):
    '''Helper function for refreshlock to generate the old and new lock structures'''
    newlock = json.loads(json.dumps(wopilock))    # this is a hack for a deep copy, to be redone in Go
    if toclose:
        # we got the full 'toclose' dict, push it as is
        newlock['toclose'] = toclose
    elif acctok[-20:] not in wopilock['toclose']:
        # if missing, just append the short token to the 'toclose' dict, similarly to the openfiles map
        newlock['toclose'][acctok[-20:]] = False
    if digest and wopilock['digest'] != digest:
        newlock['digest'] = digest
    return {'X-Wopi-Override': 'REFRESH_LOCK',
            'X-WOPI-OldLock': json.dumps(wopilock),
            'X-WOPI-Lock': json.dumps(newlock)
           }, newlock


def refreshlock(wopisrc, acctok, wopilock, digest=None, toclose=None):
    '''Refresh an existing WOPI lock. Returns the new lock if successful, None otherwise'''
    h, newlock = _getheadersforrefreshlock(acctok, wopilock, digest, toclose)
    res = request(wopisrc, acctok, 'POST', headers=h)
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
        # retry with the newly got lock
        h, newlock = _getheadersforrefreshlock(acctok, wopilock, digest, toclose)
        res = request(wopisrc, acctok, 'POST', headers=h)
        if res.status_code == http.client.OK:
            return newlock
        # else fail
    log.error('msg="Calling WOPI RefreshLock failed" url="%s" response="%d" reason="%s"' %
              (wopisrc, res.status_code, res.headers.get('X-WOPI-LockFailureReason')))
    return None


def relock(wopisrc, acctok, docid, isclose):
    '''Relock again a given document and return a valid WOPI lock, or raise InvalidLock otherwise (cf. SaveThread)'''
    # first get again the file metadata
    res = request(wopisrc, acctok, 'GET')
    if res.status_code != http.client.OK:
        log.warning('msg="Session expired or file renamed when attempting to relock it" response="%d" token="%s"' %
                    (res.status_code, acctok[-20:]))
        raise InvalidLock('Session expired, please refresh this page')
    filemd = res.json()

    # lock the file again: we assume we are alone as the previous lock had been released
    wopilock = generatelock(docid, filemd, 'dirty', None, acctok, isclose)
    lockheaders = {'X-WOPI-Lock': json.dumps(wopilock),
                   'X-WOPI-Override': 'REFRESH_LOCK',
                   'X-WOPI-Validate-Target': 'True'    # this is an extension of the Lock API
                  }
    res = request(wopisrc, acctok, 'POST', headers=lockheaders)
    if res.status_code == http.client.CONFLICT:
        log.warning('msg="Got conflict in relocking the file" response="%d" token="%s" reason="%s"' %
                    (res.status_code, acctok[-20:], res.headers.get('X-WOPI-LockFailureReason')))
        raise InvalidLock('The file was modified externally, please refresh this page to get its current version')
    if res.status_code != http.client.OK:
        log.warning('msg="Failed to relock the file" response="%d" token="%s" reason="%s"' %
                    (res.status_code, acctok[-20:], res.headers.get('X-WOPI-LockFailureReason')))
        raise InvalidLock('Failed to relock the file on save, please refresh this page')
    # relock was successful, return lock: along with noteids univocally associated to files (WOPISrc's),
    # we are sure no other updates could have been missed
    return wopilock


def handleputfile(wopicall, wopisrc, res):
    '''Deal with conflicts or errors following a PutFile/PutRelative request'''
    if res.status_code == http.client.CONFLICT:
        log.warning('msg="Conflict when calling WOPI %s" url="%s" reason="%s"' %
                    (wopicall, wopisrc, res.headers.get('X-WOPI-LockFailureReason')))
        return jsonify('Error saving the file. %s' % res.headers.get('X-WOPI-LockFailureReason')), \
               http.client.INTERNAL_SERVER_ERROR
    if res.status_code != http.client.OK:
        log.error('msg="Calling WOPI %s failed" url="%s" response="%s"' % (wopicall, wopisrc, res.status_code))
        # TODO need to save the file on a local storage for later recovery
        return jsonify('Error saving the file, please contact support'), http.client.INTERNAL_SERVER_ERROR
    return None


def saveas(wopisrc, acctok, wopilock, targetname, content):
    '''Save a given document with an alternate name by using WOPI PutRelative'''
    putrelheaders = {'X-WOPI-Lock': json.dumps(wopilock),
                     'X-WOPI-Override': 'PUT_RELATIVE',
                     # SuggestedTarget to not overwrite a possibly existing file
                     'X-WOPI-SuggestedTarget': targetname
                    }
    res = request(wopisrc, acctok, 'POST', headers=putrelheaders, contents=content)
    reply = handleputfile('PutRelative', wopisrc, res)
    if reply:
        return reply

    # use the new file's metadata from PutRelative to remove the previous file: we can do that only on close
    # because we need to keep using the current wopisrc/acctok until the session is alive in the app
    newname = res.json()['Name']
    # unlock and delete original file
    res = request(wopisrc, acctok, 'POST', headers={'X-WOPI-Lock': json.dumps(wopilock), 'X-Wopi-Override': 'UNLOCK'})
    if res.status_code != http.client.OK:
        log.warning('msg="Failed to unlock the previous file" token="%s" response="%d"' %
                    (acctok[-20:], res.status_code))
    else:
        res = request(wopisrc, acctok, 'POST', headers={'X-Wopi-Override': 'DELETE'})
        if res.status_code != http.client.OK:
            log.warning('msg="Failed to delete the previous file" token="%s" response="%d"' %
                        (acctok[-20:], res.status_code))
        else:
            log.info('msg="Previous file unlocked and removed successfully" token="%s"' % acctok[-20:])

    log.info('msg="Final save completed" filename"%s" token="%s"' % (newname, acctok[-20:]))
    return jsonify('File saved successfully'), http.client.OK
