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
from base64 import urlsafe_b64encode
import hmac
import requests
import wopiclient as wopi


class EtherpadFailure(Exception):
    '''A custom exception to represent a fatal failure when contacting Etherpad'''

# initialized by the main class
log = None
codimdurl = None
codimdexturl = None
skipsslverify = None
hashsecret = None


def jsonify(msg):
    '''One-liner to consistently json-ify a given message'''
    # a delay = 0 means the user has to click on it to dismiss it, good for longer messages
    return '{"message": "%s", "delay": "%.1f"}' % (msg, 0 if len(msg) > 60 else 0.5 + len(msg)/20)


# Cloud storage to Etherpad
###########################


def _fetchfrometherpad(wopilock, acctok):
    '''Fetch a given document from from Etherpad, raise EtherpadFailure in case of errors'''
    try:
        res = requests.get(codimdurl + '/getText',
                           params={'apikey': hashsecret, 'padID': wopilock['docid'][1:]},
                           verify=not skipsslverify)
        if res.status_code != http.client.OK:
            log.error('msg="Unable to fetch document from Etherpad" token="%s" response="%d: %s"' %
                      (acctok[-20:], res.status_code, res.content))
            raise EtherpadFailure
        res = res.json()
        if res['code'] == 0:
            return res['data']['text']
        log.error('msg="Error received by Etherpad" response="%s"' % res['message'])
        raise EtherpadFailure
    except requests.exceptions.ConnectionError as e:
        log.error('msg="Exception raised attempting to connect to Etherpad" exception="%s"' % e)
        raise EtherpadFailure


def checkredirect(wopilock, _acctok_unused):
    '''Check if the target docid is real or is a redirect, and amend the wopilock structure in such case'''
    return wopilock


def loadfromstorage(filemd, wopisrc, acctok):
    '''Copy document from storage to Etherpad'''
    # WOPI GetFile
    res = wopi.request(wopisrc, acctok, 'GET', contents=True)
    if res.status_code != http.client.OK:
        raise ValueError(res.status_code)
    epfile = res.content
    #wasbundle = os.path.splitext(filemd['BaseFileName'])[1] == '.zmd'

    # if it's a bundled file, unzip it and push the attachments in the appropriate folder
    #if wasbundle:
    #    mddoc = _unzipattachments(mdfile)
    #else:
    # compute its SHA1 hash for later checks if the file was modified
    h = hashlib.sha1()
    h.update(epfile)
    try:
        if not filemd['UserCanWrite']:
            # read-only case: push the doc to a newly generated note with a random padid
            notehash = ''.join([choice(ascii_lowercase) for _ in range(20)])
            res = requests.post(codimdurl + '/createPad',
                                data={'text': epfile},
                                params={'apikey': hashsecret.decode(), 'padID': notehash},
                                verify=not skipsslverify)
            if res.status_code != http.client.OK:
                log.error('msg="Unable to push read-only document to Etherpad" token="%s" response="%d"' %
                          (acctok[-20:], res.status_code))
                raise EtherpadFailure
            log.info('msg="Pushed read-only document to Etherpad" docid="%s" token="%s"' % (notehash, acctok[-20:]))
        else:
            # generate a deterministic note hash and use it in Etherpad
            dig = hmac.new(hashsecret, msg=wopisrc.split('/')[-1].encode(), digestmod=hashlib.sha1).digest()
            notehash = urlsafe_b64encode(dig).decode()[:-1]
            res = requests.post(codimdurl + '/createPad',
                                data={'text': epfile},
                                params={'apikey': hashsecret.decode(), 'padID': notehash},
                                verify=not skipsslverify)
            if res.status_code != http.client.OK:
                log.error('msg="Unable to push document to Etherpad" token="%s" response="%d: %s"' %
                          (acctok[-20:], res.status_code, res.content))
                raise EtherpadFailure
            if res.json()['code'] == 1:
                # already exists, update text
                res = requests.post(codimdurl + '/setText',
                                    data={'text': epfile},
                                    params={'apikey': hashsecret.decode(), 'padID': notehash},
                                    verify=not skipsslverify)
            log.info('msg="Pushed document to Etherpad" docid="%s" token="%s"' % (notehash, acctok[-20:]))
    except requests.exceptions.ConnectionError as e:
        log.error('msg="Exception raised attempting to connect to Etherpad" exception="%s"' % e)
        raise EtherpadFailure
    # we got the hash of the document just created as a redirected URL, generate a WOPI lock structure
    wopilock = wopi.generatelock(notehash, filemd, h.hexdigest(),
                                 'etherpad',
                                 acctok, False)
    return wopilock


# Etherpad to cloud storage
###########################

def _dealwithputfile(wopicall, wopisrc, res):
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


def _saveas(wopisrc, acctok, wopilock, targetname, content):
    '''Save a given document with an alternate name by using WOPI PutRelative'''
    putrelheaders = {'X-WOPI-Lock': json.dumps(wopilock),
                     'X-WOPI-Override': 'PUT_RELATIVE',
                     # SuggestedTarget to not overwrite a possibly existing file
                     'X-WOPI-SuggestedTarget': targetname
                    }
    res = wopi.request(wopisrc, acctok, 'POST', headers=putrelheaders, contents=content)
    reply = _dealwithputfile('PutRelative', wopisrc, res)
    if reply:
        return reply

    # use the new file's metadata from PutRelative to remove the previous file: we can do that only on close
    # because we need to keep using the current wopisrc/acctok until the session is alive in Etherpad
    newname = res.json()['Name']
    # unlock and delete original file
    res = wopi.request(wopisrc, acctok, 'POST', headers={'X-WOPI-Lock': json.dumps(wopilock), 'X-Wopi-Override': 'UNLOCK'})
    if res.status_code != http.client.OK:
        log.warning('msg="Failed to unlock the previous file" token="%s" response="%d"' %
                    (acctok[-20:], res.status_code))
    else:
        res = wopi.request(wopisrc, acctok, 'POST', headers={'X-Wopi-Override': 'DELETE'})
        if res.status_code != http.client.OK:
            log.warning('msg="Failed to delete the previous file" token="%s" response="%d"' %
                        (acctok[-20:], res.status_code))
        else:
            log.info('msg="Previous file unlocked and removed successfully" token="%s"' % acctok[-20:])

    log.info('msg="Final save completed" filename"%s" token="%s"' % (newname, acctok[-20:]))
    return jsonify('File saved successfully'), http.client.OK


def savetostorage(wopisrc, acctok, isclose, wopilock):
    '''Copy document from Etherpad back to storage'''
    # get document from Etherpad
    try:
        log.info('msg="Fetching file from Etherpad" isclose="%s" codimdurl="%s" token="%s"' %
                 (isclose, codimdurl + wopilock['docid'], acctok[-20:]))
        mddoc = _fetchfrometherpad(wopilock, acctok)
    except EtherpadFailure:
        return jsonify('Could not save file, failed to fetch document from Etherpad'), http.client.INTERNAL_SERVER_ERROR

    if wopilock['digest'] != 'dirty':
        # so far the file was not touched: before forcing a put let's validate the contents
        h = hashlib.sha1()
        h.update(mddoc)
        if h.hexdigest() == wopilock['digest']:
            log.info('msg="File unchanged, skipping save" token="%s"' % acctok[-20:])
            return '{}', http.client.ACCEPTED

    # check if we have attachments
    # wasbundle = os.path.splitext(wopilock['filename'])[1] == '.zmd'
    # bundlefile, attresponse = _getattachments(mddoc.decode(), wopilock['filename'].replace('.zmd', '.md'),
    #                                          (wasbundle and not isclose))

    # WOPI PutFile for the file or the bundle if it already existed
    if True: # (wasbundle ^ (not bundlefile)) or not isclose:
        res = wopi.request(wopisrc, acctok, 'POST', headers={'X-WOPI-Lock': json.dumps(wopilock)},
                           contents=mddoc)
        reply = _dealwithputfile('PutFile', wopisrc, res)
        if reply:
            return reply
        wopi.refreshlock(wopisrc, acctok, wopilock, isdirty=True)
        log.info('msg="Save completed" filename="%s" isclose="%s" token="%s"' %
                 (wopilock['filename'], isclose, acctok[-20:]))
        # combine the responses
        return jsonify('File saved successfully'), http.client.OK

    # on close, use saveas for either the new bundle, if this is the first time we have attachments,
    # or the single md file, if there are no more attachments.
    return _saveas(wopisrc, acctok, wopilock, wopilock['filename'], mddoc)
