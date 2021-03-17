'''
codimd.py

The CodiMD-specific code used by the WOPI bridge.

Author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

import os
import re
import zipfile
import io
from random import randint
import json
import hashlib
import urllib.parse
import http.client
from base64 import urlsafe_b64encode
import hmac
import requests
import wopiclient as wopi


class CodiMDFailure(Exception):
    '''A custom exception to represent a fatal failure when contacting CodiMD'''

# a regexp for uploads, that have links like '/uploads/upload_542a360ddefe1e21ad1b8c85207d9365.*'
upload_re = re.compile(r'\/uploads\/upload_\w{32}\.\w+')

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


def _getattachments(mddoc, docfilename, forcezip=False):
    '''Parse a markdown file and generate a zip file containing all included files'''
    zip_buffer = io.BytesIO()
    response = None
    for attachment in upload_re.findall(mddoc):
        log.debug('msg="Fetching attachment" url="%s"' % attachment)
        res = requests.get(codimdurl + attachment, verify=not skipsslverify)
        if res.status_code != http.client.OK:
            log.error('msg="Failed to fetch included file, skipping" path="%s" response="%d"' % (
                attachment, res.status_code))
            # also notify the user
            response = jsonify('Failed to include a referenced picture in the saved file'), http.client.NOT_FOUND
            continue
        with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_STORED, allowZip64=False) as zip_file:
            zip_file.writestr(attachment.split('/')[-1], res.content)
    if not forcezip and zip_buffer.getbuffer().nbytes == 0:
        # no attachments actually found
        return None, response
    # also include the markdown file itself
    with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_STORED, allowZip64=False) as zip_file:
        zip_file.writestr(docfilename, mddoc)
    return zip_buffer.getvalue(), response


def _unzipattachments(inputbuf):
    '''Unzip the given input buffer uploading the content to CodiMD and return the contained .md file'''
    inputzip = zipfile.ZipFile(io.BytesIO(
        inputbuf), compression=zipfile.ZIP_STORED)
    mddoc = None
    for zipinfo in inputzip.infolist():
        fname = zipinfo.filename
        log.debug('msg="Extracting attachment" name="%s"' % fname)
        if os.path.splitext(fname)[1] == '.md':
            mddoc = inputzip.read(zipinfo)
        else:
            # first check if the file already exists in CodiMD:
            res = requests.head(codimdurl + '/uploads/' + fname, verify=not skipsslverify)
            if res.status_code == http.client.OK and int(res.headers['Content-Length']) == zipinfo.file_size:
                # yes (assume that hashed filename AND size matching is a good enough content match!)
                log.debug('msg="Skipped existing attachment" filename="%s"' % fname)
                continue
            # check for collision
            if res.status_code == http.client.OK:
                log.warning('msg="Attachment collision detected" filename="%s"' % fname)
                # append a random letter to the filename
                name, ext = os.path.splitext(fname)
                fname = name + '_' + chr(randint(65, 65+26)) + ext
                # and replace its reference in the document (this creates a copy of the doc, not very efficient)
                mddoc = mddoc.replace(zipinfo.filename, fname)
            # OK, let's upload
            log.debug('msg="Pushing attachment" filename="%s"' % fname)
            res = requests.post(codimdurl + '/uploadimage', params={'generateFilename': 'false'},
                                files={'image': (fname, inputzip.read(zipinfo))}, verify=not skipsslverify)
            if res.status_code != http.client.OK:
                log.error('msg="Failed to push included file" filename="%s" httpcode="%d"' % (fname, res.status_code))
    return mddoc


def _isslides(doc):
    '''Heuristically look for signatures of slides in the header of a md document'''
    return doc[:9].decode() == '---\ntitle' or doc[:8].decode() == '---\ntype' or doc[:16].decode() == '---\nslideOptions'


def _fetchfromcodimd(wopilock, acctok):
    '''Fetch a given document from from CodiMD, raise CodiMDFailure in case of errors'''
    try:
        res = requests.get(codimdurl + wopilock['docid'] + '/download', verify=not skipsslverify)
        if res.status_code != http.client.OK:
            log.error('msg="Unable to fetch document from CodiMD" token="%s" response="%d: %s"' %
                      (acctok[-20:], res.status_code, res.content))
            raise CodiMDFailure
        return res.content
    except requests.exceptions.ConnectionError as e:
        log.error('msg="Exception raised attempting to connect to CodiMD" exception="%s"' % e)
        raise CodiMDFailure


def _saveas(wopisrc, acctok, wopilock, targetname, content):
    '''Save a given document with an alternate name by using WOPI PutRelative'''
    putrelheaders = {'X-WOPI-Lock': json.dumps(wopilock),
                     'X-WOPI-Override': 'PUT_RELATIVE',
                     # SuggestedTarget to not overwrite a possibly existing file
                     'X-WOPI-SuggestedTarget': targetname
                    }
    res = wopi.request(wopisrc, acctok, 'POST', headers=putrelheaders, contents=content)
    if res.status_code != http.client.OK:
        log.warning('msg="Calling WOPI PutRelative failed" url="%s" response="%s" reason="%s"' %
                    (wopisrc, res.status_code, res.headers.get('X-WOPI-LockFailureReason')))
        # if res.status_code != http.client.CONFLICT: TODO need to save the file on a local storage for later recovery
        return jsonify('Error saving the file. %s' % res.headers.get('X-WOPI-LockFailureReason')), res.status_code

    # use the new file's metadata from PutRelative to remove the previous file: we can do that only on close
    # because we need to keep using the current wopisrc/acctok until the session is alive in CodiMD
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

    # update our metadata: note we already hold the condition variable as we're called within the save thread
    #WB.openfiles[newwopisrc] = {'acctok': newacctok, 'tosave': False,
    #                            'lastsave': int(time.time()),
    #                            'toclose': {newacctok[-20:]: True},
    #                            }
    #del WB.openfiles[wopisrc]

    log.info('msg="Final save completed" filename"%s" token="%s"' % (newname, acctok[-20:]))
    return jsonify('File saved successfully'), http.client.OK


def loadfromstorage(filemd, wopisrc, acctok):
    '''Copy document from storage to CodiMD'''
    # WOPI GetFile
    res = wopi.request(wopisrc, acctok, 'GET', contents=True)
    if res.status_code != http.client.OK:
        raise ValueError(res.status_code)
    mdfile = res.content
    wasbundle = os.path.splitext(filemd['BaseFileName'])[1] == '.zmd'

    # if it's a bundled file, unzip it and push the attachments in the appropriate folder
    if wasbundle:
        mddoc = _unzipattachments(mdfile)
    else:
        mddoc = mdfile
    # compute its SHA1 hash for later checks if the file was modified
    h = hashlib.sha1()
    h.update(mddoc)
    try:
        if not filemd['UserCanWrite']:
            # read-only case: push the doc to a newly generated note with a random docid
            res = requests.post(codimdurl + '/new', data=mddoc,
                                allow_redirects=False,
                                params={'mode': 'locked'},
                                headers={'Content-Type': 'text/markdown'},
                                verify=not skipsslverify)
            if res.status_code != http.client.FOUND:
                log.error('msg="Unable to push read-only document to CodiMD" token="%s" response="%d"' %
                          (acctok[-20:], res.status_code))
                raise CodiMDFailure
            notehash = urllib.parse.urlsplit(res.next.url).path.split('/')[-1]
            log.debug('msg="Got redirect from CodiMD" docid="%s"' % notehash)
        else:
            # generate a deterministic note hash
            dig = hmac.new(hashsecret, msg=wopisrc.split('/')[-1].encode(), digestmod=hashlib.sha1).digest()
            notehash = urlsafe_b64encode(dig).decode()[:-1]
            res = requests.get(codimdurl + '/' + notehash, verify=not skipsslverify)
            if res.status_code != http.client.OK:
                log.error('msg="Unable to GET note hash from CodiMD" token="%s" response="%d"' %
                          (acctok[-20:], res.status_code))
                raise CodiMDFailure
            log.debug('msg="Got note hash from CodiMD" docid="%s"' % notehash)
            # push the document to CodiMD with the update API
            res = requests.put(codimdurl + '/api/notes/' + notehash,
                               json={'content': mddoc.decode()},
                               verify=not skipsslverify)
            if res.status_code != http.client.OK:
                log.error('msg="Unable to push document to CodiMD" token="%s" response="%d"' %
                          (acctok[-20:], res.status_code))
                raise CodiMDFailure
    except requests.exceptions.ConnectionError as e:
        log.error('msg="Exception raised attempting to connect to CodiMD" exception="%s"' % e)
        raise CodiMDFailure
    # we got the hash of the document just created as a redirected URL, generate a WOPI lock structure
    wopilock = wopi.generatelock(notehash, filemd, h.hexdigest(),
                                 'slide' if _isslides(mddoc) else 'md',
                                 acctok, False)
    log.info('msg="Pushed document to CodiMD" docid="%s" token="%s"' % (notehash, acctok[-20:]))
    return wopilock


def savetostorage(wopisrc, acctok, isclose, wopilock):
    '''Copy document from CodiMD back to storage'''
    # get document from CodiMD
    try:
        log.info('msg="Fetching file from CodiMD" isclose="%s" codimdurl="%s" token="%s"' %
                 (isclose, codimdurl + wopilock['docid'], acctok[-20:]))
        mddoc = _fetchfromcodimd(wopilock, acctok)
    except CodiMDFailure:
        return jsonify('Could not save file, failed to fetch document from CodiMD'), http.client.INTERNAL_SERVER_ERROR

    if isclose and wopilock['digest'] != 'dirty':
        # so far the file was not touched and we are about to close: before forcing a put let's validate the contents
        h = hashlib.sha1()
        h.update(mddoc)
        if h.hexdigest() == wopilock['digest']:
            log.info('msg="File unchanged, skipping save" token="%s"' % acctok[-20:])
            return '{}', http.client.ACCEPTED

    # check if we have attachments
    wasbundle = os.path.splitext(wopilock['filename'])[1] == '.zmd'
    bundlefile, attresponse = _getattachments(mddoc.decode(), wopilock['filename'].replace('.zmd', '.md'),
                                              (wasbundle and not isclose))

    # WOPI PutFile for the file or the bundle if it already existed
    if (wasbundle ^ (not bundlefile)) or not isclose:
        res = wopi.request(wopisrc, acctok, 'POST', headers={'X-WOPI-Lock': json.dumps(wopilock)},
                           contents=(bundlefile if wasbundle else mddoc))
        if res.status_code != http.client.OK:
            log.warning('msg="Calling WOPI PutFile failed" url="%s" response="%s"' % (wopisrc, res.status_code))
            # if res.status_code != http.client.CONFLICT: TODO need to save the file on a local storage for later recovery
            return jsonify('Error saving the file. %s' % res.headers.get('X-WOPI-LockFailureReason')), res.status_code
        # and refresh the WOPI lock
        wopi.refreshlock(wopisrc, acctok, wopilock, isdirty=True)
        log.info('msg="Save completed" filename="%s" isclose="%s" token="%s"' %
                 (wopilock['filename'], isclose, acctok[-20:]))
        # combine the responses
        return attresponse if attresponse else (jsonify('File saved successfully'), http.client.OK)

    # on close, use saveas for either the new bundle, if this is the first time we have attachments,
    # or the single md file, if there are no more attachments.
    return _saveas(wopisrc, acctok, wopilock, os.path.splitext(wopilock['filename'])[0] + ('.zmd' if bundlefile else '.md'),
                   bundlefile if bundlefile else mddoc)
