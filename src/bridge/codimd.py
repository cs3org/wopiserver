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
import urllib.parse as urlparse
import http.client
import requests
import bridge.wopiclient as wopic


TOOLARGE = 'File is too large to be edited in CodiMD. Please reduce its size with a regular text editor and try again.'
class AppFailure(Exception):
    '''A custom exception to represent a fatal failure when contacting CodiMD'''

# a regexp for uploads, that have links like '/uploads/upload_542a360ddefe1e21ad1b8c85207d9365.*'
upload_re = re.compile(r'\/uploads\/upload_\w{32}\.\w+')

# initialized by the main class or by the init method
appurl = None
appexturl = None
apikey = None
log = None
sslverify = None
disablezip = None


def init(_appurl, _appinturl, _apikey):
    '''Initialize global vars from the environment'''
    global appurl
    global appexturl
    global apikey
    appexturl = _appurl
    appurl = _appinturl
    apikey = _apikey
    try:
        # CodiMD integrates Prometheus metrics, let's probe if they exist
        res = requests.head(appurl + '/metrics/codimd', verify=sslverify)
        if res.status_code != http.client.OK:
            log.error('msg="The provided URL does not seem to be a CodiMD instance" appurl="%s"' % appurl)
            raise AppFailure
        log.info('msg="Successfully connected to CodiMD" appurl="%s"' % appurl)
    except requests.exceptions.ConnectionError as e:
        log.error('msg="Exception raised attempting to connect to CodiMD" exception="%s"' % e)
        raise AppFailure


def getredirecturl(isreadwrite, wopisrc, acctok, wopilock, displayname):
    '''Return a valid URL to the app for the given WOPI context'''
    if isreadwrite:
        return appexturl + wopilock['docid'] + '?metadata=' + \
               urlparse.quote_plus('%s?t=%s' % (wopisrc, acctok)) + \
               '&apiKey=' + apikey + '&displayName=' + displayname
    # read-only mode: in this case redirect to publish mode or normal view
    # to quickly jump in slide mode depending on the content
    url = wopilock['docid'] + ('/publish' if wopilock['app'] != 'mds' else '')
    res = requests.head(appurl + url,
                        params={'apiKey': apikey},
                        verify=sslverify)
    if res.status_code == http.client.FOUND:
        return appexturl + '/s/' + urlparse.urlsplit(res.next.url).path.split('/')[-1]
    return appexturl + url + '?apiKey=' + apikey



# Cloud storage to CodiMD
##########################

def _unzipattachments(inputbuf):
    '''Unzip the given input buffer uploading the content to CodiMD and return the contained .md file'''
    inputzip = zipfile.ZipFile(io.BytesIO(inputbuf), compression=zipfile.ZIP_STORED)
    mddoc = None
    for zipinfo in inputzip.infolist():
        fname = zipinfo.filename
        log.debug('msg="Extracting attachment" name="%s"' % fname)
        if os.path.splitext(fname)[1] == '.md':
            mddoc = inputzip.read(zipinfo)
        else:
            # first check if the file already exists in CodiMD:
            res = requests.head(appurl + '/uploads/' + fname, verify=sslverify)
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
            res = requests.post(appurl + '/uploadimage', params={'generateFilename': 'false'},
                                files={'image': (fname, inputzip.read(zipinfo))}, verify=sslverify)
            if res.status_code != http.client.OK:
                log.error('msg="Failed to push included file" filename="%s" httpcode="%d"' % (fname, res.status_code))
    return mddoc


def _isslides(doc):
    '''Heuristically look for signatures of slides in the header of a md document'''
    return doc[:9].decode() == '---\ntitle' or doc[:8].decode() == '---\ntype' or doc[:16].decode() == '---\nslideOptions'


def _fetchfromcodimd(wopilock, acctok):
    '''Fetch a given document from from CodiMD, raise AppFailure in case of errors'''
    try:
        res = requests.get(appurl + wopilock['docid'] + '/download', verify=sslverify)
        if res.status_code != http.client.OK:
            log.error('msg="Unable to fetch document from CodiMD" token="%s" response="%d: %s"' %
                      (acctok[-20:], res.status_code, res.content.decode()))
            raise AppFailure
        return res.content
    except requests.exceptions.ConnectionError as e:
        log.error('msg="Exception raised attempting to connect to CodiMD" exception="%s"' % e)
        raise AppFailure


def loadfromstorage(filemd, wopisrc, acctok, docid):
    '''Copy document from storage to CodiMD'''
    # WOPI GetFile
    res = wopic.request(wopisrc, acctok, 'GET', contents=True)
    if res.status_code != http.client.OK:
        raise AppFailure('Unable to fetch file from storage, got HTTP %d' % res.status_code)
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
        if not docid:
            # read-only case: push the doc to a newly generated note with a random docid
            res = requests.post(appurl + '/new', data=mddoc,
                                allow_redirects=False,
                                params={'mode': 'locked'},
                                headers={'Content-Type': 'text/markdown'},
                                verify=sslverify)
            if res.status_code == http.client.REQUEST_ENTITY_TOO_LARGE:
                log.error('msg="File is too large to be edited in CodiMD" token="%s"')
                raise AppFailure(TOOLARGE)
            if res.status_code != http.client.FOUND:
                log.error('msg="Unable to push read-only document to CodiMD" token="%s" response="%d"' %
                          (acctok[-20:], res.status_code))
                raise AppFailure
            docid = urlparse.urlsplit(res.next.url).path.split('/')[-1]
            log.info('msg="Pushed read-only document to CodiMD" docid="%s" token="%s"' % (docid, acctok[-20:]))
        else:
            # reserve the given docid in CodiMD via a HEAD request
            res = requests.head(appurl + '/' + docid,
                                params={'apiKey': apikey},
                                verify=sslverify)
            if res.status_code not in (http.client.OK, http.client.FOUND):
                log.error('msg="Unable to reserve note hash in CodiMD" token="%s" response="%d"' %
                          (acctok[-20:], res.status_code))
                raise AppFailure
            # check if the target docid is real or is a redirect
            if res.status_code == http.client.FOUND:
                newdocid = urlparse.urlsplit(res.next.url).path.split('/')[-1]
                log.info('msg="Document got aliased in CodiMD" olddocid="%s" docid="%s" token="%s"' %
                         (docid, newdocid, acctok[-20:]))
                docid = newdocid
            else:
                log.debug('msg="Got note hash from CodiMD" docid="%s"' % docid)
            # push the document to CodiMD with the update API
            res = requests.put(appurl + '/api/notes/' + docid,
                               params={'apiKey': apikey},    # possibly required in the future
                               json={'content': mddoc.decode()},
                               verify=sslverify)
            if res.status_code == http.client.FORBIDDEN:
                # the file got unlocked because of no activity, yet some user is there: let it go
                log.warning('msg="Document was being edited in CodiMD, redirecting user" token"%s"' % acctok[-20:])
            elif res.status_code == http.client.REQUEST_ENTITY_TOO_LARGE:
                log.error('msg="File is too large to be edited in CodiMD" token="%s"')
                raise AppFailure(TOOLARGE)
            elif res.status_code != http.client.OK:
                log.error('msg="Unable to push document to CodiMD" token="%s" response="%d"' %
                          (acctok[-20:], res.status_code))
                raise AppFailure
            log.info('msg="Pushed document to CodiMD" docid="%s" token="%s"' % (docid, acctok[-20:]))
    except requests.exceptions.ConnectionError as e:
        log.error('msg="Exception raised attempting to connect to CodiMD" exception="%s"' % e)
        raise AppFailure
    except UnicodeDecodeError as e:
        log.warning('msg="Invalid UTF-8 content found in file" exception="%s"' % e)
        raise AppFailure('File contains an invalid UTF-8 character, was it corrupted? ' + \
                         'Please fix it in a regular editor before opening it in CodiMD.')
    # generate and return a WOPI lock structure for this document
    return wopic.generatelock(docid, filemd, h.hexdigest(), 'mds' if _isslides(mddoc) else 'md', acctok, False)


# CodiMD to cloud storage
##########################

def _getattachments(mddoc, docfilename, forcezip=False):
    '''Parse a markdown file and generate a zip file containing all included files'''
    zip_buffer = io.BytesIO()
    response = None
    for attachment in upload_re.findall(mddoc):
        log.debug('msg="Fetching attachment" url="%s"' % attachment)
        res = requests.get(appurl + attachment, verify=sslverify)
        if res.status_code != http.client.OK:
            log.error('msg="Failed to fetch included file, skipping" path="%s" response="%d"' % (
                attachment, res.status_code))
            # also notify the user
            response = wopic.jsonify('Failed to include a referenced picture in the saved file'), http.client.NOT_FOUND
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


def savetostorage(wopisrc, acctok, isclose, wopilock):
    '''Copy document from CodiMD back to storage'''
    # get document from CodiMD
    try:
        log.info('msg="Fetching file from CodiMD" isclose="%s" appurl="%s" token="%s"' %
                 (isclose, appurl + wopilock['docid'], acctok[-20:]))
        mddoc = _fetchfromcodimd(wopilock, acctok)
    except AppFailure:
        return wopic.jsonify('Could not save file, failed to fetch document from CodiMD'), http.client.INTERNAL_SERVER_ERROR

    h = None
    if isclose and wopilock['digest'] != 'dirty':
        # so far the file was not touched: before forcing a put let's validate the contents
        h = hashlib.sha1()
        h.update(mddoc)
        if h.hexdigest() == wopilock['digest']:
            log.info('msg="File unchanged, skipping save" token="%s"' % acctok[-20:])
            return '{}', http.client.ACCEPTED

    # check if we have attachments
    wasbundle = os.path.splitext(wopilock['filename'])[1] == '.zmd'
    bundlefile = attresponse = None
    if not disablezip or wasbundle:     # in disablezip mode, preserve existing .zmd files but don't create new ones
        bundlefile, attresponse = _getattachments(mddoc.decode(), wopilock['filename'].replace('.zmd', '.md'),
                                                  (wasbundle and not isclose))

    # WOPI PutFile for the file or the bundle if it already existed
    if (wasbundle ^ (not bundlefile)) or not isclose:
        res = wopic.request(wopisrc, acctok, 'POST', headers={'X-WOPI-Lock': json.dumps(wopilock)},
                            contents=(bundlefile if wasbundle else mddoc))
        reply = wopic.handleputfile('PutFile', wopisrc, res)
        if reply:
            return reply
        if isclose and wopilock['digest'] == 'dirty':
            h = hashlib.sha1()
            h.update(mddoc)
        wopilock = wopic.refreshlock(wopisrc, acctok, wopilock, digest=(h.hexdigest() if h else 'dirty'))
        log.info('msg="Save completed" filename="%s" isclose="%s" token="%s"' %
                 (wopilock['filename'], isclose, acctok[-20:]))
        # combine the responses
        return attresponse if attresponse else (wopic.jsonify('File saved successfully'), http.client.OK)

    # on close, use saveas for either the new bundle, if this is the first time we have attachments,
    # or the single md file, if there are no more attachments.
    return wopic.saveas(wopisrc, acctok, wopilock, os.path.splitext(wopilock['filename'])[0] + ('.zmd' if bundlefile else '.md'),
                        bundlefile if bundlefile else mddoc)
