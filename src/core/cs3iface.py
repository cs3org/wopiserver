'''
cs3iface.py

CS3 API based interface for the IOP WOPI server

Authors:
Giuseppe.LoPresti@cern.ch, CERN/IT-ST
Lovisa.Lugnegaard@cern.ch, CERN/IT-ST
'''

import time
import http
from base64 import urlsafe_b64encode
import requests
import grpc

import cs3.storage.provider.v1beta1.resources_pb2 as cs3spr
import cs3.storage.provider.v1beta1.provider_api_pb2 as cs3sp
import cs3.gateway.v1beta1.gateway_api_pb2_grpc as cs3gw_grpc
import cs3.gateway.v1beta1.gateway_api_pb2 as cs3gw
import cs3.rpc.v1beta1.code_pb2 as cs3code
import cs3.types.v1beta1.types_pb2 as types

import core.commoniface as common

# module-wide state
ctx = {}            # "map" to store some module context: cf. init()
log = None

def init(inconfig, inlog):
    '''Init module-level variables'''
    global log     # pylint: disable=global-statement
    log = inlog
    ctx['chunksize'] = inconfig.getint('io', 'chunksize')
    ctx['ssl_verify'] = inconfig.getboolean('cs3', 'sslverify', fallback=True)
    ctx['authtokenvalidity'] = inconfig.getint('cs3', 'authtokenvalidity')
    ctx['lockexpiration'] = inconfig.getint('general', 'wopilockexpiration')
    if inconfig.has_option('cs3', 'revagateway'):
        revagateway = inconfig.get('cs3', 'revagateway')
    else:
        # legacy entry, to be dropped at next major release
        revagateway = inconfig.get('cs3', 'revahost')
    # prepare the gRPC connection
    ch = grpc.insecure_channel(revagateway)
    ctx['cs3stub'] = cs3gw_grpc.GatewayAPIStub(ch)


def getuseridfromcreds(token, _wopiuser):
    '''Maps a Reva token and wopiuser to the credentials to be used to access the storage.
    For the CS3 API case, this is just the token'''
    return token


def authenticate_for_test(userid, userpwd):
    '''Use basic authentication against Reva for testing purposes'''
    authReq = cs3gw.AuthenticateRequest(type='basic', client_id=userid, client_secret=userpwd)
    authRes = ctx['cs3stub'].Authenticate(authReq)
    log.debug('msg="Authenticated user" res="%s"' % authRes)
    if authRes.status.code != cs3code.CODE_OK:
        raise IOError('Failed to authenticate as user ' + userid + ': ' + authRes.status.message)
    return authRes.token


def stat(endpoint, fileid, userid, versioninv=1):
    '''Stat a file and returns (size, mtime) as well as other extended info using the given userid as access token.
    Note that endpoint here means the storage id. Note that fileid can be either a path (which MUST begin with /),
    or an id (which MUST NOT start with a /). The versioninv flag is natively supported by Reva.'''
    if endpoint == 'default':
        raise IOError('A CS3API-compatible storage endpoint must be identified by a storage UUID')
    tstart = time.time()
    if fileid[0] == '/':
        # assume this is a filepath
        ref = cs3spr.Reference(path=fileid)
    else:
        # assume we have an opaque fileid
        ref = cs3spr.Reference(resource_id=cs3spr.ResourceId(storage_id=endpoint, opaque_id=fileid))
    statInfo = ctx['cs3stub'].Stat(request=cs3sp.StatRequest(ref=ref),
                                   metadata=[('x-access-token', userid)])
    tend = time.time()
    log.info('msg="Invoked stat" inode="%s" elapsedTimems="%.1f"' % (fileid, (tend-tstart)*1000))
    if statInfo.status.code == cs3code.CODE_OK:
        log.debug('msg="Stat result" data="%s"' % statInfo)
        if statInfo.info.type == cs3spr.RESOURCE_TYPE_CONTAINER:
            raise IOError('Is a directory')
        if statInfo.info.type not in (cs3spr.RESOURCE_TYPE_FILE, cs3spr.RESOURCE_TYPE_SYMLINK):
            log.warning('msg="Stat: unexpected type" type="%d"' % statInfo.info.type)
            raise IOError('Unexpected type %d' % statInfo.info.type)
        # we base64-encode the inode so it can be used in a WOPISrc
        inode = urlsafe_b64encode(statInfo.info.id.opaque_id.encode()).decode()
        return {
            'inode': statInfo.info.id.storage_id + '-' + inode,
            'filepath': statInfo.info.path,
            'ownerid': statInfo.info.owner.opaque_id + '@' + statInfo.info.owner.idp,
            'size': statInfo.info.size,
            'mtime': statInfo.info.mtime.seconds
        }
    log.info('msg="Failed stat" inode="%s" reason="%s"' % (fileid, statInfo.status.message.replace('"', "'")))
    raise IOError(common.ENOENT_MSG if statInfo.status.code == cs3code.CODE_NOT_FOUND else statInfo.status.message)


def statx(endpoint, fileid, userid, versioninv=0):
    '''Get extended stat info (inode, filepath, userid, size, mtime). Equivalent to stat.'''
    return stat(endpoint, fileid, userid, versioninv)


def setxattr(_endpoint, filepath, userid, key, value):
    '''Set the extended attribute <key> to <value> using the given userid as access token'''
    reference = cs3spr.Reference(path=filepath)
    arbitrary_metadata = cs3spr.ArbitraryMetadata()
    arbitrary_metadata.metadata.update({key: str(value)})        # pylint: disable=no-member
    req = cs3sp.SetArbitraryMetadataRequest(ref=reference, arbitrary_metadata=arbitrary_metadata)
    res = ctx['cs3stub'].SetArbitraryMetadata(request=req,
                                              metadata=[('x-access-token', userid)])
    if res.status.code != cs3code.CODE_OK:
        log.error('msg="Failed to setxattr" filepath="%s" key="%s" reason="%s"' % (filepath, key, res.status.message.replace('"', "'")))
        raise IOError(res.status.message)
    log.debug('msg="Invoked setxattr" result="%s"' % res)


def getxattr(_endpoint, filepath, userid, key):
    '''Get the extended attribute <key> using the given userid as access token'''
    tstart = time.time()
    reference = cs3spr.Reference(path=filepath)
    statInfo = ctx['cs3stub'].Stat(request=cs3sp.StatRequest(ref=reference),
                                   metadata=[('x-access-token', userid)])
    tend = time.time()
    if statInfo.status.code != cs3code.CODE_OK:
        log.error('msg="Failed to stat" filepath="%s" key="%s" reason="%s"' % (filepath, key, statInfo.status.message.replace('"', "'")))
        raise IOError(statInfo.status.message)
    try:
        xattrvalue = statInfo.info.arbitrary_metadata.metadata[key]
        if xattrvalue == '':
            raise KeyError
        log.debug('msg="Invoked stat for getxattr" filepath="%s" elapsedTimems="%.1f"' % (filepath, (tend-tstart)*1000))
        return xattrvalue
    except KeyError:
        log.warning('msg="Empty value or key not found in getxattr" filepath="%s" key="%s" metadata="%s"' % (filepath, key, statInfo.info.arbitrary_metadata.metadata))
        return None


def rmxattr(_endpoint, filepath, userid, key):
    '''Remove the extended attribute <key> using the given userid as access token'''
    reference = cs3spr.Reference(path=filepath)
    req = cs3sp.UnsetArbitraryMetadataRequest(ref=reference, arbitrary_metadata_keys=[key])
    res = ctx['cs3stub'].UnsetArbitraryMetadata(request=req, metadata=[('x-access-token', userid)])
    if res.status.code != cs3code.CODE_OK:
        log.error('msg="Failed to rmxattr" filepath="%s" key="%s" reason="%s"' % (filepath, key, res.status.message.replace('"', "'")))
        raise IOError(res.status.message)
    log.debug('msg="Invoked rmxattr" result="%s"' % res.status)


def setlock(_endpoint, filepath, userid, appname, value):
    '''Set a lock to filepath with the given value metadata and appname as holder'''
    reference = cs3spr.Reference(path=filepath)
    lock = cs3spr.Lock(type=cs3spr.LOCK_TYPE_WRITE, app_name=appname, lock_id=value, \
                       expiration={'seconds': int(time.time() + ctx['lockexpiration'])})
    req = cs3sp.SetLockRequest(ref=reference, lock=lock)
    res = ctx['cs3stub'].SetLock(request=req, metadata=[('x-access-token', userid)])
    if res.status.code != cs3code.CODE_OK:
        log.error('msg="Failed to setlock" filepath="%s" appname="%s" value="%s" reason="%s"' % (filepath, appname, value, res.status.message.replace('"', "'")))
        raise IOError(res.status.message)
    log.debug('msg="Invoked setlock" filepath="%s" value="%s" result="%s"' % (filepath, value, res.status))


def getlock(_endpoint, filepath, userid):
    '''Get the lock metadata for the given filepath'''
    reference = cs3spr.Reference(path=filepath)
    req = cs3sp.GetLockRequest(ref=reference)
    res = ctx['cs3stub'].GetLock(request=req, metadata=[('x-access-token', userid)])
    if res.status.code != cs3code.CODE_OK:
        log.error('msg="Failed to getlock" filepath="%s" reason="%s"' % (filepath, res.status.message.replace('"', "'")))
        raise IOError(res.status.message)
    log.debug('msg="Invoked getlock" filepath="%s" result="%s"' % (filepath, res.lock))
    return {
        'lock_id': res.lock.lock_id,
        'type': res.lock.type,
        'app_name': res.lock.app_name,
        'user': res.lock.user.opaque_id + '@' + res.lock.user.idp,
        'expiration': {
            'seconds': res.lock.expiration.seconds
        }
    }


def refreshlock(_endpoint, filepath, userid, appname, value):
    '''Refresh the lock metadata for the given filepath'''
    reference = cs3spr.Reference(path=filepath)
    lock = cs3spr.Lock(type=cs3spr.LOCK_TYPE_WRITE, app_name=appname, lock_id=value, \
                       expiration={'seconds': int(time.time() + ctx['lockexpiration'])})
    req = cs3sp.RefreshLockRequest(ref=reference, lock=lock)
    res = ctx['cs3stub'].RefreshLock(request=req, metadata=[('x-access-token', userid)])
    if res.status.code != cs3code.CODE_OK:
        log.error('msg="Failed to refreshlock" filepath="%s" appname="%s" value="%s" reason="%s"' % (filepath, appname, value, res.status.message.replace('"', "'")))
        raise IOError(res.status.message)
    log.debug('msg="Invoked refreshlock" filepath="%s" value="%s" result="%s"' % (filepath, value, res.status))


def unlock(_endpoint, filepath, userid, appname, value):
    '''Remove the lock for the given filepath'''
    reference = cs3spr.Reference(path=filepath)
    lock = cs3spr.Lock(type=cs3spr.LOCK_TYPE_WRITE, app_name=appname, lock_id=value)
    req = cs3sp.UnlockRequest(ref=reference, lock=lock)
    res = ctx['cs3stub'].Unlock(request=req, metadata=[('x-access-token', userid)])
    if res.status.code != cs3code.CODE_OK:
        log.error('msg="Failed to unlock" filepath="%s" reason="%s"' % (filepath, res.status.message.replace('"', "'")))
        raise IOError(res.status.message)
    log.debug('msg="Invoked unlock" filepath="%s" value="%s" result="%s"' % (filepath, value, res.status))


def readfile(_endpoint, filepath, userid):
    '''Read a file using the given userid as access token. Note that the function is a generator, managed by Flask.'''
    tstart = time.time()
    # prepare endpoint
    req = cs3sp.InitiateFileDownloadRequest(ref=cs3spr.Reference(path=filepath))
    initfiledownloadres = ctx['cs3stub'].InitiateFileDownload(request=req, metadata=[('x-access-token', userid)])
    if initfiledownloadres.status.code == cs3code.CODE_NOT_FOUND:
        log.info('msg="File not found on read" filepath="%s"' % filepath)
        yield IOError(common.ENOENT_MSG)
    elif initfiledownloadres.status.code != cs3code.CODE_OK:
        log.error('msg="Failed to initiateFileDownload on read" filepath="%s" reason="%s"' %
                         (filepath, initfiledownloadres.status.message.replace('"', "'")))
        yield IOError(initfiledownloadres.status.message)
    log.debug('msg="readfile: InitiateFileDownloadRes returned" protocols="%s"' % initfiledownloadres.protocols)

    # Download
    try:
        protocol = [p for p in initfiledownloadres.protocols if p.protocol == "simple"][0]
        headers = {
            'x-access-token': userid,
            'X-Reva-Transfer': protocol.token        # needed if the downloads pass through the data gateway in reva
        }
        fileget = requests.get(url=protocol.download_endpoint, headers=headers, verify=ctx['ssl_verify'])
    except requests.exceptions.RequestException as e:
        log.error('msg="Exception when downloading file from Reva" reason="%s"' % e)
        yield IOError(e)
    tend = time.time()
    data = fileget.content
    if fileget.status_code != http.client.OK:
        log.error('msg="Error downloading file from Reva" code="%d" reason="%s"' % (fileget.status_code, fileget.reason.replace('"', "'")))
        yield IOError(fileget.reason)
    else:
        log.info('msg="File open for read" filepath="%s" elapsedTimems="%.1f"' % (filepath, (tend-tstart)*1000))
        for i in range(0, len(data), ctx['chunksize']):
            yield data[i:i+ctx['chunksize']]


def writefile(_endpoint, filepath, userid, content, islock=False):
    '''Write a file using the given userid as access token. The entire content is written
    and any pre-existing file is deleted (or moved to the previous version if supported).
    The islock flag is currently not supported. TODO the backend should at least support
    writing the file with O_CREAT|O_EXCL flags to prevent races.'''
    if islock:
        log.warning('msg="Lock (no-overwrite) flag not yet supported, going for standard upload"')
    tstart = time.time()
    # prepare endpoint
    if isinstance(content, str):
        content = bytes(content, 'UTF-8')
    size = str(len(content))
    metadata = types.Opaque(map={"Upload-Length": types.OpaqueEntry(decoder="plain", value=str.encode(size))})
    req = cs3sp.InitiateFileUploadRequest(ref=cs3spr.Reference(path=filepath), opaque=metadata)
    initfileuploadres = ctx['cs3stub'].InitiateFileUpload(request=req, metadata=[('x-access-token', userid)])
    if initfileuploadres.status.code != cs3code.CODE_OK:
        log.error('msg="Failed to initiateFileUpload on write" filepath="%s" reason="%s"' % \
                         (filepath, initfileuploadres.status.message.replace('"', "'")))
        raise IOError(initfileuploadres.status.message)
    log.debug('msg="writefile: InitiateFileUploadRes returned" protocols="%s"' % initfileuploadres.protocols)

    # Upload
    try:
        # Get the endpoint for simple protocol
        protocol = [p for p in initfileuploadres.protocols if p.protocol == "simple"][0]
        headers = {
            'x-access-token': userid,
            'Upload-Length': size,
            'X-Reva-Transfer': protocol.token        # needed if the uploads pass through the data gateway in reva
        }
        putres = requests.put(url=protocol.upload_endpoint, data=content, headers=headers, verify=ctx['ssl_verify'])
    except requests.exceptions.RequestException as e:
        log.error('msg="Exception when uploading file to Reva" reason="%s"' % e)
        raise IOError(e)
    tend = time.time()
    if putres.status_code != http.client.OK:
        log.error('msg="Error uploading file to Reva" code="%d" reason="%s"' % (putres.status_code, putres.reason))
        raise IOError(putres.reason)
    log.info('msg="File written successfully" filepath="%s" elapsedTimems="%.1f" islock="%s"' % \
                    (filepath, (tend-tstart)*1000, islock))


def renamefile(_endpoint, filepath, newfilepath, userid):
    '''Rename a file from origfilepath to newfilepath using the given userid as access token.'''
    source = cs3spr.Reference(path=filepath)
    destination = cs3spr.Reference(path=newfilepath)
    req = cs3sp.MoveRequest(source=source, destination=destination)
    res = ctx['cs3stub'].Move(request=req, metadata=[('x-access-token', userid)])
    if res.status.code != cs3code.CODE_OK:
        log.error('msg="Failed to rename file" filepath="%s" reason="%s"' % (filepath, res.status.message.replace('"', "'")))
        raise IOError(res.status.message)
    log.debug('msg="Invoked renamefile" result="%s"' % res)


def removefile(_endpoint, filepath, userid, force=False):
    '''Remove a file using the given userid as access token.
       The force argument is ignored for now for CS3 storage.'''
    reference = cs3spr.Reference(path=filepath)
    req = cs3sp.DeleteRequest(ref=reference)
    res = ctx['cs3stub'].Delete(request=req, metadata=[('x-access-token', userid)])
    if res.status.code != cs3code.CODE_OK:
        if str(res) == common.ENOENT_MSG:
            log.info('msg="Invoked removefile on non-existing file" filepath="%s"' % filepath)
        else:
            log.error('msg="Failed to remove file" filepath="%s" reason="%s"' % (filepath, res.status.message.replace('"', "'")))
        raise IOError(res.status.message)
    log.debug('msg="Invoked removefile" result="%s"' % res)
