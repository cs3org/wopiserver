'''
cs3iface.py

CS3 API based interface for the IOP WOPI server

Main author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

import os
import time
import http
import requests
import grpc

import cs3.storage.provider.v1beta1.resources_pb2 as cs3spr
import cs3.storage.provider.v1beta1.provider_api_pb2 as cs3sp
import cs3.auth.registry.v1beta1.registry_api_pb2 as cs3auth
import cs3.gateway.v1beta1.gateway_api_pb2 as cs3gw
import cs3.gateway.v1beta1.gateway_api_pb2_grpc as cs3gw_grpc
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
    ctx['revagateway'] = inconfig.get('cs3', 'revagateway')
    ctx['xattrcache'] = {}    # this is a map cs3ref -> arbitrary_metadata as returned by Stat()
    # prepare the gRPC channel and validate that the revagateway gRPC server is ready
    try:
        ch = grpc.insecure_channel(ctx['revagateway'])
        grpc.channel_ready_future(ch).result(timeout=10)
    except grpc.FutureTimeoutError as e:
        log.error('msg="Failed to connect to Reva via GRPC" error="%s"' % e)
        raise IOError(e)
    ctx['cs3gw'] = cs3gw_grpc.GatewayAPIStub(ch)


def healthcheck():
    '''Probes the storage and returns a status message. For cs3 storage, we execute a call to ListAuthProviders'''
    try:
        res = ctx['cs3gw'].ListAuthProviders(request=cs3auth.ListAuthProvidersRequest())
        log.debug('msg="Executed ListAuthProviders as health check" endpoint="%s" result="%s"' %
                  (ctx['revagateway'], res.status))
        return 'OK'
    except grpc.RpcError as e:
        log.error('msg="Health check: failed to call ListAuthProviders" endpoint="%s" error="%s"' %
                  (ctx['revagateway'], e))
        return str(e)


def getuseridfromcreds(token, wopiuser):
    '''Maps a Reva token and wopiuser to the credentials to be used to access the storage.
    For the CS3 API case this is the token, and wopiuser is expected to be `username!userid_as_returned_by_stat`'''
    return token, wopiuser.split('@')[0] + '!' + wopiuser


def _getcs3reference(endpoint, fileref):
    '''Generates a CS3 reference for a given fileref, covering the following cases:
    absolute path, relative hybrid path, fully opaque fileid'''
    # try splitting endpoint
    parts = endpoint.split("$", 2)
    endpoint = parts[0]
    space_id = ""
    if len(parts) == 2:
        space_id = parts[1]

    if fileref.find('/') == 0:
        # assume we have an absolute path (works in Reva master, not in edge)
        ref = cs3spr.Reference(path=fileref)
    elif fileref.find('/') > 0:
        # assume we have a relative path in the form `<parent_opaque_id>/<base_filename>`,
        # also works if we get `<parent_opaque_id>/<path>/<filename>`
        ref = cs3spr.Reference(resource_id=cs3spr.ResourceId(storage_id=endpoint, space_id=space_id,
                                                             opaque_id=fileref[:fileref.find('/')]),
                               path='.' + fileref[fileref.find('/'):])
    else:
        # assume we have an opaque fileid
        ref = cs3spr.Reference(resource_id=cs3spr.ResourceId(storage_id=endpoint, space_id=space_id, opaque_id=fileref), path='.')
    return ref


def authenticate_for_test(userid, userpwd):
    '''Use basic authentication against Reva for testing purposes'''
    authReq = cs3gw.AuthenticateRequest(type='basic', client_id=userid, client_secret=userpwd)
    authRes = ctx['cs3gw'].Authenticate(authReq)
    log.debug(f'msg="Authenticated user" userid="{authRes.user.id}"')
    if authRes.status.code != cs3code.CODE_OK:
        raise IOError('Failed to authenticate as user ' + userid + ': ' + authRes.status.message)
    return authRes.token


def stat(endpoint, fileref, userid, versioninv=1):
    '''Stat a file and returns (size, mtime) as well as other extended info using the given userid as access token.
    Note that endpoint here means the storage id, and fileref can be either a path in the form (parent_id/base_filename)
    or a pure id (cf. _getcs3reference). The versioninv flag is natively supported by Reva.'''
    tstart = time.time()
    ref = _getcs3reference(endpoint, fileref)
    statInfo = ctx['cs3gw'].Stat(request=cs3sp.StatRequest(ref=ref), metadata=[('x-access-token', userid)])
    tend = time.time()

    if statInfo.status.code == cs3code.CODE_NOT_FOUND:
        log.info(f'msg="File not found" endpoint="{endpoint}" fileref="{fileref}" trace="{statInfo.status.trace}"')
        raise IOError(common.ENOENT_MSG)
    if statInfo.status.code != cs3code.CODE_OK:
        log.error('msg="Failed stat" endpoint="%s" fileref="%s" trace="%s" reason="%s"' %
                  (endpoint, fileref, statInfo.status.trace, statInfo.status.message.replace('"', "'")))
        raise IOError(statInfo.status.message)
    if statInfo.info.type == cs3spr.RESOURCE_TYPE_CONTAINER:
        log.info('msg="Invoked stat" endpoint="%s" fileref="%s" trace="%s" result="ISDIR"' %
                 (endpoint, fileref, statInfo.status.trace))
        raise IOError('Is a directory')
    if statInfo.info.type not in (cs3spr.RESOURCE_TYPE_FILE, cs3spr.RESOURCE_TYPE_SYMLINK):
        log.warning('msg="Invoked stat" endpoint="%s" fileref="%s" unexpectedtype="%d"' %
                    (endpoint, fileref, statInfo.info.type))
        raise IOError('Unexpected type %d' % statInfo.info.type)

    inode = common.encodeinode(statInfo.info.id.storage_id, statInfo.info.id.opaque_id)
    if statInfo.info.path[0] == '/':
        # we got an absolute path from Reva, use it
        filepath = statInfo.info.path
    else:
        # we got a relative path (actually, just the basename): build an hybrid path that can be used to reference
        # the file, using the parent_id that per specs MUST be available
        filepath = statInfo.info.parent_id.opaque_id + '/' + os.path.basename(statInfo.info.path)
    log.info('msg="Invoked stat" fileref="%s" trace="%s" inode="%s" filepath="%s" elapsedTimems="%.1f"' %
             (fileref, statInfo.status.trace, inode, filepath, (tend-tstart)*1000))
    # cache the xattrs map prior to returning; note we're never cleaning this cache and let it grow indefinitely
    ctx['xattrcache'][ref] = statInfo.info.arbitrary_metadata
    return {
        'inode': inode,
        'filepath': filepath,
        'ownerid': statInfo.info.owner.opaque_id + '@' + statInfo.info.owner.idp,
        'size': statInfo.info.size,
        'mtime': statInfo.info.mtime.seconds,
        'etag': statInfo.info.etag,
    }


def statx(endpoint, fileref, userid, versioninv=1):
    '''Get extended stat info (inode, filepath, ownerid, size, mtime, etag). Equivalent to stat.'''
    return stat(endpoint, fileref, userid, versioninv)


def setxattr(endpoint, filepath, userid, key, value, lockmd):
    '''Set the extended attribute <key> to <value> using the given userid as access token'''
    ref = _getcs3reference(endpoint, filepath)
    md = cs3spr.ArbitraryMetadata()
    md.metadata.update({key: str(value)})        # pylint: disable=no-member
    if ref in ctx['xattrcache']:
        ctx['xattrcache'][ref].metadata[key] = str(value)
    lockid = None
    if lockmd:
        _, lockid = lockmd
    req = cs3sp.SetArbitraryMetadataRequest(ref=ref, arbitrary_metadata=md, lock_id=lockid)
    res = ctx['cs3gw'].SetArbitraryMetadata(request=req, metadata=[('x-access-token', userid)])
    if res.status.code != cs3code.CODE_OK:
        log.error('msg="Failed to setxattr" filepath="%s" key="%s" trace="%s" code="%s" reason="%s"' %
                  (filepath, key, res.status.trace, res.status.code, res.status.message.replace('"', "'")))
        raise IOError(res.status.message)
    log.debug(f'msg="Invoked setxattr" result="{res}"')


def getxattr(endpoint, filepath, userid, key):
    '''Get the extended attribute <key> using the given userid as access token'''
    ref = _getcs3reference(endpoint, filepath)
    statInfo = None
    if ref not in ctx['xattrcache']:
        # cache miss, go for Stat and refresh cache
        tstart = time.time()
        statInfo = ctx['cs3gw'].Stat(request=cs3sp.StatRequest(ref=ref), metadata=[('x-access-token', userid)])
        tend = time.time()
        if statInfo.status.code == cs3code.CODE_NOT_FOUND:
            log.debug(f'msg="Invoked stat for getxattr on missing file" filepath="{filepath}"')
            return None
        if statInfo.status.code != cs3code.CODE_OK:
            log.error('msg="Failed to stat" filepath="%s" userid="%s" trace="%s" key="%s" reason="%s"' %
                      (filepath, userid[-20:], statInfo.status.trace, key, statInfo.status.message.replace('"', "'")))
            raise IOError(statInfo.status.message)
        log.debug(f'msg="Invoked stat for getxattr" filepath="{filepath}" elapsedTimems="{(tend - tstart) * 1000:.1f}"')
        ctx['xattrcache'][ref] = statInfo.info.arbitrary_metadata
    try:
        xattrvalue = ctx['xattrcache'][ref].metadata[key]
        if xattrvalue == '':
            raise KeyError
        if not statInfo:
            log.debug(f'msg="Returning cached attr on getxattr" filepath="{filepath}" key="{key}"')
        return xattrvalue
    except KeyError:
        log.info('msg="Empty value or key not found in getxattr" filepath="%s" key="%s" trace="%s" metadata="%s"' %
                 (filepath, key, statInfo.status.trace if statInfo else 'N/A', ctx['xattrcache'][ref].metadata))
        return None


def rmxattr(endpoint, filepath, userid, key, lockmd):
    '''Remove the extended attribute <key> using the given userid as access token'''
    ref = _getcs3reference(endpoint, filepath)
    lockid = None
    if lockmd:
        _, lockid = lockmd
    req = cs3sp.UnsetArbitraryMetadataRequest(ref=ref, arbitrary_metadata_keys=[key], lock_id=lockid)
    res = ctx['cs3gw'].UnsetArbitraryMetadata(request=req, metadata=[('x-access-token', userid)])
    if res.status.code != cs3code.CODE_OK:
        log.error('msg="Failed to rmxattr" filepath="%s" trace="%s" key="%s" reason="%s"' %
                  (filepath, key, res.status.trace, res.status.message.replace('"', "'")))
        raise IOError(res.status.message)
    if ref in ctx['xattrcache']:
        del ctx['xattrcache'][ref].metadata[key]
    log.debug(f'msg="Invoked rmxattr" result="{res.status}"')


def setlock(endpoint, filepath, userid, appname, value):
    '''Set a lock to filepath with the given value metadata and appname as holder'''
    reference = _getcs3reference(endpoint, filepath)
    lock = cs3spr.Lock(type=cs3spr.LOCK_TYPE_WRITE, app_name=appname, lock_id=value,
                       expiration={'seconds': int(time.time() + ctx['lockexpiration'])})
    req = cs3sp.SetLockRequest(ref=reference, lock=lock)
    res = ctx['cs3gw'].SetLock(request=req, metadata=[('x-access-token', userid)])
    if res.status.code in [cs3code.CODE_FAILED_PRECONDITION, cs3code.CODE_ABORTED]:
        log.info('msg="Invoked setlock on an already locked entity" filepath="%s" appname="%s" trace="%s" reason="%s"' %
                 (filepath, appname, res.status.trace, res.status.message.replace('"', "'")))
        raise IOError(common.EXCL_ERROR)
    if res.status.code != cs3code.CODE_OK:
        log.error('msg="Failed to setlock" filepath="%s" appname="%s" value="%s" trace="%s" code="%s" reason="%s"' %
                  (filepath, appname, value, res.status.trace, res.status.code, res.status.message.replace('"', "'")))
        raise IOError(res.status.message)
    log.debug(f'msg="Invoked setlock" filepath="{filepath}" value="{value}" result="{res.status}"')


def getlock(endpoint, filepath, userid):
    '''Get the lock metadata for the given filepath'''
    reference = _getcs3reference(endpoint, filepath)
    req = cs3sp.GetLockRequest(ref=reference)
    res = ctx['cs3gw'].GetLock(request=req, metadata=[('x-access-token', userid)])
    if res.status.code == cs3code.CODE_NOT_FOUND:
        log.debug(f'msg="Invoked getlock on unlocked or missing file" filepath="{filepath}"')
        return None
    if res.status.code != cs3code.CODE_OK:
        log.error('msg="Failed to getlock" filepath="%s" trace="%s" code="%s" reason="%s"' %
                  (filepath, res.status.trace, res.status.code, res.status.message.replace('"', "'")))
        raise IOError(res.status.message)
    log.debug(f'msg="Invoked getlock" filepath="{filepath}" result="{res.lock}"')
    # rebuild a dict corresponding to the internal JSON structure used by Reva, cf. commoniface.py
    return {
        'lock_id': res.lock.lock_id,
        'type': res.lock.type,
        'app_name': res.lock.app_name,
        'user': {
            'opaque_id': res.lock.user.opaque_id,
            'idp': res.lock.user.idp,
            'type': res.lock.user.type
        } if res.lock.user.opaque_id else {},
        'expiration': {
            'seconds': res.lock.expiration.seconds
        }
    }


def refreshlock(endpoint, filepath, userid, appname, value, oldvalue=None):
    '''Refresh the lock metadata for the given filepath'''
    reference = _getcs3reference(endpoint, filepath)
    lock = cs3spr.Lock(type=cs3spr.LOCK_TYPE_WRITE, app_name=appname, lock_id=value,
                       expiration={'seconds': int(time.time() + ctx['lockexpiration'])})
    req = cs3sp.RefreshLockRequest(ref=reference, lock=lock, existing_lock_id=oldvalue)
    res = ctx['cs3gw'].RefreshLock(request=req, metadata=[('x-access-token', userid)])
    if res.status.code in [cs3code.CODE_FAILED_PRECONDITION, cs3code.CODE_ABORTED]:
        log.info('msg="Failed precondition on refreshlock" filepath="%s" appname="%s" trace="%s" reason="%s"' %
                 (filepath, appname, res.status.trace, res.status.message.replace('"', "'")))
        raise IOError(common.EXCL_ERROR)
    if res.status.code != cs3code.CODE_OK:
        log.warning('msg="Failed to refreshlock" filepath="%s" appname="%s" value="%s" trace="%s" code="%s" reason="%s"' %
                    (filepath, appname, value, res.status.trace, res.status.code, res.status.message.replace('"', "'")))
        raise IOError(res.status.message)
    log.debug(f'msg="Invoked refreshlock" filepath="{filepath}" value="{value}" result="{res.status}"')


def unlock(endpoint, filepath, userid, appname, value):
    '''Remove the lock for the given filepath'''
    reference = _getcs3reference(endpoint, filepath)
    lock = cs3spr.Lock(type=cs3spr.LOCK_TYPE_WRITE, app_name=appname, lock_id=value)
    req = cs3sp.UnlockRequest(ref=reference, lock=lock)
    res = ctx['cs3gw'].Unlock(request=req, metadata=[('x-access-token', userid)])
    if res.status.code in [cs3code.CODE_FAILED_PRECONDITION, cs3code.CODE_ABORTED]:
        log.info('msg="Failed precondition on unlock" filepath="%s" appname="%s" trace="%s" reason="%s"' %
                 (filepath, appname, res.status.trace, res.status.message.replace('"', "'")))
        raise IOError(common.EXCL_ERROR)
    if res.status.code != cs3code.CODE_OK:
        log.error('msg="Failed to unlock" filepath="%s" trace="%s" code="%s" reason="%s"' %
                  (filepath, res.status.trace, res.status.code, res.status.message.replace('"', "'")))
        raise IOError(res.status.message)
    log.debug(f'msg="Invoked unlock" filepath="{filepath}" value="{value}" result="{res.status}"')


def readfile(endpoint, filepath, userid, lockid):
    '''Read a file using the given userid as access token. Note that the function is a generator, managed by the app server.'''
    tstart = time.time()
    reference = _getcs3reference(endpoint, filepath)

    # prepare endpoint
    req = cs3sp.InitiateFileDownloadRequest(ref=reference, lock_id=lockid)
    res = ctx['cs3gw'].InitiateFileDownload(request=req, metadata=[('x-access-token', userid)])
    if res.status.code == cs3code.CODE_NOT_FOUND:
        log.info(f'msg="File not found on read" filepath="{filepath}"')
        yield IOError(common.ENOENT_MSG)
    elif res.status.code != cs3code.CODE_OK:
        log.error('msg="Failed to initiateFileDownload on read" filepath="%s" trace="%s" code="%s" reason="%s"' %
                  (filepath, res.status.trace, res.status.code, res.status.message.replace('"', "'")))
        yield IOError(res.status.message)
    tend = time.time()
    log.debug('msg="readfile: InitiateFileDownloadRes returned" trace="%s" protocols="%s"' %
              (res.status.trace, res.protocols))

    # Download
    try:
        protocol = [p for p in res.protocols if p.protocol == "simple" or p.protocol == "spaces"][0]
        headers = {
            'x-access-token': userid,
            'x-reva-transfer': protocol.token        # needed if the downloads pass through the data gateway in reva
        }
        fileget = requests.get(url=protocol.download_endpoint, headers=headers, verify=ctx['ssl_verify'])
    except requests.exceptions.RequestException as e:
        log.error(f'msg="Exception when downloading file from Reva" reason="{e}"')
        yield IOError(e)
    data = fileget.content
    if fileget.status_code != http.client.OK:
        log.error('msg="Error downloading file from Reva" code="%d" reason="%s"' %
                  (fileget.status_code, fileget.reason.replace('"', "'")))
        yield IOError(fileget.reason)
    else:
        log.info(f'msg="File open for read" filepath="{filepath}" elapsedTimems="{(tend - tstart) * 1000:.1f}"')
        for i in range(0, len(data), ctx['chunksize']):
            yield data[i:i + ctx['chunksize']]


def writefile(endpoint, filepath, userid, content, lockmd, islock=False):
    '''Write a file using the given userid as access token. The entire content is written
    and any pre-existing file is deleted (or moved to the previous version if supported).
    The islock flag is currently not supported. The backend should at least support
    writing the file with O_CREAT|O_EXCL flags to prevent races.'''
    if islock:
        log.warning('msg="Lock (no-overwrite) flag not supported, going for standard upload"')
    tstart = time.time()

    # prepare endpoint
    if lockmd:
        _, lockid = lockmd    # TODO we are not validating the holder on write, only the lock_id
    else:
        lockid = None
    if isinstance(content, str):
        content = bytes(content, 'UTF-8')
    size = str(len(content))
    reference = _getcs3reference(endpoint, filepath)
    metadata = types.Opaque(map={"Upload-Length": types.OpaqueEntry(decoder="plain", value=str.encode(size))})
    req = cs3sp.InitiateFileUploadRequest(ref=reference, lock_id=lockid, opaque=metadata)
    res = ctx['cs3gw'].InitiateFileUpload(request=req, metadata=[('x-access-token', userid)])
    if res.status.code != cs3code.CODE_OK:
        log.error('msg="Failed to initiateFileUpload on write" filepath="%s" trace="%s" code="%s" reason="%s"' %
                  (filepath, res.status.trace, res.status.code, res.status.message.replace('"', "'")))
        if '_lock_' in res.status.message:    # TODO find the error code returned by Reva once this is implemented
            raise IOError(common.EXCL_ERROR)
        raise IOError(res.status.message)
    tend = time.time()
    log.debug('msg="writefile: InitiateFileUploadRes returned" trace="%s" protocols="%s"' %
              (res.status.trace, res.protocols))

    # Upload
    try:
        protocol = [p for p in res.protocols if p.protocol == "simple" or p.protocol == "spaces"][0]
        headers = {
            'x-access-token': userid,
            'Upload-Length': size,
            'x-reva-transfer': protocol.token        # needed if the uploads pass through the data gateway in reva
        }
        putres = requests.put(url=protocol.upload_endpoint, data=content, headers=headers, verify=ctx['ssl_verify'])
    except requests.exceptions.RequestException as e:
        log.error(f'msg="Exception when uploading file to Reva" reason="{e}"')
        raise IOError(e)
    if putres.status_code == http.client.UNAUTHORIZED:
        log.warning(f'msg="Access denied uploading file to Reva" reason="{putres.reason}"')
        raise IOError(common.ACCESS_ERROR)
    if putres.status_code != http.client.OK:
        log.error('msg="Error uploading file to Reva" code="%d" reason="%s"' % (putres.status_code, putres.reason))
        raise IOError(putres.reason)
    log.info('msg="File written successfully" filepath="%s" elapsedTimems="%.1f" islock="%s"' %
             (filepath, (tend - tstart) * 1000, islock))


def renamefile(endpoint, filepath, newfilepath, userid, lockmd):
    '''Rename a file from origfilepath to newfilepath using the given userid as access token.'''
    reference = _getcs3reference(endpoint, filepath)
    newfileref = _getcs3reference(endpoint, newfilepath)
    lockid = None
    if lockmd:
        _, lockid = lockmd
    req = cs3sp.MoveRequest(source=reference, destination=newfileref, lock_id=lockid)
    res = ctx['cs3gw'].Move(request=req, metadata=[('x-access-token', userid)])
    if res.status.code in [cs3code.CODE_FAILED_PRECONDITION, cs3code.CODE_ABORTED]:
        log.info('msg="Failed precondition on rename" filepath="%s" trace="%s" reason="%s"' %
                 (filepath, res.status.trace, res.status.message.replace('"', "'")))
        raise IOError(common.EXCL_ERROR)
    if res.status.code != cs3code.CODE_OK:
        log.error('msg="Failed to rename file" filepath="%s" trace="%s" code="%s" reason="%s"' %
                  (filepath, res.status.trace, res.status.code, res.status.message.replace('"', "'")))
        raise IOError(res.status.message)
    log.debug(f'msg="Invoked renamefile" result="{res}"')


def removefile(endpoint, filepath, userid, _force=False):
    '''Remove a file using the given userid as access token.
       The force argument is ignored for now for CS3 storage.'''
    reference = _getcs3reference(endpoint, filepath)
    req = cs3sp.DeleteRequest(ref=reference)
    res = ctx['cs3gw'].Delete(request=req, metadata=[('x-access-token', userid)])
    if res.status.code != cs3code.CODE_OK:
        if 'path not found' in str(res):
            log.info(f'msg="Invoked removefile on non-existing file" filepath="{filepath}"')
            raise IOError(common.ENOENT_MSG)
        log.error('msg="Failed to remove file" filepath="%s" trace="%s" code="%s" reason="%s"' %
                  (filepath, res.status.trace, res.status.code, res.status.message.replace('"', "'")))
        raise IOError(res.status.message)
    log.debug(f'msg="Invoked removefile" result="{res}"')
