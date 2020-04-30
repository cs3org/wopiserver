'''
cs3iface.py

CS3 API based interface for the IOP WOPI server

Authors:
Giuseppe.LoPresti@cern.ch, CERN/IT-ST
Lovisa.Lugnegaard@cern.ch, CERN/IT-ST
'''

import time
import os
import grpc

# some_file.py
import sys
# insert at 1, 0 is the script path (or '' in REPL)
sys.path.insert(1, '../python-cs3apis')

import cs3.add.addition as a

import cs3.gateway.v1beta1.gateway_api_pb2 as cs3gw
import cs3.gateway.v1beta1.gateway_api_pb2_grpc as cs3gw_grpc
import cs3.storage.provider.v1beta1.provider_api_pb2 as sp
import cs3.storage.provider.v1beta1.resources_pb2 as spr

from google import auth as google_auth
from google.auth import jwt as google_auth_jwt
from google.auth.transport import grpc as google_auth_transport_grpc

# module-wide state
config = None
log = None
tok = None
credentials = {}

def _getfilename(filename):
    '''map the given filename into the target namespace by prepending the homepath (see storagehomepath in wopiserver.conf)'''
    return filename   # TODO do we need that??


def init(inconfig):
    '''Init module-level variables'''
    global config         # pylint: disable=global-statement
    global log            # pylint: disable=global-statement
    global tok            # pylint: disable=global-statement
    config = inconfig
    # log = inlog
    #revaurl = config.get('cs3', 'revaurl')
    revaurl = 'localhost:19000'  # XXX for now

    # prepare the gRPC connection
    ch = grpc.insecure_channel(revaurl)
    cs3stub = cs3gw_grpc.GatewayAPIStub(ch)
    authReq = cs3gw.AuthenticateRequest(
        type='basic', client_id='einstein', client_secret='relativity')
    authRes = cs3stub.Authenticate(authReq)
    credentials['ch'] = ch
    credentials['cs3stub'] = cs3stub
    credentials['authReq'] = authReq
    credentials['token'] = authRes.token


def stat(_endpoint, filename, _ruid, _rgid):
    '''Stat a file and returns (size, mtime) as well as other extended info. Assume the given uid, gid has access.'''
    filename = _getfilename(filename)
    try:
        tstart = time.clock()
        reference = spr.Reference(path = 'example.txt', id = spr.ResourceId(storage_id = '123e4567-e89b-12d3-a456-426655440000', opaque_id = 'fileid-home/example.txt'))
        statReq = sp.StatRequest(ref = reference)
        statInfo = credentials['cs3stub'].Stat(request = statReq, metadata = [('x-access-token', credentials['token'])])
        tend = time.clock()
        print('msg="Invoked stat" filename="%s" elapsedTimems="%.1f"' %
                 (filename, (tend-tstart)*1000))
        return {
            'inode': statInfo.info.id,
            'ouid': statInfo.info.owner.opaque_id,
            'size': statInfo.info.size,
            # TODO group id?
            'mtime': statInfo.info.mtime
        }
    except (FileNotFoundError, PermissionError) as e:
        raise IOError(e)

# TODO not in CS3API
# def statx(_endpoint, filename, _ruid, _rgid):
#     '''Get extended stat info (inode, ouid, ogid, size, mtime). Equivalent to stat in the case of local storage.'''
#     return stat(_endpoint, filename, _ruid, _rgid)


def setxattr(_endpoint, filename, key, value):
    '''Set the extended attribute <key> to <value> on behalf of the given reference'''
    # TODO implement this on the reva side (now reva returns operation not supported)
    reference = spr.Reference(path = 'example.txt', id = spr.ResourceId(storage_id = '123e4567-e89b-12d3-a456-426655440000', opaque_id = 'fileid-home/example.txt'))
    arbitrary_metadata = spr.ArbitraryMetadata()
    arbitrary_metadata.metadata.update({key: value})
    req = sp.SetArbitraryMetadataRequest(ref = reference, arbitrary_metadata = arbitrary_metadata)
    try:
        credentials['cs3stub'].SetArbitraryMetadata(request = req, metadata = [('x-access-token', credentials['token'])])
        # TODO check for error
    except (FileNotFoundError, PermissionError) as e:
        raise IOError(e)


# not in cs3 API
# def getxattr(_endpoint, filename, _ruid, _rgid, key):
#     '''Get the extended attribute <key> on behalf of the given uid, gid. Do not raise exceptions'''
#     try:
#         return credentials['cs3stub'].getarbritarymetadata(_getfilename(filename), key)
#     except (FileNotFoundError, PermissionError) as e:
#         log.warning('msg="Failed to getxattr" filename="%s" key="%s" exception="%s"' % (
#             filename, key, e))
#         return None


def rmxattr(_endpoint, filename, key):
    '''Remove the extended attribute <key> on behalf of the given uid, gid'''
    # TODO implement this on the reva side (now reva returns operation not supported)
    reference = spr.Reference(path = 'example.txt', id = spr.ResourceId(storage_id = '123e4567-e89b-12d3-a456-426655440000', opaque_id = 'fileid-home/example.txt'))
    req = sp.UnsetArbitraryMetadataRequest(ref = reference, arbitrary_metadata_keys = [key])
    try:
        credentials['cs3stub'].UnsetArbitraryMetadata(request = req, metadata = [('x-access-token', credentials['token'])])
        # TODO check for error
    except (FileNotFoundError, PermissionError) as e:
        raise IOError(e)


def readfile(_endpoint, filename, _ruid, _rgid):
    '''Read a file on behalf of the given uid, gid. Note that the function is a generator, managed by Flask.'''
    print('msg="Invoking readFile" filename="%s"' % filename)
    try:
        tstart = time.clock()
        # chunksize = config.getint('io', 'chunksize')
        reference = spr.Reference(path = 'example.txt', id = spr.ResourceId(storage_id = '123e4567-e89b-12d3-a456-426655440000', opaque_id = 'fileid-home/example.txt'))
        req = sp.InitiateFileDownloadRequest(ref = reference)
        res = credentials['cs3stub'].InitiateFileDownload(request = req, metadata = [('x-access-token', credentials['token'])])
        #TODO open and actually read file
        tend = time.clock()
        print('res' + res)
        print('msg="File open for read" filename="%s" elapsedTimems="%.1f"' % (
            filename, (tend-tstart)*1000))
    except FileNotFoundError as e:
        print('msg="File not found on read" filename="%s"' % filename)


def writefile(_endpoint, filename, content, noversion=0):
    '''Write a file via cs3 apis on behalf of the given uid, gid. The entire content is written
       and any pre-existing file is deleted (or moved to the previous version if supported).
       If noversion=1, the write explicitly disables versioning: this is useful for lock files.'''
    size = len(content)
    print('msg="Invoking writeFile" filename="%s" size="%d"' %
              (filename, size))
    try:
        tstart = time.clock()
        # get file to write to, do we need this?
        reference = spr.Reference(path = 'example.txt', id = spr.ResourceId(storage_id = '123e4567-e89b-12d3-a456-426655440000', opaque_id = 'fileid-home/example.txt'))
        req = sp.InitiateFileDownloadRequest(ref = reference)
        res = credentials['cs3stub'].InitiateFileDownload(request = req, metadata = [('x-access-token', credentials['token'])])
        f = open(filename, mode='wb')
        tend = time.clock()
        log.info('msg="File open for write" filename="%s" elapsedTimems="%.1f"' % (filename, (tend-tstart)*1000))
        # write the file. In a future implementation, we should find a way to only update the required chunks...
        written = f.write(content)
        f.close()
        tstart = time.clock()
        reference = spr.Reference(path = 'example.txt', id = spr.ResourceId(storage_id = '123e4567-e89b-12d3-a456-426655440000', opaque_id = 'fileid-home/example.txt'))
        req = sp.InitiateFileUploadRequest(ref = reference)
        res = credentials['cs3stub'].InitiateFileUpload(request = req, metadata = [('x-access-token', credentials['token'])])
        tend = time.clock()
        print('msg="File open for write" filename="%s" elapsedTimems="%.1f"' % (
            filename, (tend-tstart)*1000))
        if res.status.code != 1:
            raise IOError('Something went wrong, message: ' + res.status.message)
    except OSError as e:
        print(
            'msg="Error writing to file" filename="%s" error="%s"' % (filename, e))
        raise IOError(e)


def renamefile(_endpoint, origfilename, newfilename, ruid, rgid):
    '''Rename a file from origfilename to newfilename on behalf of the given uid, gid.'''
    source = spr.Reference(path = 'example.txt', id = spr.ResourceId(storage_id = '123e4567-e89b-12d3-a456-426655440000', opaque_id = 'fileid-home/example.txt'))
    destination = spr.Reference(path = newfilename, id = spr.ResourceId(storage_id = '123e4567-e89b-12d3-a456-426655440000', opaque_id = 'fileid-home/' +  newfilename))
    req = sp.MoveRequest(source = source, destination = destination)
    try:
        credentials['cs3stub'].Move(request = req, metadata = [('x-access-token', credentials['token'])])
    except (FileNotFoundError, PermissionError) as e:
        raise IOError(e)


def removefile(_endpoint, filename, _ruid, _rgid, _force=0):
    '''Remove a file on behalf of the given uid, gid.
       The force argument is irrelevant and ignored for local storage.'''
    reference = spr.Reference(path = 'example.txt', id = spr.ResourceId(storage_id = '123e4567-e89b-12d3-a456-426655440000', opaque_id = 'fileid-home/example.txt'))
    req = sp.DeleteRequest(ref = reference)
    try:
        credentials['cs3stub'].Delete(request = req, metadata = [('x-access-token', credentials['token'])])
    except (FileNotFoundError, PermissionError, IsADirectoryError) as e:
        raise IOError(e)
