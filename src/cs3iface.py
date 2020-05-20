'''
cs3iface.py

CS3 API based interface for the IOP WOPI server

Authors:
Giuseppe.LoPresti@cern.ch, CERN/IT-ST
Lovisa.Lugnegaard@cern.ch, CERN/IT-ST
'''

import time
import requests
import grpc
import http

from tusclient import client as tusclient

from google.auth.transport import grpc as google_auth_transport_grpc
from google.auth import jwt as google_auth_jwt
from google import auth as google_auth

import cs3.storage.provider.v1beta1.resources_pb2 as spr
import cs3.storage.provider.v1beta1.provider_api_pb2 as sp
import cs3.types.v1beta1.types_pb2 as types
import cs3.gateway.v1beta1.gateway_api_pb2_grpc as cs3gw_grpc
import cs3.gateway.v1beta1.gateway_api_pb2 as cs3gw
import cs3.rpc.code_pb2 as cs3code


# module-wide state
ctx = {}        # "map" to store some module context: cf. init()
tokens = {}     # map userid [string] to authentication token


def init(config, log):
  '''Init module-level variables'''
  ctx['log'] = log
  ctx['chunksize'] = config.getint('io', 'chunksize')
  revahost = config.get('cs3', 'revahost')
  # prepare the gRPC connection
  ch = grpc.insecure_channel(revahost)
  ctx['cs3stub'] = cs3gw_grpc.GatewayAPIStub(ch)


def _authenticate(userid):
  '''Obtain a token from Reva for the given userid'''
  # TODO this will become
  #authReq = cs3gw.AuthenticateRequest(type='bearer', client_secret=userid)
  authReq = cs3gw.AuthenticateRequest(type='basic', client_id='einstein', client_secret='relativity')
  if userid not in tokens:
    # authenticate this user
    authRes = ctx['cs3stub'].Authenticate(authReq)
    tokens[userid] = authRes.token
  return tokens[userid]


def stat(endpoint, fileid, userid):
  '''Stat a file and returns (size, mtime) as well as other extended info using the given userid as access token.'''
  if endpoint == 'default':
    raise IOError('A CS3API-compatible storage endpoint must be identified by a storage UUID')
  tstart = time.clock()
  if fileid[0] == '/':
    # assume this is a filepath
    ref = spr.Reference(path=fileid)
  else:
    # assume we have an opaque fileid
    ref = spr.Reference(id=spr.ResourceId(storage_id=endpoint, opaque_id=fileid))
  statInfo = ctx['cs3stub'].Stat(request=sp.StatRequest(ref=ref),
                                 metadata=[('x-access-token', _authenticate(userid))])
  tend = time.clock()
  ctx['log'].info('msg="Invoked stat" fileid="%s" elapsedTimems="%.1f"' % (fileid, (tend-tstart)*1000))
  if statInfo.status.code == cs3code.CODE_OK:
    ctx['log'].debug('msg="Stat result" data="%s"' % statInfo)
    return {
        'inode': statInfo.info.id.storage_id + ':' + statInfo.info.id.opaque_id,
        'filepath': statInfo.info.path,
        'userid': statInfo.info.owner.opaque_id,
        'size': statInfo.info.size,
        'mtime': statInfo.info.mtime
        }
  else:
    ctx['log'].info('msg="Failed stat" fileid="%s" reason="%s"' % (fileid, statInfo.status.message))
    raise IOError(statInfo.status.message)


def statx(endpoint, fileid, userid):
  '''Get extended stat info (inode, filepath, userid, size, mtime). Equivalent to stat.'''
  return stat(endpoint, fileid, userid)


def setxattr(endpoint, filepath, userid, key, value):
  '''Set the extended attribute <key> to <value> using the given userid as access token'''
  # TODO implement this on the reva side (now reva returns operation not supported)
  reference = spr.Reference(path=filepath, id=spr.ResourceId(storage_id=endpoint))
  arbitrary_metadata = spr.ArbitraryMetadata()
  arbitrary_metadata.metadata.update({key: value})
  req = sp.SetArbitraryMetadataRequest(ref=reference, arbitrary_metadata=arbitrary_metadata)
  try:
    ctx['cs3stub'].SetArbitraryMetadata(
        request=req, metadata=[('x-access-token', _authenticate(userid))])
    # TODO check for error
  except Exception as e:
    raise IOError(e)


def getxattr(endpoint, filepath, userid, key):
  '''Get the extended attribute <key> using the given userid as access token. Do not raise exceptions'''
  try:
    tstart = time.clock()
    reference = spr.Reference(path=filepath, id=spr.ResourceId(storage_id=endpoint))
    statInfo = ctx['cs3stub'].Stat(request=sp.StatRequest(ref=reference),
                                   metadata=[('x-access-token', _authenticate(userid))])
    tend = time.clock()
    ctx['log'].info('msg="Invoked stat for getxattr" filepath="%s" elapsedTimems="%.1f"' % (filepath, (tend-tstart)*1000))
    try:
      return statInfo.info.arbitrary_metadata.metadata[key]
    except KeyError:
      ctx['log'].warning('msg="Key not found in getxattr" filepath="%s" key="%s"' % (filepath, key))
  except Exception as e:
    ctx['log'].warning('msg="Failed to getxattr" filepath="%s" key="%s" exception="%s"' % (filepath, key, e))
    raise IOError(e)
  return None


def rmxattr(endpoint, filepath, userid, key):
  '''Remove the extended attribute <key> using the given userid as access token'''
  # TODO implement this on the reva side (now reva returns operation not supported)
  reference = spr.Reference(path=filepath, id=spr.ResourceId(storage_id=endpoint))
  req = sp.UnsetArbitraryMetadataRequest(ref=reference, arbitrary_metadata_keys=[key])
  try:
    ctx['cs3stub'].UnsetArbitraryMetadata(request=req, metadata=[('x-access-token', _authenticate(userid))])
    # TODO check for error
  except Exception as e:
    ctx['log'].warning('msg="Failed to rmxattr" filepath="%s" key="%s" exception="%s"' % (filepath, key, e))
    raise IOError(e)


def readfile(endpoint, filepath, userid):
  '''Read a file using the given userid as access token. Note that the function is a generator, managed by Flask.'''
  ctx['log'].info('msg="Invoking readFile" filepath="%s"' % filepath)
  #fileid = stat(endpoint, filepath, userid)['inode'].split(':')[1]
  try:
    reference = spr.Reference(path=filepath)
    req = sp.InitiateFileDownloadRequest(ref=reference)
    filedownloadres = ctx['cs3stub'].InitiateFileDownload(
        request=req, metadata=[('x-access-token', _authenticate(userid))])

    # Download
    ctx['log'].debug('msg="readfile: InitiateFileDownloadRes returned" endpoint="%s"' % filedownloadres.download_endpoint)
    fileinformation = requests.get(url=filedownloadres.download_endpoint + filepath,    # XXX this is a bug in Reva, the endpoint is supposed to be complete
                                   headers={'x-access-token': _authenticate(userid)})
    data = fileinformation.content
    if not data:
      ctx['log'].info('msg="File not found on read" filepath="%s" rc="%s"' % (filepath, fileinformation))
      yield IOError('No such file or directory')
    else:
      for i in range(0, len(data), ctx['chunksize']):
        yield data[i:i+ctx['chunksize']]
  except Exception as e:
    ctx['log'].warning('msg="Error when reading file" filepath="%s" error="%s"' % (filepath, e))
    yield IOError(e)


def writefile(endpoint, filepath, userid, content, noversion=0):
  '''Write a file using the given userid as access token. The entire content is written
    and any pre-existing file is deleted (or moved to the previous version if supported).
    If noversion=1, the write explicitly disables versioning: this is useful for lock files.'''
  try:
    # TODO: In a future implementation, we should find a way to only update the required chunks 
    # TODO: Use tus client instead of PUT
    headers = {
      'Tus-Resumable': '1.0.0',
      'x-access-token':  _authenticate(userid)
    }

    requests.put(url='http://localhost:19001/data' + filepath, data=content, headers=headers)
  except Exception as e:
    print('msg="Error writing to file" filepath="%s" error="%s"' % (filepath, e))
    raise IOError(e)


def renamefile(endpoint, filepath, newfilepath, userid):
  '''Rename a file from origfilepath to newfilepath using the given userid as access token.'''
  source = spr.Reference(path=filepath, id=spr.ResourceId(storage_id=endpoint))
  destination = spr.Reference(path=newfilepath, id=spr.ResourceId(storage_id=endpoint))
  req = sp.MoveRequest(source=source, destination=destination)
  try:
    ctx['cs3stub'].Move(request=req, metadata=[('x-access-token', _authenticate(userid))])
  except Exception as e:
    ctx['log'].warning('msg="Failed to rename file" filepath="%s" error="%s"' % (filepath, e))
    raise IOError(e)


def removefile(endpoint, filepath, userid, _force=0):
  '''Remove a file using the given userid as access token.
     The force argument is ignored for now for CS3 storage.'''
  reference = spr.Reference(path=filepath, id=spr.ResourceId(storage_id=endpoint))
  req = sp.DeleteRequest(ref=reference)
  try:
    ctx['cs3stub'].Delete(request=req, metadata=[('x-access-token', _authenticate(userid))])
  except Exception as e:
    ctx['log'].warning('msg="Failed to remove file" filepath="%s" error="%s"' % (filepath, e))
    raise IOError(e)
