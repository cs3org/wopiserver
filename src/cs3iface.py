'''
cs3iface.py

CS3 API based interface for the IOP WOPI server

Authors:
Giuseppe.LoPresti@cern.ch, CERN/IT-ST
Lovisa.Lugnegaard@cern.ch, CERN/IT-ST
'''

import time
import asyncio
import http
import requests
import grpc

import cs3.storage.provider.v1beta1.resources_pb2 as cs3spr
import cs3.storage.provider.v1beta1.provider_api_pb2 as cs3sp
import cs3.gateway.v1beta1.gateway_api_pb2_grpc as cs3gw_grpc
import cs3.gateway.v1beta1.gateway_api_pb2 as cs3gw
import cs3.rpc.code_pb2 as cs3code


# module-wide state
ctx = {}        # "map" to store some module context: cf. init()
tokens = {}     # map userid [string] to {authentication token, token expiration time}


def init(config, log):
  '''Init module-level variables'''
  ctx['log'] = log
  ctx['chunksize'] = config.getint('io', 'chunksize')
  ctx['authtokenvalidity'] = config.getint('cs3', 'authtokenvalidity')
  revahost = config.get('cs3', 'revahost')
  # prepare the gRPC connection
  ch = grpc.insecure_channel(revahost)
  ctx['cs3stub'] = cs3gw_grpc.GatewayAPIStub(ch)


async def _async_cleanuptokens():
  '''A local function to go through existing tokens and remove the expired ones'''
  now = time.time()
  expiredkeys = [u for u in tokens if tokens[u]['exp'] < now]
  for u in expiredkeys:
    del tokens[u]


def _authenticate(userid):
  '''Obtain a token from Reva for the given userid'''
  # TODO this will become
  #authReq = cs3gw.AuthenticateRequest(type='bearer', client_secret=userid)
  authReq = cs3gw.AuthenticateRequest(type='basic', client_id='einstein', client_secret='relativity')
  if userid not in tokens or tokens[userid]['exp'] < time.time():
    authRes = ctx['cs3stub'].Authenticate(authReq)
    tokens[userid] = {'tok': authRes.token, 'exp': time.time() + ctx['authtokenvalidity']}
    # piggy back on the opportunity to expire old tokens, but asynchronously
    # as to not impact the current session: let's use python3.7's coroutines support
    asyncio.run(_async_cleanuptokens())
  return tokens[userid]['tok']


def stat(endpoint, fileid, userid):
  '''Stat a file and returns (size, mtime) as well as other extended info using the given userid as access token.
  Note that endpoint here means the storage id. Note that fileid can be either a path (which MUST begin with /), or an id (which MUST NOT
  start with a /).'''
  if endpoint == 'default':
    raise IOError('A CS3API-compatible storage endpoint must be identified by a storage UUID')
  tstart = time.time()
  if fileid[0] == '/':
    # assume this is a filepath
    ref = cs3spr.Reference(path=fileid)
  else:
    # assume we have an opaque fileid
    ref = cs3spr.Reference(id=cs3spr.ResourceId(storage_id=endpoint, opaque_id=fileid))
  statInfo = ctx['cs3stub'].Stat(request=cs3sp.StatRequest(ref=ref),
                                 metadata=[('x-access-token', _authenticate(userid))])
  tend = time.time()
  ctx['log'].info('msg="Invoked stat" fileid="%s" elapsedTimems="%.1f"' % (fileid, (tend-tstart)*1000))
  if statInfo.status.code == cs3code.CODE_OK:
    ctx['log'].debug('msg="Stat result" data="%s"' % statInfo)
    return {
        'inode': statInfo.info.id.storage_id + ':' + statInfo.info.id.opaque_id,
        'filepath': statInfo.info.path,
        'userid': statInfo.info.owner.opaque_id,
        'size': statInfo.info.size,
        'mtime': statInfo.info.mtime.seconds
        }
  ctx['log'].info('msg="Failed stat" fileid="%s" reason="%s"' % (fileid, statInfo.status.message))
  raise IOError(statInfo.status.message)


def statx(endpoint, fileid, userid):
  '''Get extended stat info (inode, filepath, userid, size, mtime). Equivalent to stat.'''
  return stat(endpoint, fileid, userid)


def setxattr(_endpoint, filepath, userid, key, value):
  '''Set the extended attribute <key> to <value> using the given userid as access token'''
  reference = cs3spr.Reference(path=filepath)
  arbitrary_metadata = cs3spr.ArbitraryMetadata()
  arbitrary_metadata.metadata.update({key: str(value)})    # pylint: disable=no-member
  req = cs3sp.SetArbitraryMetadataRequest(ref=reference, arbitrary_metadata=arbitrary_metadata)
  res = ctx['cs3stub'].SetArbitraryMetadata(request=req,
                                            metadata=[('x-access-token', _authenticate(userid))])
  if res.status.code != cs3code.CODE_OK:
    ctx['log'].warning('msg="Failed to getxattr" filepath="%s" key="%s" reason="%s"' % (filepath, key, res.status.message))
    raise IOError(res.status.message)
  ctx['log'].debug('msg="Invoked setxattr" result="%s"' % res)


def getxattr(_endpoint, filepath, userid, key):
  '''Get the extended attribute <key> using the given userid as access token. Do not raise exceptions'''
  tstart = time.time()
  reference = cs3spr.Reference(path=filepath)
  statInfo = ctx['cs3stub'].Stat(request=cs3sp.StatRequest(ref=reference),
                                 metadata=[('x-access-token', _authenticate(userid))])
  tend = time.time()
  if statInfo.status.code != cs3code.CODE_OK:
    ctx['log'].warning('msg="Failed to stat" filepath="%s" key="%s" reason="%s"' % (filepath, key, statInfo.status.message))
    raise IOError(statInfo.status.message)
  try:
    xattrvalue = statInfo.info.arbitrary_metadata.metadata[key]
    if xattrvalue == '':
      raise KeyError
    ctx['log'].debug('msg="Invoked stat for getxattr" filepath="%s" elapsedTimems="%.1f"' % (filepath, (tend-tstart)*1000))
    return xattrvalue
  except KeyError:
    ctx['log'].info('msg="Key not found in getxattr" filepath="%s" key="%s"' % (filepath, key))
    return None


def rmxattr(_endpoint, filepath, userid, key):
  '''Remove the extended attribute <key> using the given userid as access token'''
  reference = cs3spr.Reference(path=filepath)
  req = cs3sp.UnsetArbitraryMetadataRequest(ref=reference, arbitrary_metadata_keys=[key])
  res = ctx['cs3stub'].UnsetArbitraryMetadata(request=req, metadata=[('x-access-token', _authenticate(userid))])
  if res.status.code != cs3code.CODE_OK:
    ctx['log'].warning('msg="Failed to rmxattr" filepath="%s" key="%s" exception="%s"' % (filepath, key, res.status.message))
    raise IOError(res.status.message)
  ctx['log'].debug('msg="Invoked rmxattr" result="%s"' % res)


def readfile(_endpoint, filepath, userid):
  '''Read a file using the given userid as access token. Note that the function is a generator, managed by Flask.'''
  tstart = time.time()
  # prepare endpoint
  req = cs3sp.InitiateFileDownloadRequest(ref=cs3spr.Reference(path=filepath))
  initfiledownloadres = ctx['cs3stub'].InitiateFileDownload(request=req, metadata=[('x-access-token', _authenticate(userid))])
  if initfiledownloadres.status.code == cs3code.CODE_NOT_FOUND:
    ctx['log'].info('msg="File not found on read" filepath="%s"' % filepath)
    yield IOError('No such file or directory')
  elif initfiledownloadres.status.code != cs3code.CODE_OK:
    ctx['log'].debug('msg="Failed to initiateFileDownload on read" filepath="%s" reason="%s"' % \
                     (filepath, initfiledownloadres.status.message))
    yield IOError(initfiledownloadres.status.message)
  ctx['log'].debug('msg="readfile: InitiateFileDownloadRes returned" endpoint="%s"' % initfiledownloadres.download_endpoint)

  # Download
  try:
    fileget = requests.get(url=initfiledownloadres.download_endpoint, headers={'x-access-token': _authenticate(userid)})
  except requests.exceptions.RequestException as e:
    ctx['log'].error('msg="Exception when downloading file from Reva" reason="%s"' % e)
    yield IOError(e)
  tend = time.time()
  data = fileget.content
  if fileget.status_code != http.client.OK:
    ctx['log'].error('msg="Error downloading file from Reva" code="%d" reason="%s"' % (fileget.status_code, fileget.reason))
    yield IOError(fileget.reason)
  else:
    ctx['log'].info('msg="File open for read" filepath="%s" elapsedTimems="%.1f"' % (filepath, (tend-tstart)*1000))
    for i in range(0, len(data), ctx['chunksize']):
      yield data[i:i+ctx['chunksize']]


def writefile(_endpoint, filepath, userid, content, _noversion=0):
  '''Write a file using the given userid as access token. The entire content is written
    and any pre-existing file is deleted (or moved to the previous version if supported).
    The noversion flag is currently not supported.'''
  tstart = time.time()
  # prepare endpoint
  req = cs3sp.InitiateFileUploadRequest(ref=cs3spr.Reference(path=filepath))
  initfileuploadres = ctx['cs3stub'].InitiateFileUpload(request=req, metadata=[('x-access-token', _authenticate(userid))])
  if initfileuploadres.status.code != cs3code.CODE_OK:
    ctx['log'].debug('msg="Failed to initiateFileUpload on write" filepath="%s" reason="%s"' % \
                     (filepath, initfileuploadres.status.message))
    raise IOError(initfileuploadres.status.message)
  ctx['log'].debug('msg="writefile: InitiateFileUploadRes returned" endpoint="%s"' % initfileuploadres.upload_endpoint)

  # Upload
  try:
    # TODO: Use tus client instead of PUT
    headers = {
        'Tus-Resumable': '1.0.0',
        'x-access-token':  _authenticate(userid)
    }
    putres = requests.put(url=initfileuploadres.upload_endpoint, data=content, headers=headers)
  except requests.exceptions.RequestException as e:
    ctx['log'].error('msg="Exception when uploading file to Reva" reason="%s"' % e)
    raise IOError(e)
  tend = time.time()
  if putres.status_code != http.client.OK:
    ctx['log'].error('msg="Error uploading file to Reva" code="%d" reason="%s"' % (putres.status_code, putres.reason))
    raise IOError(putres.reason)
  ctx['log'].info('msg="File open for write" filepath="%s" elapsedTimems="%.1f"' % (filepath, (tend-tstart)*1000))


def renamefile(_endpoint, filepath, newfilepath, userid):
  '''Rename a file from origfilepath to newfilepath using the given userid as access token.'''
  source = cs3spr.Reference(path=filepath)
  destination = cs3spr.Reference(path=newfilepath)
  req = cs3sp.MoveRequest(source=source, destination=destination)
  res = ctx['cs3stub'].Move(request=req, metadata=[('x-access-token', _authenticate(userid))])
  if res.status.code != cs3code.CODE_OK:
    ctx['log'].warning('msg="Failed to rename file" filepath="%s" error="%s"' % (filepath, res.status.message))
    raise IOError(res.status.message)
  ctx['log'].debug('msg="Invoked renamefile" result="%s"' % res)


def removefile(_endpoint, filepath, userid, _force=0):
  '''Remove a file using the given userid as access token.
     The force argument is ignored for now for CS3 storage.'''
  reference = cs3spr.Reference(path=filepath)
  req = cs3sp.DeleteRequest(ref=reference)
  res = ctx['cs3stub'].Delete(request=req, metadata=[('x-access-token', _authenticate(userid))])
  if res.status.code != cs3code.CODE_OK:
    ctx['log'].warning('msg="Failed to remove file" filepath="%s" error="%s"' % (filepath, res))
    raise IOError(res.status.message)
  ctx['log'].debug('msg="Invoked removefile" result="%s"' % res)
