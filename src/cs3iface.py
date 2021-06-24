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


# module-wide state
ctx = {}        # "map" to store some module context: cf. init()
tokens = {}     # map userid [string] to {authentication token, token expiration time}


def init(config, log):
  '''Init module-level variables'''
  ctx['log'] = log
  ctx['chunksize'] = config.getint('io', 'chunksize')
  ctx['ssl_verify'] = config.getboolean('cs3', 'sslverify', fallback=True)
  ctx['authtokenvalidity'] = config.getint('cs3', 'authtokenvalidity')
  if config.has_option('cs3', 'revagateway'):
    revagateway = config.get('cs3', 'revagateway')
  else:
    # legacy entry, to be dropped at next major release
    revagateway = config.get('cs3', 'revahost')
  # prepare the gRPC connection
  ch = grpc.insecure_channel(revagateway)
  ctx['cs3stub'] = cs3gw_grpc.GatewayAPIStub(ch)



def authenticate_for_test(userid, userpwd):
  '''Use basic authentication against Reva for testing purposes'''
  authReq = cs3gw.AuthenticateRequest(type='basic', client_id=userid, client_secret=userpwd)
  authRes = ctx['cs3stub'].Authenticate(authReq)
  ctx['log'].debug('msg="Authenticated user" res="%s"' % authRes)
  if authRes.status.code != cs3code.CODE_OK:
    raise IOError('Failed to authenticate as user ' + userid + ': ' + authRes.status.message)
  return authRes.token


def stat(endpoint, fileid, userid, versioninv=0):
  '''Stat a file and returns (size, mtime) as well as other extended info using the given userid as access token.
  Note that endpoint here means the storage id. Note that fileid can be either a path (which MUST begin with /),
  or an id (which MUST NOT start with a /).
  The versioninv flag is currently not supported, see CERNBOX-1216.'''
  if endpoint == 'default':
    raise IOError('A CS3API-compatible storage endpoint must be identified by a storage UUID')
  if versioninv == 1:
    ctx['log'].warning('msg="Version-invariant Stat not yet supported, going for standard Stat"')
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
  ctx['log'].info('msg="Invoked stat" fileid="%s" elapsedTimems="%.1f"' % (fileid, (tend-tstart)*1000))
  if statInfo.status.code == cs3code.CODE_OK:
    ctx['log'].debug('msg="Stat result" data="%s"' % statInfo)
    if statInfo.info.type == cs3spr.RESOURCE_TYPE_CONTAINER:
      raise IOError('Is a directory')
    elif statInfo.info.type not in (cs3spr.RESOURCE_TYPE_FILE, cs3spr.RESOURCE_TYPE_SYMLINK):
      ctx['log'].warning('msg="Stat: unexpected type" type="%d"' % statInfo.info.type)
      raise IOError('Unexpected type %d' % statInfo.info.type)
    # we base64-encode the inode so it can be used in a WOPISrc
    inode = urlsafe_b64encode(statInfo.info.id.opaque_id.encode())
    return {
        'inode': statInfo.info.id.storage_id + '-' + inode.decode(),
        'filepath': statInfo.info.path,
        'userid': statInfo.info.owner.opaque_id,
        'size': statInfo.info.size,
        'mtime': statInfo.info.mtime.seconds
        }
  ctx['log'].info('msg="Failed stat" fileid="%s" reason="%s"' % (fileid, statInfo.status.message))
  raise IOError('No such file or directory' if statInfo.status.code == cs3code.CODE_NOT_FOUND else statInfo.status.message)


def statx(endpoint, fileid, userid, versioninv=0):
  '''Get extended stat info (inode, filepath, userid, size, mtime). Equivalent to stat.'''
  return stat(endpoint, fileid, userid, versioninv)


def setxattr(_endpoint, filepath, userid, key, value):
  '''Set the extended attribute <key> to <value> using the given userid as access token'''
  reference = cs3spr.Reference(path=filepath)
  arbitrary_metadata = cs3spr.ArbitraryMetadata()
  arbitrary_metadata.metadata.update({key: str(value)})    # pylint: disable=no-member
  req = cs3sp.SetArbitraryMetadataRequest(ref=reference, arbitrary_metadata=arbitrary_metadata)
  res = ctx['cs3stub'].SetArbitraryMetadata(request=req,
                                            metadata=[('x-access-token', userid)])
  if res.status.code != cs3code.CODE_OK:
    ctx['log'].warning('msg="Failed to getxattr" filepath="%s" key="%s" reason="%s"' % (filepath, key, res.status.message))
    raise IOError(res.status.message)
  ctx['log'].debug('msg="Invoked setxattr" result="%s"' % res)


def getxattr(_endpoint, filepath, userid, key):
  '''Get the extended attribute <key> using the given userid as access token. Do not raise exceptions'''
  tstart = time.time()
  reference = cs3spr.Reference(path=filepath)
  statInfo = ctx['cs3stub'].Stat(request=cs3sp.StatRequest(ref=reference),
                                 metadata=[('x-access-token', userid)])
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
  res = ctx['cs3stub'].UnsetArbitraryMetadata(request=req, metadata=[('x-access-token', userid)])
  if res.status.code != cs3code.CODE_OK:
    ctx['log'].warning('msg="Failed to rmxattr" filepath="%s" key="%s" exception="%s"' % (filepath, key, res.status.message))
    raise IOError(res.status.message)
  ctx['log'].debug('msg="Invoked rmxattr" result="%s"' % res)


def readfile(_endpoint, filepath, userid):
  '''Read a file using the given userid as access token. Note that the function is a generator, managed by Flask.'''
  tstart = time.time()
  # prepare endpoint
  req = cs3sp.InitiateFileDownloadRequest(ref=cs3spr.Reference(path=filepath))
  initfiledownloadres = ctx['cs3stub'].InitiateFileDownload(request=req, metadata=[('x-access-token', userid)])
  if initfiledownloadres.status.code == cs3code.CODE_NOT_FOUND:
    ctx['log'].info('msg="File not found on read" filepath="%s"' % filepath)
    yield IOError('No such file or directory')
  elif initfiledownloadres.status.code != cs3code.CODE_OK:
    ctx['log'].debug('msg="Failed to initiateFileDownload on read" filepath="%s" reason="%s"' % \
                     (filepath, initfiledownloadres.status.message))
    yield IOError(initfiledownloadres.status.message)
  ctx['log'].debug('msg="readfile: InitiateFileDownloadRes returned" protocols="%s"' % initfiledownloadres.protocols)

  # Download
  try:
    protocol = [p for p in initfiledownloadres.protocols if p.protocol == "simple"][0]
    headers = {
        'x-access-token': userid,
        'X-Reva-Transfer': protocol.token    # needed if the downloads pass through the data gateway in reva
    }
    fileget = requests.get(url=protocol.download_endpoint, headers=headers, verify=ctx['ssl_verify'])
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


def writefile(_endpoint, filepath, userid, content, islock=False):
  '''Write a file using the given userid as access token. The entire content is written
    and any pre-existing file is deleted (or moved to the previous version if supported).
    The islock flag is currently not supported. TODO the backend should at least support
    writing the file with O_CREAT|O_EXCL flags to prevent races.'''
  if islock:
    ctx['log'].warning('msg="Lock (no-overwrite) flag not yet supported, going for standard upload"')
  tstart = time.time()
  # prepare endpoint
  if isinstance(content, str):
    content = bytes(content, 'UTF-8')
  size = str(len(content))
  metadata = types.Opaque(map={"Upload-Length": types.OpaqueEntry(decoder="plain", value=str.encode(size))})
  req = cs3sp.InitiateFileUploadRequest(ref=cs3spr.Reference(path=filepath), opaque=metadata)
  initfileuploadres = ctx['cs3stub'].InitiateFileUpload(request=req, metadata=[('x-access-token', userid)])
  if initfileuploadres.status.code != cs3code.CODE_OK:
    ctx['log'].debug('msg="Failed to initiateFileUpload on write" filepath="%s" reason="%s"' % \
                     (filepath, initfileuploadres.status.message))
    raise IOError(initfileuploadres.status.message)
  ctx['log'].debug('msg="writefile: InitiateFileUploadRes returned" protocols="%s"' % initfileuploadres.protocols)

  # Upload
  try:
    # Get the endpoint for simple protocol
    # TODO: configure TUS client
    protocol = [p for p in initfileuploadres.protocols if p.protocol == "simple"][0]
    headers = {
        'x-access-token': userid,
        'Upload-Length': size,
        'X-Reva-Transfer': protocol.token    # needed if the uploads pass through the data gateway in reva
    }
    putres = requests.put(url=protocol.upload_endpoint, data=content, headers=headers, verify=ctx['ssl_verify'])
  except requests.exceptions.RequestException as e:
    ctx['log'].error('msg="Exception when uploading file to Reva" reason="%s"' % e)
    raise IOError(e)
  tend = time.time()
  if putres.status_code != http.client.OK:
    ctx['log'].error('msg="Error uploading file to Reva" code="%d" reason="%s"' % (putres.status_code, putres.reason))
    raise IOError(putres.reason)
  ctx['log'].info('msg="File written successfully" filepath="%s" elapsedTimems="%.1f" islock="%s"' % \
                  (filepath, (tend-tstart)*1000, islock))


def renamefile(_endpoint, filepath, newfilepath, userid):
  '''Rename a file from origfilepath to newfilepath using the given userid as access token.'''
  source = cs3spr.Reference(path=filepath)
  destination = cs3spr.Reference(path=newfilepath)
  req = cs3sp.MoveRequest(source=source, destination=destination)
  res = ctx['cs3stub'].Move(request=req, metadata=[('x-access-token', userid)])
  if res.status.code != cs3code.CODE_OK:
    ctx['log'].warning('msg="Failed to rename file" filepath="%s" error="%s"' % (filepath, res.status.message))
    raise IOError(res.status.message)
  ctx['log'].debug('msg="Invoked renamefile" result="%s"' % res)


def removefile(_endpoint, filepath, userid, _force=0):
  '''Remove a file using the given userid as access token.
     The force argument is ignored for now for CS3 storage.'''
  reference = cs3spr.Reference(path=filepath)
  req = cs3sp.DeleteRequest(ref=reference)
  res = ctx['cs3stub'].Delete(request=req, metadata=[('x-access-token', userid)])
  if res.status.code != cs3code.CODE_OK:
    ctx['log'].warning('msg="Failed to remove file" filepath="%s" error="%s"' % (filepath, res))
    raise IOError(res.status.message)
  ctx['log'].debug('msg="Invoked removefile" result="%s"' % res)
