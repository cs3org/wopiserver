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

from tusclient import client as tusclient

from google.auth.transport import grpc as google_auth_transport_grpc
from google.auth import jwt as google_auth_jwt
from google import auth as google_auth

import cs3.storage.provider.v1beta1.resources_pb2 as spr
import cs3.storage.provider.v1beta1.provider_api_pb2 as sp
import cs3.gateway.v1beta1.gateway_api_pb2_grpc as cs3gw_grpc
import cs3.gateway.v1beta1.gateway_api_pb2 as cs3gw
import cs3.rpc.code_pb2 as cs3code

# module-wide state
config = None
log = None
credentials = {}


def init(inconfig):
  '''Init module-level variables'''
  global config         # pylint: disable=global-statement
  global log            # pylint: disable=global-statement
  config = inconfig
  # log = inlog
  #revaurl = config.get('cs3', 'revaurl')
  revaurl = 'localhost:19000'  # XXX for now

  # prepare the gRPC connection
  ch = grpc.insecure_channel(revaurl)
  credentials['cs3stub'] = cs3gw_grpc.GatewayAPIStub(ch)


def _authenticate(userid):
  '''Obtain a token from Reva for the given userid'''
  # TODO this will become
  #authReq = cs3gw.AuthenticateRequest(type='bearer', client_secret=userid)
  authReq = cs3gw.AuthenticateRequest(type='basic', client_id='einstein', client_secret='relativity')
  if userid not in credentials:
    # authenticate this user
    authRes = credentials['cs3stub'].Authenticate(authReq)
    credentials[userid] = authRes.token
  return credentials[userid]


def stat(endpoint, fileid, userid):
  '''Stat a file and returns (size, mtime) as well as other extended info using the given userid as access token.'''
  if endpoint == 'default':
    raise IOError('A CS3API-compatible storage endpoint must be identified by a storage UUID')
  try:
    tstart = time.clock()
    ref = spr.Reference(id=spr.ResourceId(storage_id=endpoint, opaque_id=fileid))
    statInfo = credentials['cs3stub'].Stat(request=sp.StatRequest(ref=ref), metadata=[('x-access-token', _authenticate(userid))])
    tend = time.clock()
    print('msg="Invoked stat" fileid="%s" elapsedTimems="%.1f" res="%s"' % (fileid, (tend-tstart)*1000, statInfo))
    if statInfo.status.code == cs3code.CODE_OK:
      return {
          'inode': statInfo.info.id.storage_id + ':' + statInfo.info.id.opaque_id,
          'filepath': statInfo.info.path,
          'userid': '0000',  # TODO not yet available
          'size': statInfo.info.size,
          'mtime': statInfo.info.mtime
          }
    raise IOError(statInfo.status.message)
  except Exception as e:
    raise IOError(e)


def statx(endpoint, fileid, userid):
  '''Get extended stat info (inode, filepath, userid, size, mtime). Equivalent to stat.'''
  return stat(endpoint, fileid, userid)


def setxattr(_endpoint, filepath, userid, key, value):
  '''Set the extended attribute <key> to <value> using the given userid as access token'''
  # TODO implement this on the reva side (now reva returns operation not supported)
  reference = spr.Reference(path='example.txt', id=spr.ResourceId(
    storage_id='123e4567-e89b-12d3-a456-426655440000', opaque_id='fileid-home/example.txt'))
  arbitrary_metadata = spr.ArbitraryMetadata()
  arbitrary_metadata.metadata.update({key: value})
  req = sp.SetArbitraryMetadataRequest(
    ref=reference, arbitrary_metadata=arbitrary_metadata)
  try:
    credentials['cs3stub'].SetArbitraryMetadata(
        request=req, metadata=[('x-access-token', credentials['token'])])
    # TODO check for error
  except Exception as e:
    raise IOError(e)


def getxattr(_endpoint, filepath, userid, key):
  '''Get the extended attribute <key> using the given userid as access token. Do not raise exceptions'''
  try:
    tstart = time.clock()
    reference = spr.Reference(path='example.txt', id=spr.ResourceId(
        storage_id='123e4567-e89b-12d3-a456-426655440000', opaque_id='fileid-home/example.txt'))
    statInfo = credentials['cs3stub'].Stat(request=sp.StatRequest(ref=reference),
                                           metadata=[('x-access-token', credentials['token'])])
    tend = time.clock()
    print('msg="Invoked stat for getxattr" filepath="%s" elapsedTimems="%.1f"' % (filepath, (tend-tstart)*1000))
    try:
      return statInfo.info.arbitrary_metadata[key]
    except KeyError:
      log.warning('msg="Key not found in getxattr" filepath="%s" key="%s"' % (filepath, key))
  except Exception as e:
    log.warning('msg="Failed to getxattr" filepath="%s" key="%s" exception="%s"' % (filepath, key, e))
  return None


def rmxattr(_endpoint, filepath, userid, key):
  '''Remove the extended attribute <key> using the given userid as access token'''
  # TODO implement this on the reva side (now reva returns operation not supported)
  reference = spr.Reference(path='example.txt', id=spr.ResourceId(
    storage_id='123e4567-e89b-12d3-a456-426655440000', opaque_id='fileid-home/example.txt'))
  req = sp.UnsetArbitraryMetadataRequest(
    ref=reference, arbitrary_metadata_keys=[key])
  try:
    credentials['cs3stub'].UnsetArbitraryMetadata(
        request=req, metadata=[('x-access-token', credentials['token'])])
    # TODO check for error
  except Exception as e:
    raise IOError(e)


def readfile(_endpoint, filepath, userid):
  '''Read a file using the given userid as access token. Note that the function is a generator, managed by Flask.'''
  print('msg="Invoking readFile" filepath="%s"' % filepath)
  try:
    chunksize = 2  # config.getint('io', 'chunksize')
    reference = spr.Reference(path=filepath)
    req = sp.InitiateFileDownloadRequest(ref=reference)
    initiatefiledownloadres = credentials['cs3stub'].InitiateFileDownload(
      request=req, metadata=[('x-access-token', credentials['token'])])

    # Download
    print("initiatefiledownloadres.token: " + initiatefiledownloadres.token) 
    url = initiatefiledownloadres.download_endpoint
    headers = {'X-Reva-Transfer': initiatefiledownloadres.token,
                'Authorization': 'Basic ZWluc3RlaW46cmVsYXRpdml0eQ=='}
    fileinformation = requests.get(url=url, headers=headers)

    data = fileinformation.content
    for i in range(0, len(data), chunksize):
      yield data[i:i+chunksize]
  except Exception as e:
    print('msg="Error when reading file" filepath="%s" error="%s"' % (filepath))
    raise IOError(e)



def writefile(_endpoint, filepath, userid, content, noversion=0):
  '''Write a file using the given userid as access token. The entire content is written
    and any pre-existing file is deleted (or moved to the previous version if supported).
    If noversion=1, the write explicitly disables versioning: this is useful for lock files.'''
  # size = len(content)
  # print('msg="Invoking writeFile" filepath="%s" size="%d"' %
  #           (filepath, size))
  try:
    tstart = time.clock()
    tend = time.clock()
    print('msg="File open for write" filepath="%s" elapsedTimems="%.1f"' % (filepath, (tend-tstart)*1000))
    # write the file. In a future implementation, we should find a way to only update the required chunks...

    tstart = time.clock()
    reference = spr.Reference(path = filepath)

    req = sp.InitiateFileUploadRequest(ref = reference)
    res1 = credentials['cs3stub'].InitiateFileUpload(request = req, metadata = [('x-access-token', credentials['token'])])
    print("--------------")
    print("upload ep" + res1.upload_endpoint)
    print("token" + res1.token) #This token is generally empty
    metadata = {
      "filepath": filepath,
      "dir":      "/home"
    }
    headers = {
      'Upload-Length': '24',
      'Tus-Resumable': '1.0.0',
      'Upload-Metadata': 'filename L2hvbWUvZXhhbXBsZUEudHh0,dir L2hvbWU=',
      'Location': res1.upload_endpoint,
      #'X-Reva-Transfer': res1.token, #Not used since empty
      'Content-Type':'application/offset+octet-stream',
      'x-access-token': credentials['token'],
      'Authorization': 'Basic ZWluc3RlaW46cmVsYXRpdml0eQ=='}
    
    my_client = tusclient.TusClient(res1.upload_endpoint, headers=headers)
    myfiles = {'file': open('src/example.txt' ,'rb')}

    
    res = requests.post(url=res1.upload_endpoint, files=myfiles, headers=headers, data=metadata)
    print(res.text)
    # uploader = my_client.uploader(file_path='src/example.txt', chunk_size=20000000, metadata=metadata, client=my_client)
    # print("res1.text" + res1.upload_endpoint)
    # uploader.upload_chunk()
    # # url = uploader.create_url()
    # uploader.upload()
    # request_tus = tusRequest(uploader)
    tend = time.clock()
    print('msg="File open for write" filepath="%s" elapsedTimems="%.1f"' % (
        filepath, (tend-tstart)*1000))
    # if res.status.code != 1:
    #     raise IOError('Something went wrong, message: ' + res.status.message)
  except OSError as e:
    print('msg="Error writing to file" filepath="%s" error="%s"' % (filepath, e))
    raise IOError(e)


def renamefile(_endpoint, filepath, newfilepath, userid):
  '''Rename a file from origfilepath to newfilepath using the given userid as access token.'''
  source = spr.Reference(path=filepath)
  destination = spr.Reference(path=newfilepath)
  req = sp.MoveRequest(source=source, destination=destination)
  try:
    credentials['cs3stub'].Move(request=req, metadata=[('x-access-token', credentials['token'])])
  except Exception as e:
    raise IOError(e)


def removefile(_endpoint, filepath, userid, _force=0):
  '''Remove a file using the given userid as access token.
    The force argument is irrelevant and ignored for local storage.'''
  reference = spr.Reference(path=filepath)
  req = sp.DeleteRequest(ref=reference)
  try:
    credentials['cs3stub'].Delete(request=req, metadata=[('x-access-token', credentials['token'])])
  except Exception as e:
    raise IOError(e)
