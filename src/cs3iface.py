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

import cs3.gateway.v1beta1.gateway_api_pb2 as cs3gw
import cs3.gateway.v1beta1.gateway_api_pb2_grpc as cs3gw_grpc

# module-wide state
config = None
log = None
tok = None

def _getfilename(filename):
  '''map the given filename into the target namespace by prepending the homepath (see storagehomepath in wopiserver.conf)'''
  return filename   # TODO do we need that??

def init(inconfig, inlog):
  '''Init module-level variables'''
  global config         # pylint: disable=global-statement
  global log            # pylint: disable=global-statement
  global tok            # pylint: disable=global-statement
  config = inconfig
  log = inlog
  #revaurl = config.get('cs3', 'revaurl')
  revaurl = 'iota:19000' # XXX for now

  # prepare the gRPC connection
  ch = grpc.insecure_channel(revaurl)
  cs3stub = cs3gw_grpc.GatewayAPIStub(ch)
  authReq = cs3gw.AuthenticateRequest(type='basic', client_id='gonzalhu', client_secret='test')
  tok = cs3stub.Authenticate(authReq)


def stat(_endpoint, filename, _ruid, _rgid):
  '''Stat a file and returns (size, mtime) as well as other extended info. Assume the given uid, gid has access.'''
  filename = _getfilename(filename)
  try:
    tstart = time.clock()
    statInfo = os.stat(filename)
    tend = time.clock()
    log.info('msg="Invoked stat" filename="%s" elapsedTimems="%.1f"' % (filename, (tend-tstart)*1000))
    return {
        'inode': statInfo.st_ino,
        'ouid': statInfo.st_uid,
        'ogid': statInfo.st_gid,
        'size': statInfo.st_size,
        'mtime': statInfo.st_mtime
        }
  except (FileNotFoundError, PermissionError) as e:
    raise IOError(e)

def statx(_endpoint, filename, _ruid, _rgid):
  '''Get extended stat info (inode, ouid, ogid, size, mtime). Equivalent to stat in the case of local storage.'''
  return stat(_endpoint, filename, _ruid, _rgid)

def setxattr(_endpoint, filename, _ruid, _rgid, key, value):
  '''Set the extended attribute <key> to <value> on behalf of the given uid, gid'''
  try:
    os.setxattr(_getfilename(filename), key, str(value))
  except (FileNotFoundError, PermissionError) as e:
    raise IOError(e)

def getxattr(_endpoint, filename, _ruid, _rgid, key):
  '''Get the extended attribute <key> on behalf of the given uid, gid. Do not raise exceptions'''
  try:
    return os.getxattr(_getfilename(filename), key)
  except (FileNotFoundError, PermissionError) as e:
    log.warning('msg="Failed to getxattr" filename="%s" key="%s" exception="%s"' % (filename, key, e))
    return None

def rmxattr(_endpoint, filename, _ruid, _rgid, key):
  '''Remove the extended attribute <key> on behalf of the given uid, gid'''
  try:
    os.removexattr(_getfilename(filename), key)
  except (FileNotFoundError, PermissionError) as e:
    raise IOError(e)

def readfile(_endpoint, filename, _ruid, _rgid):
  '''Read a file on behalf of the given uid, gid. Note that the function is a generator, managed by Flask.'''
  log.debug('msg="Invoking readFile" filename="%s"' % filename)
  try:
    tstart = time.clock()
    chunksize = config.getint('io', 'chunksize')
    f = open(_getfilename(filename), mode='rb', buffering=chunksize)
    tend = time.clock()
    log.info('msg="File open for read" filename="%s" elapsedTimems="%.1f"' % (filename, (tend-tstart)*1000))
    # the actual read is buffered and managed by the Flask server
    for chunk in iter(lambda: f.read(chunksize), b''):
      yield chunk
  except FileNotFoundError as e:
    # log this case as info to keep the logs cleaner
    log.info('msg="File not found on read" filename="%s"' % filename)
    # as this is a generator, we yield the error string instead of the file's contents
    yield 'ERROR on read'
    yield 'No such file or directory'
  except OSError as e:
    # general case, issue a warning
    log.warning('msg="Error opening the file for read" filename="%s" error="%s"' % (filename, e))
    yield 'ERROR on read'
    yield str(e)

def writefile(_endpoint, filename, ruid, rgid, content, noversion=0):
  '''Write a file via xroot on behalf of the given uid, gid. The entire content is written
     and any pre-existing file is deleted (or moved to the previous version if supported).
     If noversion=1, the write explicitly disables versioning: this is useful for lock files.'''
  size = len(content)
  log.debug('msg="Invoking writeFile" filename="%s" size="%d"' % (filename, size))
  try:
    tstart = time.clock()
    f = open(_getfilename(filename), mode='wb')
    tend = time.clock()
    log.info('msg="File open for write" filename="%s" elapsedTimems="%.1f"' % (filename, (tend-tstart)*1000))
    # write the file. In a future implementation, we should find a way to only update the required chunks...
    written = f.write(content)
    f.close()
    if written != size:
      raise IOError('Written %d bytes but content is %d bytes' % (written, size))
  except OSError as e:
    log.warning('msg="Error writing to file" filename="%s" error="%s"' % (filename, e))
    raise IOError(e)

def renamefile(_endpoint, origfilename, newfilename, ruid, rgid):
  '''Rename a file from origfilename to newfilename on behalf of the given uid, gid.'''
  try:
    os.rename(_getfilename(origfilename), _getfilename(newfilename))
  except (FileNotFoundError, PermissionError) as e:
    raise IOError(e)

def removefile(_endpoint, filename, _ruid, _rgid, _force=0):
  '''Remove a file on behalf of the given uid, gid.
     The force argument is irrelevant and ignored for local storage.'''
  try:
    os.remove(_getfilename(filename))
  except (FileNotFoundError, PermissionError, IsADirectoryError) as e:
    raise IOError(e)
