#!/bin/python
#
# xrootiface.py
#
# XRootD interface for the WOPI server for CERNBox
#
# Giuseppe.LoPresti@cern.ch

from XRootD import client as XrdClient      # the xroot bindings for python, xrootd-python-4.4.x.el7.x86_64.rpm
from XRootD.client.flags import OpenFlags, QueryCode

# module-wide state
config = None
log = None
storageserver = None
xrdfs = None

def _eosargs(ruid, rgid, atomicwrite=0):
  '''One-liner to generate extra EOS-specific arguments for the xroot URL'''
  return '?eos.ruid=' + ruid + '&eos.rgid=' + rgid + ('&eos.atomic=1' if atomicwrite else '')

def _xrootcmd(cmd, subcmd, ruid, rgid, args):
  '''Perform the <cmd>/<subcmd> action on the special /proc/user path on behalf of the given uid,gid'''
  log.debug('msg="Invoking _xrootcmd" cmd="%s" subcmd="%s" args="%s"' % (cmd, subcmd, args))
  if not xrdfs:
    raise ValueError
  with XrdClient.File() as f:
    rc, _statInfo_unused = f.open(storageserver + '//proc/user/' + _eosargs(ruid, rgid) + '&mgm.cmd=' + cmd + \
                                  ('&mgm.subcmd=' + subcmd if subcmd else '') + '&' + args, OpenFlags.READ)
    res = f.readline().strip('\n').split('&')
    if len(res) == 3:    # we may only just get stdout: in that case, assume it's all OK
      rc = res[2]
      rc = rc[rc.find('=')+1:]
      if rc != '0':
        # failure: get info from stderr, log and raise
        msg = res[1][res[1].find('=')+1:]
        log.warning('msg="Error with xroot command" cmd="%s" subcmd="%s" args="%s" error="%s" rc="%s"' % (cmd, subcmd, args, msg, rc))
        raise IOError(msg)
  # all right, return everything that came in stdout
  return res[0][res[0].find('stdout=')+7:]


def init(inConfig, inLog):
  '''Init module-level variables'''
  global config
  global log
  global storageserver
  global xrdfs
  config = inConfig
  log = inLog
  storageserver = config.get('general', 'storageserver')
  # prepare the xroot client
  xrdfs = XrdClient.FileSystem(storageserver)

def stat(filename, ruid, rgid):
  '''Stat a file via xroot on behalf of the given uid,gid. Not actually used but included for completeness.'''
  log.debug('msg="Invoking stat" filename="%s"' % filename)
  if not xrdfs:
    raise ValueError
  rc, statInfo = xrdfs.stat(filename + _eosargs(ruid, rgid))
  if statInfo is None:
    raise IOError(rc.message.strip('\n'))
  return statInfo

def statx(filename, ruid, rgid):
  '''Get extended stat info via an xroot opaque query on behalf of the given uid,gid'''
  log.debug('msg="Invoking statx" filename="%s"' % filename)
  if not xrdfs:
    raise ValueError
  rc, rawinfo = xrdfs.query(QueryCode.OPAQUEFILE, filename + _eosargs(ruid, rgid) + '&mgm.pcmd=stat')
  if rawinfo is None:
    raise IOError(rc.message.strip('\n'))
  return rawinfo.split()

def setXAttr(filename, ruid, rgid, key, value):
  '''Set the extended attribute <key> to <value> via a special open on behalf of the given uid,gid'''
  _xrootcmd('attr', 'set', ruid, rgid, 'mgm.attr.key=' + key + '&mgm.attr.value=' + str(value) + '&mgm.path=' + filename)

def getXAttr(filename, ruid, rgid, key):
  '''Get the extended attribute <key> via a special open on behalf of the given uid,gid'''
  res = _xrootcmd('attr', 'get', ruid, rgid, 'mgm.attr.key=' + key + '&mgm.path=' + filename)
  # if no error, the response comes in the format <key>="<value>"
  return res.split('"')[1]

def rmXAttr(filename, ruid, rgid, key):
  '''Remove the extended attribute <key> via a special open on behalf of the given uid,gid'''
  _xrootcmd('attr', 'rm', ruid, rgid, 'mgm.attr.key=' + key + '&mgm.path=' + filename)

def readFile(filename, ruid, rgid):
  '''Read a file via xroot on behalf of the given uid,gid. Note that the function is a generator, managed by Flask.'''
  log.debug('msg="Invoking readFile" filename="%s"' % filename)
  if not xrdfs:
    raise ValueError
  with XrdClient.File() as f:
    rc, _statInfo_unused = f.open(storageserver + '/' + filename + _eosargs(ruid, rgid), OpenFlags.READ)
    if not rc.ok:
      # the file could not be opened: as this is a generator, we yield the error string instead of the file's contents
      log.warning('msg="Error opening the file for read" filename="%s" error="%s"' % (filename, rc.message.strip('\n')))
      yield rc.message
    else:
      # the actual read is buffered and managed by the Flask server
      for chunk in f.readchunks(offset=0, chunksize=config.getint('io', 'chunksize')):
        yield chunk

def writeFile(filename, ruid, rgid, content):
  '''Write a file via xroot on behalf of the given uid,gid. The entire content is written and any pre-existing file is deleted.'''
  log.debug('msg="Invoking writeFile filename="%s"' % filename)
  if not xrdfs:
    raise ValueError
  f = XrdClient.File()
  rc, _statInfo_unused = f.open(storageserver + '/' + filename + _eosargs(ruid, rgid, 1), OpenFlags.DELETE)
  if not rc.ok:
    log.info('msg="Error opening the file for write" filename="%s" error="%s"' % (filename, rc.message.strip('\n')))
    raise IOError(rc.message.strip('\n'))
  # write the file. In a future implementation, we should find a way to only update the required chunks...
  rc, _statInfo_unused = f.write(content, offset=0)
  if not rc.ok:
    log.warning('msg="Error writing the file" filename="%s" error="%s"' % (filename, rc.message.strip('\n')))
    raise IOError(rc.message.strip('\n'))
  rc, _statInfo_unused = f.close()
  if not rc.ok:
    log.warning('msg="Error closing the file" filename="%s" error="%s"' % (filename, rc.message.strip('\n')))
    raise IOError(rc.message.strip('\n'))

def renameFile(origFilename, newFilename, ruid, rgid):
  '''Rename a file via a special open from origFilename to newFilename on behalf of the given uid,gid.'''
  _xrootcmd('file', 'rename', ruid, rgid, '&mgm.path=' + origFilename + '&mgm.file.target=' + newFilename)

def removeFile(filename, ruid, rgid):
  '''Remove a file via a special open on behalf of the given uid,gid.'''
  _xrootcmd('rm', None, ruid, rgid, '&mgm.path=' + filename)
