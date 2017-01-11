#!/bin/python
#
# xrootiface.py
#
# XRootD interface for the WOPI server for CERNBox
#
# Giuseppe.LoPresti@cern.ch

import sys, os, time
import logging
from XRootD import client as XrdClient      # the xroot bindings for python, xrootd-python-4.4.x.el7.x86_64.rpm
from XRootD.client.flags import OpenFlags

# module-wide state
config = None
log = None
storageserver = None
xrdfs = None

def _eosargs(ruid, rgid, atomicwrite=0):
  '''One-liner to generate extra EOS-specific arguments for the xroot URL'''
  return '?eos.ruid=' + ruid + '&eos.rgid=' + rgid + ('&eos.atomicwrite=1' if atomicwrite else '')

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
  '''Stat a file via xroot on behalf of the given uid,gid'''
  if not xrdfs:
    raise ValueError
  rc, statInfo = xrdfs.stat(filename + _eosargs(ruid, rgid))
  # XXX todo get the etag for later
  if statInfo is None:
    raise IOError(rc.message.strip('\n'))
  return statInfo

def readFile(filename, ruid, rgid):
  '''Read a file via xroot on behalf of the given uid,gid. Note that the function is a generator, managed by Flask.'''
  if not xrdfs:
    raise ValueError
  with XrdClient.File() as f:
    rc, _statInfo_unused = f.open(storageserver + '/' + filename + _eosargs(ruid, rgid), OpenFlags.READ)
    if not rc.ok:
      # the file could not be opened: as this is a generator, we yield the error string instead of the file's contents
      log.info('msg="Error opening the file for read" filename="%s" error="%s"' % (filename, rc.message.strip('\n')))
      yield rc.message
    else:
      # the actual read is buffered and managed by the Flask server
      for chunk in f.readchunks(offset=0, chunksize=config.getint('io', 'chunksize')):
        yield chunk

def writeFile(filename, ruid, rgid, content):
  '''Write a file via xroot on behalf of the given uid,gid. The entire content is written and any pre-existing file is deleted.'''
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
    log.info('msg="Error writing the file" filename="%s" error="%s"' % (filename, rc.message.strip('\n')))
    raise IOError(rc.message.strip('\n'))
  rc, _statInfo_unused = f.close()
  if not rc.ok:
    log.info('msg="Error closing the file" filename="%s" error="%s"' % (filename, rc.message.strip('\n')))
    raise IOError(rc.message.strip('\n'))
