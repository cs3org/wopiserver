#!/bin/python
#
# xrootiface.py
#
# XRootD interface for the WOPI server for CERNBox
#
# Giuseppe.LoPresti@cern.ch

import sys, os, time
import logging
from XRootD import client as XrdClient   # the xroot bindings for python, xrootd-python-4.4.x.el7.x86_64.rpm
from XRootD.client.flags import OpenFlags

class XrdCl:
  global config

  def __init__(self, log, filename):
    self.log = log
    self.filename = filename
    # prepare the xroot client
    self.storageserver = config.get('general', 'storageserver')
    self.homedir = '/castor/cern.ch/user/i/itglp/'    # XXX temporary - to be discussed
    self.xrdfs = XrdClient.FileSystem(self.storageserver)  
    self.chunksize = config.getint('io', 'chunksize')

  def stat(self):
    rc, statInfo = self.xrdfs.stat(self.homedir + self.filename)
    if statInfo is None:
      raise IOError(rc.message.strip('\n'))
    return statInfo

  def readFile(self):
    with XrdClient.File() as f:
      rc, _statInfo_unused = f.open(self.storageserver + '/' + self.homedir + self.filename, OpenFlags.READ)
      if not rc.ok:
        # the file could not be opened: as this is a generator, we yield the error string instead of the file's contents
        self.log.info('msg="Error opening the file for read" filename="%s" error="%s"' % (self.filename, rc.message.strip('\n')))
        yield rc.message
      else:
        # the actual read is buffered and managed by the Flask server
        for chunk in f.readchunks(offset=0, chunksize=self.chunksize):
          yield chunk

  def writeFile(self, content):
    f = XrdClient.File()
    # XXX todo pass in the URL a special flag to enable the EOS atomic overwrite like for the OwnCloud server
    rc, _statInfo_unused = f.open(self.storageserver + '/' + self.homedir + self.filename, OpenFlags.DELETE)
    if not rc.ok:
      self.log.info('msg="Error opening the file for write" filename="%s" error="%s"' % (self.filename, rc.message.strip('\n')))
      raise IOError(rc.message.strip('\n'))
    # write the file. In a future implementation, we should find a way to only update the required chunks...
    rc, _statInfo_unused = f.write(content, offset=0)
    if not rc.ok:
      self.log.info('msg="Error writing the file" filename="%s" error="%s"' % (self.filename, rc.message.strip('\n')))
      raise IOError(rc.message.strip('\n'))
    rc, _statInfo_unused = f.close()
    if not rc.ok:
      self.log.info('msg="Error closing the file" filename="%s" error="%s"' % (self.filename, rc.message.strip('\n')))
      raise IOError(rc.message.strip('\n'))

