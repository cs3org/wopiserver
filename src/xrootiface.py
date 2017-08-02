'''
xrootiface.py

XRootD interface for the WOPI server for CERNBox

<<<<<<< HEAD
Author: Giuseppe.LoPresti@cern.ch
CERN/IT-ST

Modified by michael.dsilva@aarnet.edu.au
=======
Author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
Contributions: Michael.DSilva@aarnet.edu.au
>>>>>>> pr/1
'''

from XRootD import client as XrdClient      # the xroot bindings for python, xrootd-python-4.4.x.el7.x86_64.rpm
from XRootD.client.flags import OpenFlags, QueryCode

# module-wide state
config = None
log = None
storageserver = None
xrdfs = None
homepath = None

def _eosargs(ruid, rgid, atomicwrite=0, bookingsize=0):
  '''One-liner to generate extra EOS-specific arguments for the xroot URL'''
<<<<<<< HEAD
  #return '?eos.ruid=' + ruid + '&eos.rgid=' + rgid + ('&eos.atomic=1' if atomicwrite else '') + '&eos.app=wopi'
  return '?eos.ruid=' + ruid + '&eos.rgid=' + rgid + ('&eos.atomic=1' if atomicwrite else '') + (('&eos.bookingsize='+str(bookingsize)) if bookingsize else '') + '&eos.app=wopi'
=======
  return '?eos.ruid=' + ruid + '&eos.rgid=' + rgid + ('&eos.atomic=1' if atomicwrite else '') + \
          (('&eos.bookingsize='+str(bookingsize)) if bookingsize else '') + '&eos.app=wopi'
>>>>>>> pr/1

def _xrootcmd(cmd, subcmd, ruid, rgid, args):
  '''Perform the <cmd>/<subcmd> action on the special /proc/user path on behalf of the given uid,gid.
     Note that this is entirely EOS-specific.'''
  if not xrdfs:
    raise ValueError
  with XrdClient.File() as f:
    url = storageserver + '//proc/user/' + _eosargs(ruid, rgid) + '&mgm.cmd=' + cmd + \
          ('&mgm.subcmd=' + subcmd if subcmd else '') + '&' + args
    log.debug('msg="Invoking _xrootcmd" cmd="%s%s" url="%s"' % (cmd, ('/' + subcmd if subcmd else ''), url))
    rc, statInfo_unused = f.open(url, OpenFlags.READ)
    res = f.readline().strip('\n').split('&')
    if len(res) == 3:    # we may only just get stdout: in that case, assume it's all OK
      rc = res[2]
      rc = rc[rc.find('=')+1:]
      if rc != '0':
        # failure: get info from stderr, log and raise
        msg = res[1][res[1].find('=')+1:]
        log.info('msg="Error with xroot command" cmd="%s" subcmd="%s" args="%s" error="%s" rc="%s"' % \
                 (cmd, subcmd, args, msg, rc.strip('\00')))
        raise IOError(msg)
  # all right, return everything that came in stdout
  return res[0][res[0].find('stdout=')+7:]

<<<<<<< HEAD
#build path
def getFilename(filename):
=======
def _getfilename(filename):
  '''map the given filename into the target namespace by prepending the homepath (see storagehomepath in wopiserver.conf)'''
>>>>>>> pr/1
  return '/' + homepath + filename

def init(inconfig, inlog):
  '''Init module-level variables'''
  global config
  global log
  global storageserver
  global xrdfs
  global homepath
  config = inconfig
  log = inlog
  storageserver = config.get('general', 'storageserver')
  homepath = config.get('general', 'storagehomepath')
  # prepare the xroot client
  xrdfs = XrdClient.FileSystem(storageserver)
  storageserver = 'root://' + storageserver

def stat(filename, ruid, rgid):
  filename = getFilename(filename)
  '''Stat a file via xroot on behalf of the given uid,gid. Uses the default xroot API.'''
  filename = _getfilename(filename)
  log.debug('msg="Invoking stat" filename="%s"' % filename)
  if not xrdfs:
    raise ValueError
  rc, statInfo = xrdfs.stat(filename + _eosargs(ruid, rgid))
  if statInfo is None:
    raise IOError(rc.message.strip('\n'))
  return statInfo

def statx(filename, ruid, rgid):
  filename = getFilename(filename)
  '''Get extended stat info via an xroot opaque query on behalf of the given uid,gid'''
  filename = _getfilename(filename)
  log.debug('msg="Invoking statx" filename="%s"' % filename)
  if not xrdfs:
    raise ValueError
  rc, rawinfo = xrdfs.query(QueryCode.OPAQUEFILE, filename + _eosargs(ruid, rgid) + '&mgm.pcmd=stat')
  if str(rc).find('[SUCCESS]') == -1:
    raise IOError(str(rc).strip('\n'))
  if rawinfo.find('retc=') > 0:
    raise IOError(rawinfo.strip('\n'))
  return rawinfo.split()

def setxattr(filename, ruid, rgid, key, value):
  '''Set the extended attribute <key> to <value> via a special open on behalf of the given uid,gid'''
<<<<<<< HEAD
  filename = getFilename(filename)
  _xrootcmd('attr', 'set', ruid, rgid, 'mgm.attr.key=' + key + '&mgm.attr.value=' + str(value) + '&mgm.path=' + filename)

def getxattr(filename, ruid, rgid, key):
  '''Get the extended attribute <key> via a special open on behalf of the given uid,gid'''
  filename = getFilename(filename)
  res = _xrootcmd('attr', 'get', ruid, rgid, 'mgm.attr.key=' + key + '&mgm.path=' + filename)
=======
  _xrootcmd('attr', 'set', ruid, rgid, 'mgm.attr.key=' + key + '&mgm.attr.value=' + str(value) + '&mgm.path=' + _getfilename(filename))

def getxattr(filename, ruid, rgid, key):
  '''Get the extended attribute <key> via a special open on behalf of the given uid,gid'''
  res = _xrootcmd('attr', 'get', ruid, rgid, 'mgm.attr.key=' + key + '&mgm.path=' + _getfilename(filename))
>>>>>>> pr/1
  # if no error, the response comes in the format <key>="<value>"
  return res.split('"')[1]

def rmxattr(filename, ruid, rgid, key):
  '''Remove the extended attribute <key> via a special open on behalf of the given uid,gid'''
<<<<<<< HEAD
  filename = getFilename(filename) 
=======
  filename = _getfilename(filename)
>>>>>>> pr/1
  _xrootcmd('attr', 'rm', ruid, rgid, 'mgm.attr.key=' + key + '&mgm.path=' + filename)

def readfile(filename, ruid, rgid):
  '''Read a file via xroot on behalf of the given uid,gid. Note that the function is a generator, managed by Flask.'''
  log.debug('msg="Invoking readFile" filename="%s"' % filename)
  if not xrdfs:
    raise ValueError
  with XrdClient.File() as f:
<<<<<<< HEAD
    fileurl = storageserver + '/' + homepath + filename + _eosargs(ruid, rgid) 
=======
    fileurl = storageserver + '/' + homepath + filename + _eosargs(ruid, rgid)
>>>>>>> pr/1
    rc, statInfo_unused = f.open(fileurl, OpenFlags.READ)
    if not rc.ok:
      # the file could not be opened: as this is a generator, we yield the error string instead of the file's contents
      log.warning('msg="Error opening the file for read" filename="%s" error="%s"' % (fileurl, rc.message.strip('\n')))
      yield rc.message
    else:
      chunksize = config.getint('io', 'chunksize')
<<<<<<< HEAD
      rc, stat = f.stat() 
      chunksize = min(chunksize, stat.size-1)
=======
      rc, statInfo = f.stat()
      chunksize = min(chunksize, statInfo.size-1)
>>>>>>> pr/1
      # the actual read is buffered and managed by the Flask server
      for chunk in f.readchunks(offset=0, chunksize=chunksize):
        yield chunk

def writefile(filename, ruid, rgid, content):
  '''Write a file via xroot on behalf of the given uid,gid. The entire content is written
     and any pre-existing file is deleted.'''
  log.debug('msg="Invoking writeFile" filename="%s"' % filename)
  size = len(content)
  log.debug('msg="Invoking writeFile" filename="%s" size="%d"' % (filename, size))
  if not xrdfs:
    raise ValueError
  f = XrdClient.File()
  rc, statInfo_unused = f.open(storageserver + '/' + homepath + filename + _eosargs(ruid, rgid, 1, size), OpenFlags.DELETE)
  if not rc.ok:
    log.info('msg="Error opening the file for write" filename="%s" error="%s"' % (filename, rc.message.strip('\n')))
    raise IOError(rc.message.strip('\n'))
  # write the file. In a future implementation, we should find a way to only update the required chunks...
  rc, statInfo_unused = f.write(content, offset=0, size=size)
  if not rc.ok:
    log.warning('msg="Error writing the file" filename="%s" error="%s"' % (filename, rc.message.strip('\n')))
    raise IOError(rc.message.strip('\n'))
  rc, statInfo_unused = f.truncate(size)
  if not rc.ok:
    log.warning('msg="Error truncing the file" filename="%s" error="%s"' % (filename, rc.message.strip('\n')))
    raise IOError(rc.message.strip('\n'))
  rc, statInfo_unused = f.close()
  if not rc.ok:
    log.warning('msg="Error closing the file" filename="%s" error="%s"' % (filename, rc.message.strip('\n')))
    raise IOError(rc.message.strip('\n'))

def renamefile(origfilename, newfilename, ruid, rgid):
  '''Rename a file via a special open from origfilename to newfilename on behalf of the given uid,gid.'''
<<<<<<< HEAD
  filename = getFilename(filename) 
  _xrootcmd('file', 'rename', ruid, rgid, 'mgm.path=' + origfilename + '&mgm.file.source=' + origfilename + '&mgm.file.target=' + newfilename)

def removefile(filename, ruid, rgid):
  '''Remove a file via a special open on behalf of the given uid,gid.'''
  filename = getFilename(filename) 
  _xrootcmd('rm', None, ruid, rgid, 'mgm.path=' + filename)

=======
  _xrootcmd('file', 'rename', ruid, rgid, 'mgm.path=' + _getfilename(origfilename) + \
            '&mgm.file.source=' + _getfilename(origfilename) + '&mgm.file.target=' + _getfilename(newfilename))

def removefile(filename, ruid, rgid):
  '''Remove a file via a special open on behalf of the given uid,gid.'''
  _xrootcmd('rm', None, ruid, rgid, 'mgm.path=' + _getfilename(filename))
>>>>>>> pr/1
