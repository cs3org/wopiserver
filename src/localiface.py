'''
localiface.py

Local storage interface for the IOP WOPI server

Author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

import time
import os
from stat import S_ISDIR
import sys
import traceback


# module-wide state
config = None
log = None
homepath = None


def _getfilepath(filepath):
  '''map the given filepath into the target namespace by prepending the homepath (see storagehomepath in wopiserver.conf)'''
  return os.path.normpath(homepath + os.sep + filepath)


def init(inconfig, inlog):
  '''Init module-level variables'''
  global config         # pylint: disable=global-statement
  global log            # pylint: disable=global-statement
  global homepath       # pylint: disable=global-statement
  config = inconfig
  log = inlog
  homepath = config.get('local', 'storagehomepath')
  try:
    # validate the given storagehomepath folder
    mode = os.stat(homepath).st_mode
    if not S_ISDIR(mode):
      raise IOError('Not a directory')
  except IOError as e:
    raise IOError('Could not stat storagehomepath folder %s: %s' % (homepath, e))


def stat(_endpoint, filepath, _userid):
  '''Stat a file and returns (size, mtime) as well as other extended info. This method assumes that the given userid has access.'''
  try:
    tstart = time.time()
    statInfo = os.stat(_getfilepath(filepath))
    tend = time.time()
    log.info('msg="Invoked stat" filepath="%s" elapsedTimems="%.1f"' % (_getfilepath(filepath), (tend-tstart)*1000))
    return {
        'inode': str(statInfo.st_ino),
        'filepath': filepath,
        'userid': str(statInfo.st_uid) + ':' + str(statInfo.st_gid),
        'size': statInfo.st_size,
        'mtime': statInfo.st_mtime
        }
  except (FileNotFoundError, PermissionError) as e:
    raise IOError(e)


def statx(endpoint, filepath, userid, versioninv=1):    # pylint: disable=unused-argument
  '''Get extended stat info (inode, filepath, userid, size, mtime). Equivalent to stat in the case of local storage.
  The versioninv flag is ignored as local storage always supports version-invariant inodes (cf. CERNBOX-1216).'''
  return stat(endpoint, filepath, userid)


def setxattr(_endpoint, filepath, _userid, key, value):
  '''Set the extended attribute <key> to <value> on behalf of the given userid'''
  try:
    os.setxattr(_getfilepath(filepath), 'user.' + key, str(value).encode())
  except (FileNotFoundError, PermissionError, OSError) as e:
    log.warning('msg="Failed to setxattr" filepath="%s" key="%s" exception="%s"' % (filepath, key, e))
    raise IOError(e)


def getxattr(_endpoint, filepath, _userid, key):
  '''Get the extended attribute <key> on behalf of the given userid. Do not raise exceptions'''
  try:
    filepath = _getfilepath(filepath)
    return os.getxattr(filepath, 'user.' + key).decode('UTF-8')
  except (FileNotFoundError, PermissionError, OSError) as e:
    log.warning('msg="Failed to getxattr" filepath="%s" key="%s" exception="%s"' % (filepath, key, e))
    return None


def rmxattr(_endpoint, filepath, _userid, key):
  '''Remove the extended attribute <key> on behalf of the given userid'''
  try:
    os.removexattr(_getfilepath(filepath), 'user.' + key)
  except (FileNotFoundError, PermissionError, OSError) as e:
    log.warning('msg="Failed to rmxattr" filepath="%s" key="%s" exception="%s"' % (filepath, key, e))
    raise IOError(e)


def readfile(_endpoint, filepath, _userid):
  '''Read a file on behalf of the given userid. Note that the function is a generator, managed by Flask.'''
  log.debug('msg="Invoking readFile" filepath="%s"' % filepath)
  try:
    tstart = time.time()
    filepath = _getfilepath(filepath)
    chunksize = config.getint('io', 'chunksize')
    with open(filepath, mode='rb', buffering=chunksize) as f:
      tend = time.time()
      log.info('msg="File open for read" filepath="%s" elapsedTimems="%.1f"' % (filepath, (tend-tstart)*1000))
      # the actual read is buffered and managed by the Flask server
      for chunk in iter(lambda: f.read(chunksize), b''):
        yield chunk
  except FileNotFoundError as e:
    # log this case as info to keep the logs cleaner
    log.info('msg="File not found on read" filepath="%s"' % filepath)
    # as this is a generator, we yield the error string instead of the file's contents
    yield IOError('No such file or directory')
  except OSError as e:
    # general case, issue a warning
    log.warning('msg="Error opening the file for read" filepath="%s" error="%s"' % (filepath, e))
    yield IOError(e)


def writefile(_endpoint, filepath, _userid, content, islock=False):
  '''Write a file via xroot on behalf of the given userid. The entire content is written
     and any pre-existing file is deleted (or moved to the previous version if supported).
     With islock=True, the file is opened with O_CREAT|O_EXCL.'''
  if isinstance(content, str):
    content = bytes(content, 'UTF-8')
  size = len(content)
  filepath = _getfilepath(filepath)
  log.debug('msg="Invoking writeFile" filepath="%s" size="%d"' % (filepath, size))
  tstart = time.time()
  fd = 0
  if islock:
    # apparently there's no way to pass the O_CREAT without O_TRUNC to the python f.open()!
    # cf. https://stackoverflow.com/questions/38530910/python-open-flags-for-open-or-create
    try:
      fd = os.open(filepath, os.O_CREAT | os.O_EXCL)   # no O_BINARY in Linux
      f = os.fdopen(fd, mode='wb')
    except FileExistsError:
      log.info('msg="File exists on write but islock flag requested" filepath="%s"' % filepath)
      raise IOError('File exists and islock flag requested')
  else:
    try:
      f = open(filepath, mode='wb')
    except OSError as e:
      log.warning('msg="Error opening file for write" filepath="%s" error="%s"' % (filepath, e))
      raise IOError(e)
  tend = time.time()
  try:
    written = f.write(content)
    if fd == 0:
      f.close()
    # else for some reason we get a EBADF if we close a file opened with os.open, though it should be closed!
    if written != size:
      raise IOError('Written %d bytes but content is %d bytes' % (written, size))
    log.info('msg="File written successfully" filepath="%s" elapsedTimems="%.1f" islock="%s"' % \
             (filepath, (tend-tstart)*1000, islock))
  except OSError as e:
    log.warning('msg="Error writing to file" filepath="%s" error="%s"' % (filepath, e))
    raise IOError(e)


def renamefile(_endpoint, origfilepath, newfilepath, _userid):
  '''Rename a file from origfilepath to newfilepath on behalf of the given userid.'''
  try:
    os.rename(_getfilepath(origfilepath), _getfilepath(newfilepath))
  except (FileNotFoundError, PermissionError, OSError) as e:
    raise IOError(e)


def removefile(_endpoint, filepath, _userid, _force=0):
  '''Remove a file on behalf of the given userid.
     The force argument is irrelevant and ignored for local storage.'''
  try:
    os.remove(_getfilepath(filepath))
  except (FileNotFoundError, PermissionError, IsADirectoryError, OSError) as e:
    raise IOError(e)
