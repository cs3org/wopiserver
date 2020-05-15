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
  '''Stat a file and returns (size, mtime) as well as other extended info. Assume the given userid has access.'''
  try:
    tstart = time.clock()
    statInfo = os.stat(_getfilepath(filepath))
    tend = time.clock()
    log.info('msg="Invoked stat" filepath="%s" elapsedTimems="%.1f"' % (_getfilepath(filepath), (tend-tstart)*1000))
    return {
        'inode': statInfo.st_ino,
        'filepath': filepath,
        'userid': str(statInfo.st_uid) + ':' + str(statInfo.st_gid),
        'size': statInfo.st_size,
        'mtime': statInfo.st_mtime
        }
  except (FileNotFoundError, PermissionError) as e:
    raise IOError(e)


def statx(_endpoint, filepath, _userid):
  '''Get extended stat info (inode, filepath, userid, size, mtime). Equivalent to stat in the case of local storage.'''
  return stat(_endpoint, filepath, _userid)


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
    return os.getxattr(filepath, 'user.' + key)
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
    tstart = time.clock()
    filepath = _getfilepath(filepath)
    chunksize = config.getint('io', 'chunksize')
    f = open(filepath, mode='rb', buffering=chunksize)
    tend = time.clock()
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


def writefile(_endpoint, filepath, _userid, content, _noversion=1):
  '''Write a file via xroot on behalf of the given userid. The entire content is written
     and any pre-existing file is deleted (or moved to the previous version if supported).
     On local storage, versioning is disabled, therefore the _noversion argument is ignored.'''
  size = len(content)
  filepath = _getfilepath(filepath)
  log.debug('msg="Invoking writeFile" filepath="%s" size="%d"' % (filepath, size))
  try:
    tstart = time.clock()
    f = open(filepath, mode='wb')
    tend = time.clock()
    log.info('msg="File open for write" filepath="%s" elapsedTimems="%.1f"' % (filepath, (tend-tstart)*1000))
    # write the file. In a future implementation, we should find a way to only update the required chunks...
    if isinstance(content, str):
      content = bytes(content, 'UTF-8')
    written = f.write(content)
    f.close()
    if written != size:
      raise IOError('Written %d bytes but content is %d bytes' % (written, size))
  except OSError as e:
    log.warning('msg="Error writing to file" filepath="%s" error="%s"' % (filepath, e))
    raise IOError(e)
  except Exception:
    ex_type, ex_value, ex_traceback = sys.exc_info()
    log.error('msg="Unknown error writing to file" filepath="%s" traceback="%s"' % \
              (filepath, traceback.format_exception(ex_type, ex_value, ex_traceback)))
    raise


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
