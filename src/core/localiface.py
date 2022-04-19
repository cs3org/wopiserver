'''
localiface.py

Local storage interface for the IOP WOPI server

Main author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

import time
import os
import warnings
from stat import S_ISDIR
import core.commoniface as common

# module-wide state
config = None
log = None
homepath = None

# a conventional value recognized by _checklock()
LOCK = '__LOCK__'

def _getfilepath(filepath):
    '''map the given filepath into the target fs by prepending the homepath (see storagehomepath in wopiserver.conf)'''
    return os.path.normpath(homepath + os.sep + filepath)


def init(inconfig, inlog):
    '''Init module-level variables'''
    global config                 # pylint: disable=global-statement
    global log                        # pylint: disable=global-statement
    global homepath             # pylint: disable=global-statement
    common.config = config = inconfig
    log = inlog
    homepath = config.get('local', 'storagehomepath')
    try:
        # validate the given storagehomepath folder
        mode = os.stat(homepath).st_mode
        if not S_ISDIR(mode):
            raise IOError('Not a directory')
    except IOError as e:
        raise IOError('Could not stat storagehomepath folder %s: %s' % (homepath, e))


def getuseridfromcreds(_token, _wopiuser):
    '''Maps a Reva token and wopiuser to the credentials to be used to access the storage.
    For the localfs case, this is trivially hardcoded'''
    return '0:0'


def stat(_endpoint, filepath, _userid):
    '''Stat a file and returns (size, mtime) as well as other extended info.
    This method assumes that the given userid has access.'''
    try:
        tstart = time.time()
        statInfo = os.stat(_getfilepath(filepath))
        tend = time.time()
        log.info('msg="Invoked stat" inode="%d" filepath="%s" elapsedTimems="%.1f"' %
                 (statInfo.st_ino, _getfilepath(filepath), (tend - tstart) * 1000))
        if S_ISDIR(statInfo.st_mode):
            raise IOError('Is a directory')
        return {
            'inode': common.encodeinode('local', str(statInfo.st_ino)),
            'filepath': filepath,
            'ownerid': str(statInfo.st_uid) + ':' + str(statInfo.st_gid),
            'size': statInfo.st_size,
            'mtime': statInfo.st_mtime
        }
    except (FileNotFoundError, PermissionError) as e:
        raise IOError(e)


def statx(endpoint, filepath, userid, versioninv=1):
    '''Get extended stat info (inode, filepath, userid, size, mtime). Equivalent to stat in the case of local storage.
    The versioninv flag is ignored as local storage always supports version-invariant inodes (cf. CERNBOX-1216).'''
    return stat(endpoint, filepath, userid)


def _checklock(op, endpoint, filepath, userid, lockid):
    '''Verify if the given lockid matches the existing one on the given filepath, if any'''
    if lockid == LOCK:
        # this is a special value to skip the check, used by the lock operations themselves
        return
    lock = getlock(endpoint, filepath, userid)
    if lock and lock['lock_id'] != lockid:
        log.warning('msg="%s: file was locked" filepath="%s" holder="%s"' % (op, filepath, lock['app_name']))
        raise IOError('File was locked')


def setxattr(endpoint, filepath, userid, key, value, lockid):
    '''Set the extended attribute <key> to <value> on behalf of the given userid'''
    _checklock('setxattr', endpoint, filepath, userid, lockid)
    try:
        os.setxattr(_getfilepath(filepath), 'user.' + key, str(value).encode())
    except OSError as e:
        log.error('msg="Failed to setxattr" filepath="%s" key="%s" exception="%s"' % (filepath, key, e))
        raise IOError(e)


def getxattr(_endpoint, filepath, _userid, key):
    '''Get the extended attribute <key> on behalf of the given userid. Do not raise exceptions'''
    try:
        return os.getxattr(_getfilepath(filepath), 'user.' + key).decode('UTF-8')
    except OSError as e:
        log.error('msg="Failed to getxattr" filepath="%s" key="%s" exception="%s"' % (filepath, key, e))
        return None


def rmxattr(endpoint, filepath, userid, key, lockid):
    '''Remove the extended attribute <key> on behalf of the given userid'''
    _checklock('rmxattr', endpoint, filepath, userid, lockid)
    try:
        os.removexattr(_getfilepath(filepath), 'user.' + key)
    except OSError as e:
        log.error('msg="Failed to rmxattr" filepath="%s" key="%s" exception="%s"' % (filepath, key, e))
        raise IOError(e)


def setlock(endpoint, filepath, userid, appname, value):
    '''Set the lock as an xattr on behalf of the given userid'''
    log.debug('msg="Invoked setlock" filepath="%s" value="%s"' % (filepath, value))
    if not getlock(endpoint, filepath, userid):
        # we do not protect from race conditions here
        setxattr(endpoint, filepath, '0:0', common.LOCKKEY, common.genrevalock(appname, value), LOCK)
    else:
        raise IOError(common.EXCL_ERROR)


def getlock(endpoint, filepath, _userid):
    '''Get the lock metadata as an xattr on behalf of the given userid'''
    rawl = getxattr(endpoint, filepath, '0:0', common.LOCKKEY)
    if rawl:
        lock = common.retrieverevalock(rawl)
        if lock['expiration']['seconds'] > time.time():
            log.debug('msg="Invoked getlock" filepath="%s"' % filepath)
            return lock
        # otherwise, the lock had expired: drop it and return None
        log.debug('msg="getlock: removed stale lock" filepath="%s"' % filepath)
        rmxattr(endpoint, filepath, '0:0', common.LOCKKEY, LOCK)
    return None


def refreshlock(endpoint, filepath, userid, appname, value):
    '''Refresh the lock value as an xattr on behalf of the given userid'''
    common.validatelock(filepath, appname, getlock(endpoint, filepath, userid), 'refreshlock', log)
    # this is non-atomic, but if we get here the lock was already held
    log.debug('msg="Invoked refreshlock" filepath="%s" value="%s"' % (filepath, value))
    setxattr(endpoint, filepath, '0:0', common.LOCKKEY, common.genrevalock(appname, value), LOCK)


def unlock(endpoint, filepath, userid, appname, value):
    '''Remove the lock as an xattr on behalf of the given userid'''
    common.validatelock(filepath, appname, getlock(endpoint, filepath, userid), 'unlock', log)
    log.debug('msg="Invoked unlock" filepath="%s" value="%s"' % (filepath, value))
    rmxattr(endpoint, filepath, '0:0', common.LOCKKEY, LOCK)


def readfile(_endpoint, filepath, _userid, _lockid):
    '''Read a file on behalf of the given userid. Note that the function is a generator, managed by Flask.'''
    log.debug('msg="Invoking readFile" filepath="%s"' % filepath)
    try:
        tstart = time.time()
        chunksize = config.getint('io', 'chunksize')
        with open(_getfilepath(filepath), mode='rb', buffering=chunksize) as f:
            tend = time.time()
            log.info('msg="File open for read" filepath="%s" elapsedTimems="%.1f"' % (filepath, (tend - tstart) * 1000))
            # the actual read is buffered and managed by the Flask server
            for chunk in iter(lambda: f.read(chunksize), b''):
                yield chunk
    except FileNotFoundError:
        # log this case as info to keep the logs cleaner
        log.info('msg="File not found on read" filepath="%s"' % filepath)
        # as this is a generator, we yield the error string instead of the file's contents
        yield IOError('No such file or directory')
    except OSError as e:
        # general case, issue a warning
        log.error('msg="Error opening the file for read" filepath="%s" error="%s"' % (filepath, e))
        yield IOError(e)


def writefile(endpoint, filepath, userid, content, lockid, islock=False):
    '''Write a file via xroot on behalf of the given userid. The entire content is written
    and any pre-existing file is deleted (or moved to the previous version if supported).
    With islock=True, the file is opened with O_CREAT|O_EXCL.'''
    if isinstance(content, str):
        content = bytes(content, 'UTF-8')
    size = len(content)
    _checklock('writefile', endpoint, filepath, userid, lockid)
    log.debug('msg="Invoking writeFile" filepath="%s" size="%d"' % (filepath, size))
    tstart = time.time()
    if islock:
        warnings.simplefilter("ignore", ResourceWarning)
        try:
            # apparently there's no way to pass the O_CREAT without O_TRUNC to the python f.open()!
            # cf. https://stackoverflow.com/questions/38530910/python-open-flags-for-open-or-create
            # so we resort to the os-level open(), with some caveats
            fd = os.open(_getfilepath(filepath), os.O_CREAT | os.O_EXCL)
            f = os.fdopen(fd, mode='wb')
            written = f.write(content)        # os.write(fd, ...) raises EBADF?
            os.close(fd)     # f.close() raises EBADF! while this works
            # as f goes out of scope here, we'd get a false ResourceWarning, which is ignored by the above filter
        except FileExistsError:
            log.info('msg="File exists on write but islock flag requested" filepath="%s"' % filepath)
            raise IOError(common.EXCL_ERROR)
        except OSError as e:
            log.warning('msg="Error writing file in O_EXCL mode" filepath="%s" error="%s"' % (filepath, e))
            raise IOError(e)
    else:
        try:
            with open(_getfilepath(filepath), mode='wb') as f:
                written = f.write(content)
        except OSError as e:
            log.error('msg="Error writing file" filepath="%s" error="%s"' % (filepath, e))
            raise IOError(e)
    tend = time.time()
    if written != size:
        raise IOError('Written %d bytes but content is %d bytes' % (written, size))
    log.info('msg="File written successfully" filepath="%s" elapsedTimems="%.1f" islock="%s"' %
             (filepath, (tend - tstart) * 1000, islock))


def renamefile(endpoint, origfilepath, newfilepath, userid, lockid):
    '''Rename a file from origfilepath to newfilepath on behalf of the given userid.'''
    _checklock('renamefile', endpoint, origfilepath, userid, lockid)
    try:
        os.rename(_getfilepath(origfilepath), _getfilepath(newfilepath))
    except (FileNotFoundError, PermissionError, OSError) as e:
        raise IOError(e)


def removefile(_endpoint, filepath, _userid, force=False):
    '''Remove a file on behalf of the given userid.
       The force argument is irrelevant and ignored for local storage.'''
    try:
        os.remove(_getfilepath(filepath))
    except (FileNotFoundError, PermissionError, IsADirectoryError, OSError) as e:
        raise IOError(e)
