'''
localiface.py

Local storage interface for the IOP WOPI server.
Note that this interface is meant for development purposes only,
and it is supported on Linux and WSL for Windows, not
on native Windows nor on native MacOS systems as they lack
support for extended attributes.

Main author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

import time
import os
import fcntl
import warnings
from stat import S_ISDIR
import core.commoniface as common

# module-wide state
config = None
log = None
homepath = None


class Flock:
    '''A simple class to lock/unlock when entering/leaving a runtime context
    credits: https://github.com/misli/python-flock/blob/master/flock.py
    Could be used as a PoC for the production storage interfaces'''

    def __init__(self, fd, blocking=False):
        '''Instance init'''
        self.fd = fd
        self.op = fcntl.LOCK_EX
        if not blocking:
            self.op |= fcntl.LOCK_NB

    def __enter__(self):
        '''Called on `with`'''
        fcntl.flock(self.fd, self.op)
        return self

    def __exit__(self, _exc_type, _exc_value, _traceback):
        '''Called when exiting a `with` runtime context'''
        fcntl.flock(self.fd, fcntl.LOCK_UN)


def _getfilepath(filepath):
    '''map the given filepath into the target fs by prepending the homepath (see storagehomepath in wopiserver.conf)'''
    return os.path.normpath(homepath + os.sep + filepath)


def init(inconfig, inlog):
    '''Init module-level variables'''
    global config               # pylint: disable=global-statement
    global log                  # pylint: disable=global-statement
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
            'mtime': statInfo.st_mtime,
            'etag': str(statInfo.st_mtime),
        }
    except (FileNotFoundError, PermissionError) as e:
        raise IOError(e)


def statx(endpoint, filepath, userid, versioninv=1):
    '''Get extended stat info (inode, filepath, ownerid, size, mtime). Equivalent to stat in the case of local storage.
    The versioninv flag is ignored as local storage always supports version-invariant inodes (cf. CERNBOX-1216).'''
    return stat(endpoint, filepath, userid)


def _validatelock(filepath, currlock, lockmd, op, log):
    '''Common logic for validating locks: duplicates some logic
    natively implemented by EOS and Reva on the other storage interfaces'''
    appname = value = None
    if lockmd:
        appname, value = lockmd
    try:
        if not currlock:
            raise IOError(common.EXCL_ERROR)
        if appname and currlock['app_name'] != appname \
           and currlock['app_name'] != 'wopi' and appname != 'wopi':    # TODO deprecated, to be removed after CERNBox rollout
            raise IOError(common.EXCL_ERROR + ', file is locked by %s' % currlock['app_name'])
        if value != currlock['lock_id']:
            raise IOError(common.EXCL_ERROR)
    except IOError as e:
        log.warning('msg="Failed to %s" filepath="%s" appname="%s" lockid="%s" currlock="%s" reason="%s"' %
                    (op, filepath, appname, value, currlock, e))
        raise


def setxattr(endpoint, filepath, userid, key, value, lockmd):
    '''Set the extended attribute <key> to <value> on behalf of the given userid'''
    if key != common.LOCKKEY:
        currlock = getlock(endpoint, filepath, userid)
        if currlock:
            # enforce lock only if previously set
            _validatelock(filepath, currlock, lockmd, 'setxattr', log)
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
        log.warning('msg="Failed to getxattr or missing key" filepath="%s" key="%s" exception="%s"' % (filepath, key, e))
        return None


def rmxattr(endpoint, filepath, userid, key, lockmd):
    '''Remove the extended attribute <key> on behalf of the given userid'''
    if key != common.LOCKKEY:
        _validatelock(filepath, getlock(endpoint, filepath, userid), lockmd, 'rmxattr', log)
    try:
        os.removexattr(_getfilepath(filepath), 'user.' + key)
    except OSError as e:
        log.error('msg="Failed to rmxattr" filepath="%s" key="%s" exception="%s"' % (filepath, key, e))
        raise IOError(e)


def setlock(endpoint, filepath, userid, appname, value):
    '''Set the lock as an xattr on behalf of the given userid'''
    log.debug('msg="Invoked setlock" filepath="%s" value="%s"' % (filepath, value))
    with open(_getfilepath(filepath)) as fd:
        fl = Flock(fd)    # ensures atomicity of the following operations
        try:
            with fl:
                if not getlock(endpoint, filepath, userid):
                    log.debug('msg="setlock: invoking setxattr" filepath="%s" value="%s"' % (filepath, value))
                    setxattr(endpoint, filepath, '0:0', common.LOCKKEY, common.genrevalock(appname, value), None)
                else:
                    raise IOError(common.EXCL_ERROR)
        except BlockingIOError as e:
            log.error('msg="File already flocked" filepath="%s" exception="%s"' % (filepath, e))
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
        rmxattr(endpoint, filepath, '0:0', common.LOCKKEY, None)
    return None


def refreshlock(endpoint, filepath, userid, appname, value, oldvalue=None):
    '''Refresh the lock value as an xattr on behalf of the given userid'''
    currlock = getlock(endpoint, filepath, userid)
    if not oldvalue and currlock:
        # this is a pure refresh operation
        oldvalue = currlock['lock_id']
    _validatelock(filepath, currlock, (appname, oldvalue), 'refreshlock', log)
    # this is non-atomic, but if we get here the lock was already held
    log.debug('msg="Invoked refreshlock" filepath="%s" value="%s"' % (filepath, value))
    setxattr(endpoint, filepath, '0:0', common.LOCKKEY, common.genrevalock(appname, value), None)


def unlock(endpoint, filepath, userid, appname, value):
    '''Remove the lock as an xattr on behalf of the given userid'''
    _validatelock(filepath, getlock(endpoint, filepath, userid), (appname, value), 'unlock', log)
    log.debug('msg="Invoked unlock" filepath="%s" value="%s"' % (filepath, value))
    rmxattr(endpoint, filepath, '0:0', common.LOCKKEY, None)


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


def writefile(endpoint, filepath, userid, content, lockmd, islock=False):
    '''Write a file via xroot on behalf of the given userid. The entire content is written
    and any pre-existing file is deleted (or moved to the previous version if supported).
    With islock=True, the file is opened with O_CREAT|O_EXCL.'''
    if isinstance(content, str):
        content = bytes(content, 'UTF-8')
    size = len(content)
    if lockmd:
        _validatelock(filepath, getlock(endpoint, filepath, userid), lockmd, 'writefile', log)
    elif getlock(endpoint, filepath, userid):
        raise IOError(common.EXCL_ERROR)
    log.debug('msg="Invoking writeFile" filepath="%s" size="%d"' % (filepath, size))
    tstart = time.time()
    if islock:
        warnings.simplefilter("ignore", ResourceWarning)
        try:
            # apparently there's no way to pass O_CREAT without O_TRUNC to the python/C f.open()!
            # cf. https://stackoverflow.com/questions/38530910/python-open-flags-for-open-or-create
            # so we resort to the os-level open(), with some caveats
            fd = os.open(_getfilepath(filepath), os.O_CREAT | os.O_EXCL)
            f = os.fdopen(fd, mode='wb')
            tend = time.time()
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
                tend = time.time()
                written = f.write(content)
        except OSError as e:
            log.error('msg="Error writing file" filepath="%s" error="%s"' % (filepath, e))
            raise IOError(e)
    if written != size:
        raise IOError('Written %d bytes but content is %d bytes' % (written, size))
    log.info('msg="File written successfully" filepath="%s" elapsedTimems="%.1f" islock="%s"' %
             (filepath, (tend - tstart) * 1000, islock))


def renamefile(endpoint, origfilepath, newfilepath, userid, lockmd):
    '''Rename a file from origfilepath to newfilepath on behalf of the given userid.'''
    currlock = getlock(endpoint, origfilepath, userid)
    if currlock:
        # enforce lock only if previously set
        _validatelock(origfilepath, currlock, lockmd, 'renamefile', log)
    try:
        os.rename(_getfilepath(origfilepath), _getfilepath(newfilepath))
    except OSError as e:
        raise IOError(e)


def removefile(_endpoint, filepath, _userid, force=False):
    '''Remove a file on behalf of the given userid.
       The force argument is irrelevant and ignored for local storage.'''
    try:
        os.remove(_getfilepath(filepath))
    except OSError as e:
        raise IOError(e)
