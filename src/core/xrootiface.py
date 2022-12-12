'''
xrootiface.py

eos-xrootd interface for the IOP WOPI server

Main author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

import time
import os
from pwd import getpwnam
from XRootD import client as XrdClient
from XRootD.client.flags import OpenFlags, QueryCode, MkDirFlags, StatInfoFlags

import core.commoniface as common

EOSVERSIONPREFIX = '.sys.v#.'
EXCL_XATTR_MSG = 'exclusive set for existing attribute'
LOCK_MISMATCH_MSG = 'file has a valid extended attribute lock'
FOREIGN_XATTR_MSG = 'foreign attribute lock existing'
OK_MSG = '[SUCCESS]'     # this is what xroot returns on success
EOSLOCKKEY = 'sys.app.lock'

# module-wide state
config = None
log = None
xrdfs = {}        # this is to map each endpoint [string] to its XrdClient
defaultstorage = None
endpointoverride = None
homepath = None
timeout = None


def init(inconfig, inlog):
    '''Init module-level variables'''
    global config               # pylint: disable=global-statement
    global log                  # pylint: disable=global-statement
    global endpointoverride     # pylint: disable=global-statement
    global defaultstorage       # pylint: disable=global-statement
    global homepath             # pylint: disable=global-statement
    global timeout              # pylint: disable=global-statement
    common.config = config = inconfig
    log = inlog
    endpointoverride = config.get('xroot', 'endpointoverride', fallback='')
    defaultstorage = config.get('xroot', 'storageserver')
    homepath = config.get('xroot', 'storagehomepath', fallback='')
    timeout = int(config.get('xroot', 'timeout', fallback='10'))
    # prepare the xroot client for the default storageserver
    _getxrdfor(defaultstorage)


def _getxrdfor(endpoint):
    '''Look up the xrootd client for the given endpoint, create it if missing.
    Supports "default" for the defaultstorage endpoint.'''
    if endpointoverride:
        endpoint = endpointoverride
    if endpoint == 'default':
        return xrdfs[defaultstorage]
    try:
        return xrdfs[endpoint]
    except KeyError:
        # not found, create it
        xrdfs[endpoint] = XrdClient.FileSystem(_geturlfor(endpoint))
        return xrdfs[endpoint]


def _geturlfor(endpoint):
    '''Look up the URL for a given endpoint: "default" corresponds to the defaultstorage one.
    Supports overriding it via configuration, as well as overriding a legacy scheme for project endpoints.'''
    if endpointoverride:
        return endpointoverride
    if endpoint == 'default':
        return defaultstorage
    return endpoint if endpoint.find('root://') == 0 else ('root://' + endpoint.replace('newproject', 'eosproject') + '.cern.ch')


def _appforlock(appname):
    '''One-liner to generate the app name used for eos locks'''
    return 'wopi_' + appname.replace(' ', '_').lower()


def _geneoslock(appname):
    '''One-liner to generate an EOS app lock. Type is `shared` (hardcoded) for WOPI apps, `exclusive` is also supported'''
    return 'expires:%d,type:shared,owner:*:%s' % \
        (int(time.time()) + config.getint("general", "wopilockexpiration"), _appforlock(appname))


def _eosargs(userid, app='wopi', bookingsize=0):
    '''Assume userid is in the form uid:gid and split it into uid, gid
       plus generate extra EOS-specific arguments for the xroot URL'''
    try:
        # try to assert that userid must follow a '%d:%d' format
        userid = userid.split(':')
        if len(userid) != 2:
            raise ValueError
        ruid = int(userid[0])
        rgid = int(userid[1])
        if app not in ('wopi', 'fuse::wopi'):
            app = _appforlock(app)
        return '?eos.ruid=%d&eos.rgid=%d' % (ruid, rgid) + '&eos.app=' + app + \
               (('&eos.bookingsize=' + str(bookingsize)) if bookingsize else '')
    except (ValueError, IndexError):
        raise ValueError('Only Unix-based userid is supported with xrootd storage: %s' % userid)


def _xrootcmd(endpoint, cmd, subcmd, userid, args, app='wopi'):
    '''Perform the <cmd>/<subcmd> action on the special /proc/user path on behalf of the given userid.
       Note that this is entirely EOS-specific.'''
    with XrdClient.File() as f:
        url = _geturlfor(endpoint) + '//proc/user/' + _eosargs(userid, app) + '&mgm.cmd=' + cmd + \
            ('&mgm.subcmd=' + subcmd if subcmd else '') + '&' + args
        tstart = time.time()
        rc, _ = f.open(url, OpenFlags.READ, timeout=timeout)
        tend = time.time()
        if not f.is_open():
            log.error('msg="Error or timeout with xroot" cmd="%s" subcmd="%s" args="%s" rc="%s"' % (cmd, subcmd, args, rc))
            raise IOError('Timeout executing %s' % cmd)
        res = b''.join(f.readlines()).decode().split('&')
        if len(res) == 3:        # we may only just get stdout: in that case, assume it's all OK
            rc = res[2].strip('\n')
            rc = rc[rc.find('=') + 1:].strip('\00')
            if rc != '0':
                # failure: get info from stderr, log and raise
                msg = res[1][res[1].find('=') + 1:].strip('\n')
                if common.ENOENT_MSG.lower() in msg or 'unable to get attribute' in msg or rc == '2':
                    log.info('msg="Invoked cmd on non-existing entity" cmd="%s" subcmd="%s" args="%s" result="%s" rc="%s"' %
                             (cmd, subcmd, args, msg.replace('error:', ''), rc.strip('\00')))
                    raise IOError(common.ENOENT_MSG)
                if EXCL_XATTR_MSG in msg:
                    log.info('msg="Invoked setxattr on an already locked entity" args="%s" result="%s" rc="%s"' %
                             (args, msg.replace('error:', ''), rc.strip('\00')))
                    raise IOError(common.EXCL_ERROR)
                if LOCK_MISMATCH_MSG or FOREIGN_XATTR_MSG in msg:
                    log.info('msg="Mismatched lock" cmd="%s" subcmd="%s" args="%s" app="%s" result="%s" rc="%s"' %
                             (cmd, subcmd, args, app, msg.replace('error:', ''), rc.strip('\00')))
                    raise IOError(common.EXCL_ERROR)
                # anything else (including permission errors) are logged as errors
                log.error('msg="Error with xroot" cmd="%s" subcmd="%s" args="%s" error="%s" rc="%s"' %
                          (cmd, subcmd, args, msg, rc.strip('\00')))
                raise IOError(msg)
    # all right, return everything that came in stdout
    log.debug('msg="Invoked xroot" cmd="%s%s" url="%s" res="%s" elapsedTimems="%.1f"' %
              (cmd, ('/' + subcmd if subcmd else ''), url, (res if cmd != 'fileinfo' else '_redacted_'), (tend - tstart) * 1000))
    return res[0][res[0].find('stdout=') + 7:].strip('\n')


def _getfilepath(filepath, encodeamp=False):
    '''Map the given filepath into the target namespace by prepending the homepath (see storagehomepath in wopiserver.conf)'''
    # use a special legacy encoding by eos for '&'
    return homepath + (filepath if not encodeamp else filepath.replace('&', '#AND#'))


def getuseridfromcreds(_token, wopiuser):
    '''Maps a Reva token and wopiuser to the credentials to be used to access the storage.
    For the xrootd case, we have to resolve the username to uid:gid'''
    userid = getpwnam(wopiuser.split('@')[0])    # a wopiuser has the form username@idp
    return str(userid.pw_uid) + ':' + str(userid.pw_gid)


def stat(endpoint, filepath, userid):
    '''Stat a file via xroot on behalf of the given userid, and returns (size, mtime). Uses the default xroot API.'''
    filepath = _getfilepath(filepath, encodeamp=True)
    tstart = time.time()
    rc, statInfo = _getxrdfor(endpoint).stat(filepath + _eosargs(userid), timeout=timeout)
    tend = time.time()
    log.info('msg="Invoked stat" filepath="%s" elapsedTimems="%.1f"' % (filepath, (tend - tstart) * 1000))
    if not statInfo:
        if common.ENOENT_MSG in rc.message:
            raise IOError(common.ENOENT_MSG)
        raise IOError(rc.message.strip('\n'))
    if statInfo.flags & StatInfoFlags.IS_DIR > 0:
        raise IOError('Is a directory')
    return {'size': statInfo.size, 'mtime': statInfo.modtime}


def statx(endpoint, fileref, userid, versioninv=1):
    '''Get extended stat info (inode, filepath, ownerid, size, mtime) via an xroot opaque query on behalf of the given userid.
    If versioninv=0, the logic to support the version folder is not triggered.
    If the given fileref is an inode, it is resolved to a full path.'''
    tstart = time.time()
    if fileref[0] != '/':
        # we got the fileid of a version folder (typically from Reva), get the path of the corresponding file
        rc = _xrootcmd(endpoint, 'fileinfo', '', userid, 'mgm.path=pid:' + fileref)
        log.info('msg="Invoked stat" fileid="%s"' % fileref)
        # output looks like:
        # Directory: '/eos/.../.sys.v#.filename/'  Treesize: 562\\n  Container: 0  Files: 9  Flags: 40700  Clock: 16b4ea335b36bb06
        # Modify: Sat Nov  6 10:14:27 2021 Timestamp: 1636190067.768903475
        # Change: Tue Oct 12 17:11:58 2021 Timestamp: 1634051518.588282898
        # Sync  : Sat Nov  6 10:14:27 2021 Timestamp: 1636190067.768903475
        # Birth : Tue Oct 12 17:11:58 2021 Timestamp: 1634051518.588282898
        # CUid: 4179 CGid: 2763 Fxid: 000b80fe Fid: 753918 Pid: 2571 Pxid: 00000a0b
        # ETAG: b80fe:1636190067.768
        filepath = rc[rc.find('Directory:')+12:rc.find('Treesize')-4].replace(EOSVERSIONPREFIX, '').replace('#and#', '&')  # noqa:
    else:
        filepath = fileref
    # now stat with the -m flag, so to obtain a k=v list
    statInfo = _xrootcmd(endpoint, 'fileinfo', '', userid, 'mgm.path=' + _getfilepath(filepath, encodeamp=True)
                         + '&mgm.pcmd=fileinfo&mgm.file.info.option=-m')
    try:
        # output looks like:
        # keylength.file=35 file=/eos/.../filename size=2915 mtime=1599649863.0 ctime=1599649866.280468540
        # btime=1599649866.280468540 clock=0 mode=0644 uid=xxxx gid=xxxx fxid=19ab8b68 fid=430672744 ino=115607834422411264
        # pid=1713958 pxid=001a2726 xstype=adler xs=a2dfcdf9 etag="115607834422411264:a2dfcdf9" detached=0 layout=replica
        # nstripes=2 lid=00100112 nrep=2 xattrn=sys.eos.btime xattrv=1599649866.280468540 uid:xxxx[username] gid:xxxx[group]
        # tident:xxx name:username dn: prot:https host:xxxx.cern.ch domain:cern.ch geo: sudo:0 fsid=305 fsid=486
        # cf. https://gitlab.cern.ch/dss/eos/-/blob/master/archive/eosarch/utils.py
        kvlist = [kv.split('=') for kv in statInfo.split()]
        statxdata = {k: v.strip('"') for k, v in [kv for kv in kvlist if len(kv) == 2]}
    except ValueError as e:
        log.error('msg="Invoked fileinfo but failed to parse output" result="%s" exception="%s"' % (statInfo, e))
        raise IOError('Failed to parse fileinfo response')
    if 'treesize' in statxdata:
        raise IOError('Is a directory')      # EISDIR
    if versioninv == 0:
        # statx info of the given file:
        # we extract the eosinstance from endpoint, which looks like e.g. root://eosinstance[.cern.ch]
        endpoint = _geturlfor(endpoint)
        inode = common.encodeinode(endpoint[7:] if endpoint.find('.') == -1 else endpoint[7:endpoint.find('.')], statxdata['ino'])
        log.debug('msg="Invoked stat return" inode="%s" filepath="%s"' % (inode, _getfilepath(filepath)))
        return {
            'inode': inode,
            'filepath': filepath,
            'ownerid': statxdata['uid'] + ':' + statxdata['gid'],
            'size': int(statxdata['size']),
            'mtime': int(float(statxdata['mtime'])),
            'etag': statxdata['etag'],
        }
    # now stat the corresponding version folder to get an inode invariant to save operations, see CERNBOX-1216
    # also, use the owner's as opposed to the user's credentials to bypass any restriction (e.g. with single-share files)
    verFolder = os.path.dirname(filepath) + os.path.sep + EOSVERSIONPREFIX + os.path.basename(filepath)
    ownerarg = _eosargs(statxdata['uid'] + ':' + statxdata['gid'])
    rcv, infov = _getxrdfor(endpoint).query(QueryCode.OPAQUEFILE, _getfilepath(verFolder) + ownerarg + '&mgm.pcmd=stat',
                                            timeout=timeout)
    tend = time.time()
    try:
        if not infov:
            raise IOError('xrdquery returned nothing, rcv=%s' % rcv)
        infov = infov.decode()
        if OK_MSG not in str(rcv) or 'retc=2' in infov:
            # the version folder does not exist: create it (on behalf of the owner) as it is done in Reva
            rcmkdir = _getxrdfor(endpoint).mkdir(_getfilepath(verFolder) + ownerarg, MkDirFlags.MAKEPATH, timeout=timeout)
            if OK_MSG not in str(rcmkdir):
                raise IOError(rcmkdir)
            log.debug('msg="Invoked mkdir on version folder" filepath="%s"' % _getfilepath(verFolder))
            rcv, infov = _getxrdfor(endpoint).query(QueryCode.OPAQUEFILE, _getfilepath(verFolder) + ownerarg + '&mgm.pcmd=stat',
                                                    timeout=timeout)
            tend = time.time()
            if not infov:
                raise IOError('xrdquery returned nothing, rcv=%s' + rcv)
            infov = infov.decode()
            if OK_MSG not in str(rcv) or 'retc=' in infov:
                raise IOError(rcv)
        # infov is a full record according to https://gitlab.cern.ch/dss/eos/-/blob/master/mgm/XrdMgmOfs/fsctl/Stat.cc#L53
        statxdata['ino'] = infov.split()[2]
        log.debug('msg="Invoked stat on version folder" endpoint="%s" filepath="%s" rc="%s" result="%s" elapsedTimems="%.1f"' %
                  (endpoint, _getfilepath(verFolder), str(rcv).strip('\n'), infov, (tend-tstart)*1000))
    except IOError as e:
        # here we should really raise the error, but for now we just log it
        log.error('msg="Failed to mkdir/stat version folder, returning file metadata instead" filepath="%s" error="%s"' %
                  (_getfilepath(filepath), e))
    # return the metadata of the given file, with the inode taken from the version folder
    endpoint = _geturlfor(endpoint)
    inode = common.encodeinode(endpoint[7:] if endpoint.find('.') == -1 else endpoint[7:endpoint.find('.')], statxdata['ino'])
    log.debug('msg="Invoked stat return" inode="%s" filepath="%s"' % (inode, _getfilepath(verFolder)))
    return {
        'inode': inode,
        'filepath': filepath,
        'ownerid': statxdata['uid'] + ':' + statxdata['gid'],
        'size': int(statxdata['size']),
        'mtime': int(float(statxdata['mtime'])),
        'etag': statxdata['etag'],
    }


def setxattr(endpoint, filepath, userid, key, value, lockmd):
    '''Set the extended attribute <key> to <value> via a special open.
    The userid is overridden to make sure it also works on shared files.'''
    appname = 'wopi'
    lockid = None
    if lockmd:
        appname, lockid = lockmd
    if key not in (EOSLOCKKEY, common.LOCKKEY):
        currlock = getlock(endpoint, filepath, userid)
        if currlock and currlock['lock_id'] != lockid:
            raise IOError(common.EXCL_ERROR)
    if 'user' not in key and 'sys' not in key:
        # if nothing is given, assume it's a user attr
        key = 'user.' + key
    _xrootcmd(endpoint, 'attr', 'set', '0:0', 'mgm.attr.key=' + key + '&mgm.attr.value=' + str(value)
              + '&mgm.path=' + _getfilepath(filepath, encodeamp=True), appname)


def getxattr(endpoint, filepath, _userid, key):
    '''Get the extended attribute <key> via a special open.
    The userid is overridden to make sure it also works on shared files.'''
    if 'user' not in key and 'sys' not in key:
        # if nothing is given, assume it's a user attr
        key = 'user.' + key
    try:
        res = _xrootcmd(endpoint, 'attr', 'get', '0:0',
                        'mgm.attr.key=' + key + '&mgm.path=' + _getfilepath(filepath, encodeamp=True))
        # if no error, the response comes in the format <key>="<value>"
        return res.split('"')[1]
    except (IndexError, IOError):
        return None


def rmxattr(endpoint, filepath, _userid, key, lockmd):
    '''Remove the extended attribute <key> via a special open.
    The userid is overridden to make sure it also works on shared files.'''
    appname = 'wopi'
    if lockmd:
        appname, _ = lockmd
    if 'user' not in key and 'sys' not in key:
        # if nothing is given, assume it's a user attr
        key = 'user.' + key
    _xrootcmd(endpoint, 'attr', 'rm', '0:0',
              'mgm.attr.key=' + key + '&mgm.path=' + _getfilepath(filepath, encodeamp=True), appname)


def setlock(endpoint, filepath, userid, appname, value, recurse=False):
    '''Set a lock as an xattr with the given value metadata and appname as holder.
    The special option "c" (create-if-not-exists) is used to be atomic'''
    try:
        log.debug('msg="Invoked setlock" filepath="%s" value="%s"' % (filepath, value))
        setxattr(endpoint, filepath, userid, EOSLOCKKEY, _geneoslock(appname) + '&mgm.option=c', None)
        setxattr(endpoint, filepath, userid, common.LOCKKEY, common.genrevalock(appname, value), (appname, None))
    except IOError as e:
        if common.EXCL_ERROR not in str(e):
            raise
        # check for pre-existing stale locks (this is now not atomic)
        if not getlock(endpoint, filepath, userid) and not recurse:
            setlock(endpoint, filepath, userid, appname, value, recurse=True)
        else:
            # the lock is valid
            raise


def getlock(endpoint, filepath, userid):
    '''Get the lock metadata as an xattr'''
    rawl = getxattr(endpoint, filepath, userid, common.LOCKKEY)
    if rawl:
        lock = common.retrieverevalock(rawl)
        if lock['expiration']['seconds'] > time.time():
            log.debug('msg="Invoked getlock" filepath="%s"' % filepath)
            return lock
        # otherwise, the lock had expired: drop it and return None
        log.debug('msg="getlock: removing stale lock" filepath="%s"' % filepath)
        rmxattr(endpoint, filepath, userid, EOSLOCKKEY, None)
        rmxattr(endpoint, filepath, userid, common.LOCKKEY, None)
    return None


def refreshlock(endpoint, filepath, userid, appname, value, oldvalue=None):
    '''Refresh the lock value as an xattr'''
    try:
        currlock = getlock(endpoint, filepath, userid)
    except IOError as e:
        if 'Unable to parse' in e:
            # ensure we can set the new lock
            currlock = {'lock_id': oldvalue}
        else:
            raise
    if not currlock or (oldvalue and currlock['lock_id'] != oldvalue):
        raise IOError(common.EXCL_ERROR)
    log.debug('msg="Invoked refreshlock" filepath="%s" value="%s"' % (filepath, value))
    # this is non-atomic, but the lock was already held
    setxattr(endpoint, filepath, userid, EOSLOCKKEY, _geneoslock(appname), (appname, None))
    setxattr(endpoint, filepath, userid, common.LOCKKEY, common.genrevalock(appname, value), (appname, None))


def unlock(endpoint, filepath, userid, appname, value):
    '''Remove a lock as an xattr'''
    if not getlock(endpoint, filepath, userid):
        raise IOError(common.EXCL_ERROR)
    log.debug('msg="Invoked unlock" filepath="%s" value="%s"' % (filepath, value))
    try:
        rmxattr(endpoint, filepath, userid, common.LOCKKEY, (appname, None))
    finally:
        # make sure this is attempted regardless the result of the previous operation
        rmxattr(endpoint, filepath, userid, EOSLOCKKEY, (appname, None))


def readfile(endpoint, filepath, userid, _lockid):
    '''Read a file via xroot on behalf of the given userid. Note that the function is a generator, managed by Flask.'''
    log.debug('msg="Invoking readFile" filepath="%s"' % filepath)
    with XrdClient.File() as f:
        tstart = time.time()
        rc, _ = f.open(_geturlfor(endpoint) + '/' + homepath + filepath + _eosargs(userid),
                       OpenFlags.READ, timeout=timeout)
        tend = time.time()
        if not rc.ok:
            # the file could not be opened: check the case of ENOENT and log it as info to keep the logs cleaner
            if common.ENOENT_MSG in rc.message:
                log.info('msg="File not found on read" filepath="%s"' % filepath)
                yield IOError(common.ENOENT_MSG)
            else:
                log.error('msg="Error opening the file for read" filepath="%s" code="%d" error="%s"' %
                          (filepath, rc.shellcode, rc.message.strip('\n')))
                yield IOError(rc.message)
        else:
            log.info('msg="File open for read" filepath="%s" elapsedTimems="%.1f"' % (filepath, (tend - tstart) * 1000))
            chunksize = config.getint('io', 'chunksize')
            rc, statInfo = f.stat()
            chunksize = min(chunksize, statInfo.size)
            # the actual read is buffered and managed by the Flask server
            for chunk in f.readchunks(offset=0, chunksize=chunksize):
                yield chunk


def writefile(endpoint, filepath, userid, content, lockmd, islock=False):
    '''Write a file via xroot on behalf of the given userid. The entire content is written
         and any pre-existing file is deleted (or moved to the previous version if supported).
         With islock=True, the write explicitly disables versioning, and the file is opened with
         O_CREAT|O_EXCL, preventing race conditions.'''
    size = len(content)
    log.debug('msg="Invoking writeFile" filepath="%s" userid="%s" size="%d" islock="%s"' % (filepath, userid, size, islock))
    if islock:
        # this is required to trigger the O_EXCL behavior on EOS when creating lock files
        appname = 'fuse::wopi'
    elif lockmd:
        # this is exclusively used to validate the lock with the app as holder, according to EOS specs (cf. _geneoslock())
        appname, _ = lockmd
    else:
        appname = 'wopi'
    f = XrdClient.File()
    tstart = time.time()
    rc, _ = f.open(_geturlfor(endpoint) + '/' + homepath + filepath + _eosargs(userid, appname, size),
                   OpenFlags.NEW if islock else OpenFlags.DELETE, timeout=timeout)
    tend = time.time()
    if not rc.ok:
        if islock and 'File exists' in rc.message:
            # racing against an existing file
            log.info('msg="File exists on write but islock flag requested" filepath="%s"' % filepath)
            raise IOError(common.EXCL_ERROR)
        if LOCK_MISMATCH_MSG in rc.message:
            log.warning('msg="Lock mismatch when writing file" app="%s" filepath="%s"' % (appname, filepath))
            raise IOError(common.EXCL_ERROR)
        if common.ACCESS_ERROR in rc.message:
            log.warning('msg="Access denied when writing file" filepath="%s"' % filepath)
            raise IOError(common.ACCESS_ERROR)
        # any other failure is reported as is
        log.error('msg="Error opening the file for write" filepath="%s" elapsedTimems="%.1f" error="%s"' %
                  (filepath, (tend-tstart)*1000, rc.message.strip('\n')))
        raise IOError(rc.message.strip('\n'))
    rc, _ = f.write(content, offset=0, size=size)
    if not rc.ok:
        log.error('msg="Error writing the file" filepath="%s" elapsedTimems="%.1f" error="%s"' %
                  (filepath, (tend-tstart)*1000, rc.message.strip('\n')))
        raise IOError(rc.message.strip('\n'))
    log.debug('msg="Write completed" filepath="%s"' % filepath)
    rc, _ = f.truncate(size)
    if not rc.ok:
        log.error('msg="Error truncating the file" filepath="%s" elapsedTimems="%.1f" error="%s"' %
                  (filepath, (tend-tstart)*1000, rc.message.strip('\n')))
        raise IOError(rc.message.strip('\n'))
    rc, _ = f.close()
    if not rc.ok:
        log.error('msg="Error closing the file" filepath="%s" elapsedTimems="%.1f" error="%s"' %
                  (filepath, (tend-tstart)*1000, rc.message.strip('\n')))
        raise IOError(rc.message.strip('\n'))
    log.info('msg="File written successfully" filepath="%s" elapsedTimems="%.1f" islock="%s"' %
             (filepath, (tend-tstart)*1000, islock))


def renamefile(endpoint, origfilepath, newfilepath, userid, lockmd):
    '''Rename a file via a special open from origfilepath to newfilepath on behalf of the given userid.'''
    appname = 'wopi'
    if lockmd:
        appname, _ = lockmd
    _xrootcmd(endpoint, 'file', 'rename', userid, 'mgm.path=' + _getfilepath(origfilepath, encodeamp=True)
              + '&mgm.file.source=' + _getfilepath(origfilepath, encodeamp=True)
              + '&mgm.file.target=' + _getfilepath(newfilepath, encodeamp=True), appname)


def removefile(endpoint, filepath, userid, force=False):
    '''Remove a file via a special open on behalf of the given userid.
    If force then pass the f option, that is skip the recycle bin.
    This is useful for lock files, but as it requires root access the userid is overridden.'''
    if force:
        userid = '0:0'
    _xrootcmd(endpoint, 'rm', None, userid, 'mgm.path=' + _getfilepath(filepath, encodeamp=True)
              + ('&mgm.option=f' if force else ''))
