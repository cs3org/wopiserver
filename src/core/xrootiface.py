'''
xrootiface.py

eos-xrootd interface for the IOP WOPI server

Author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
Contributions: Michael.DSilva@aarnet.edu.au
'''

import time
import os
from stat import S_ISDIR
from base64 import b64encode
from pwd import getpwnam
from XRootD import client as XrdClient
from XRootD.client.flags import OpenFlags, QueryCode, MkDirFlags, StatInfoFlags

import core.commoniface as common

EOSVERSIONPREFIX = '.sys.v#.'

EXCL_XATTR_MSG = 'exclusive set for existing attribute'

# module-wide state
config = None
log = None
xrdfs = {}        # this is to map each endpoint [string] to its XrdClient
defaultstorage = None
endpointoverride = None
homepath = None


def _getxrdfor(endpoint):
    '''Look up the xrootd client for the given endpoint, create it if missing.
    Supports "default" for the defaultstorage endpoint.'''
    global xrdfs             # pylint: disable=global-statement
    global defaultstorage    # pylint: disable=global-statement
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


def _eosargs(userid, atomicwrite=0, bookingsize=0):
    '''Assume userid is in the form uid:gid and split it into uid, gid
       plus generate extra EOS-specific arguments for the xroot URL'''
    try:
        # try to assert that userid must follow a '%d:%d' format
        userid = userid.split(':')
        if len(userid) != 2:
            raise ValueError
        ruid = int(userid[0])
        rgid = int(userid[1])
        return '?eos.ruid=%d&eos.rgid=%d' % (ruid, rgid) + '&eos.app=' + ('fuse::wopi' if not atomicwrite else 'wopi') + \
               (('&eos.bookingsize='+str(bookingsize)) if bookingsize else '')
    except (ValueError, IndexError):
        raise ValueError('Only Unix-based userid is supported with xrootd storage: %s' % userid)


def _xrootcmd(endpoint, cmd, subcmd, userid, args):
    '''Perform the <cmd>/<subcmd> action on the special /proc/user path on behalf of the given userid.
       Note that this is entirely EOS-specific.'''
    with XrdClient.File() as f:
        url = _geturlfor(endpoint) + '//proc/user/' + _eosargs(userid) + '&mgm.cmd=' + cmd + \
              ('&mgm.subcmd=' + subcmd if subcmd else '') + '&' + args
        tstart = time.time()
        rc, _ = f.open(url, OpenFlags.READ)
        tend = time.time()
        res = b''.join(f.readlines()).decode().split('&')
        if len(res) == 3:        # we may only just get stdout: in that case, assume it's all OK
            rc = res[2].strip('\n')
            rc = rc[rc.find('=')+1:]
            if rc != '0':
                # failure: get info from stderr, log and raise
                msg = res[1][res[1].find('=')+1:].strip('\n')
                if common.ENOENT_MSG.lower() in msg or 'unable to get attribute' in msg:
                    log.info('msg="Invoked xroot on non-existing entity" cmd="%s" subcmd="%s" args="%s" error="%s" rc="%s"' % \
                             (cmd, subcmd, args, msg, rc.strip('\00')))
                    raise IOError(common.ENOENT_MSG)
                if EXCL_XATTR_MSG in msg:
                    log.info('msg="Invoked setxattr on an already locked entity" cmd="%s" subcmd="%s" args="%s" error="%s" rc="%s"' % \
                             (cmd, subcmd, args, msg, rc.strip('\00')))
                    raise IOError(EXCL_XATTR_MSG)
                log.error('msg="Error with xroot" cmd="%s" subcmd="%s" args="%s" error="%s" rc="%s"' % \
                          (cmd, subcmd, args, msg, rc.strip('\00')))
                raise IOError(msg)
    # all right, return everything that came in stdout
    log.debug('msg="Invoked xroot" cmd="%s%s" url="%s" res="%s" elapsedTimems="%.1f"' %
              (cmd, ('/' + subcmd if subcmd else ''), url, res, (tend-tstart)*1000))
    return res[0][res[0].find('stdout=')+7:].strip('\n')


def _getfilepath(filepath, encodeamp=False):
    '''Map the given filepath into the target namespace by prepending the homepath (see storagehomepath in wopiserver.conf)'''
    # use a special legacy encoding by eos for '&'
    return homepath + (filepath if not encodeamp else filepath.replace('&', '#AND#'))


def init(inconfig, inlog):
    '''Init module-level variables'''
    global config               # pylint: disable=global-statement
    global log                  # pylint: disable=global-statement
    global endpointoverride     # pylint: disable=global-statement
    global defaultstorage       # pylint: disable=global-statement
    global homepath             # pylint: disable=global-statement
    common.config = config = inconfig
    log = inlog
    endpointoverride = config.get('xroot', 'endpointoverride', fallback='')
    defaultstorage = config.get('xroot', 'storageserver')
    # prepare the xroot client for the default storageserver
    _getxrdfor(defaultstorage)
    if config.has_option('xroot', 'storagehomepath'):
        homepath = config.get('xroot', 'storagehomepath')
    else:
        homepath = ''


def getuseridfromcreds(_token, wopiuser):
    '''Maps a Reva token and wopiuser to the credentials to be used to access the storage.
    For the xrootd case, we have to resolve the username to uid:gid'''
    userid = getpwnam(wopiuser.split('@')[0])    # a wopiuser has the form username@idp
    return str(userid.pw_uid) + ':' + str(userid.pw_gid)


def stat(endpoint, filepath, userid):
    '''Stat a file via xroot on behalf of the given userid, and returns (size, mtime). Uses the default xroot API.'''
    filepath = _getfilepath(filepath, encodeamp=True)
    tstart = time.time()
    rc, statInfo = _getxrdfor(endpoint).stat(filepath + _eosargs(userid))
    tend = time.time()
    log.info('msg="Invoked stat" filepath="%s" elapsedTimems="%.1f"' % (filepath, (tend-tstart)*1000))
    if not statInfo:
        if common.ENOENT_MSG in rc.message:
            raise IOError(common.ENOENT_MSG)
        raise IOError(rc.message.strip('\n'))
    if statInfo.flags & StatInfoFlags.IS_DIR > 0:
        raise IOError('Is a directory')
    return {'size': statInfo.size, 'mtime': statInfo.modtime}


def statx(endpoint, fileid, userid, versioninv=0):
    '''Get extended stat info (inode, filepath, userid, size, mtime) via an xroot opaque query on behalf of the given userid.
    If versioninv=0, the logic to support the version folder is not triggered.
    If the given fileid is an inode, it is resolved to a full path.'''
    tstart = time.time()
    if fileid[0] != '/':
        # we got the fileid of a version folder (typically from Reva), get the path of the corresponding file
        rc = _xrootcmd(endpoint, 'fileinfo', '', userid, 'mgm.path=pid:' + fileid)
        log.info('msg="Invoked stat" fileid="%s"' % fileid)
        # output looks like:
        # ```
        # Directory: '/eos/.../.sys.v#.filename/'  Treesize: 562\\n  Container: 0  Files: 9  Flags: 40700  Clock: 16b4ea335b36bb06
        # Modify: Sat Nov  6 10:14:27 2021 Timestamp: 1636190067.768903475
        # Change: Tue Oct 12 17:11:58 2021 Timestamp: 1634051518.588282898
        # Sync  : Sat Nov  6 10:14:27 2021 Timestamp: 1636190067.768903475
        # Birth : Tue Oct 12 17:11:58 2021 Timestamp: 1634051518.588282898
        # CUid: 4179 CGid: 2763 Fxid: 000b80fe Fid: 753918 Pid: 2571 Pxid: 00000a0b
        # ETAG: b80fe:1636190067.768
        # ```
        filepath = rc[rc.find('Directory:')+12:rc.find('Treesize')-4].replace(EOSVERSIONPREFIX, '')
    else:
        filepath = fileid
    rc, statInfo = _getxrdfor(endpoint).query(QueryCode.OPAQUEFILE, _getfilepath(filepath, encodeamp=True) + \
                                              _eosargs(userid) + '&mgm.pcmd=stat')
    log.info('msg="Invoked stat" filepath="%s"' % _getfilepath(filepath))
    if '[SUCCESS]' not in str(rc) or not statInfo:
        raise IOError(str(rc).strip('\n'))
    statInfo = statInfo.decode()
    if 'stat: retc=2' in statInfo:
        raise IOError(common.ENOENT_MSG)     # convert ENOENT
    if 'retc=' in statInfo:
        raise IOError(statInfo.strip('\n'))
    statxdata = statInfo.split()
    # we got now a full record according to https://gitlab.cern.ch/dss/eos/-/blob/master/mgm/XrdMgmOfs/fsctl/Stat.cc#L53
    if S_ISDIR(int(statxdata[3])):
        raise IOError('Is a directory')            # EISDIR
    if versioninv == 0:
        # classic statx info of the given file:
        # the inode is base64-encoded to match the format issued by the CS3APIs and ensure interoperability,
        # and we extract the eosinstance from endpoint, which looks like e.g. root://eosinstance[.cern.ch]
        endpoint = _geturlfor(endpoint)
        inode = endpoint[7:] if endpoint.find('.') == -1 else endpoint[7:endpoint.find('.')]
        inode += '-' + b64encode(statxdata[2].encode()).decode()
        log.debug('msg="Invoked stat return" inode="%s" filepath="%s"' % (inode, _getfilepath(filepath)))
        return {
            'inode': inode,
            'filepath': filepath,
            'ownerid': statxdata[5] + ':' + statxdata[6],
            'size': int(statxdata[8]),
            'mtime': int(statxdata[12])
        }
    # now stat the corresponding version folder to get an inode invariant to save operations, see CERNBOX-1216
    verFolder = os.path.dirname(filepath) + os.path.sep + EOSVERSIONPREFIX + os.path.basename(filepath)
    rcv, infov = _getxrdfor(endpoint).query(QueryCode.OPAQUEFILE, _getfilepath(verFolder) + _eosargs(userid) + '&mgm.pcmd=stat')
    tend = time.time()
    infov = infov.decode()
    log.debug('msg="Invoked stat on version folder" endpoint="%s" filepath="%s" result="%s" elapsedTimems="%.1f"' % \
              (endpoint, _getfilepath(verFolder), infov, (tend-tstart)*1000))
    try:
        if '[SUCCESS]' not in str(rcv) or 'retc=' in infov:
            # the version folder does not exist: create it
            # cf. https://github.com/cernbox/revaold/blob/master/api/public_link_manager_owncloud/public_link_manager_owncloud.go#L127
            rcmkdir = _getxrdfor(endpoint).mkdir(_getfilepath(verFolder) + _eosargs(userid), MkDirFlags.MAKEPATH)
            log.debug('msg="Invoked mkdir on version folder" filepath="%s" rc="%s"' % (_getfilepath(verFolder), rcmkdir))
            if '[SUCCESS]' not in str(rcmkdir):
                raise IOError
            rcv, infov = _getxrdfor(endpoint).query(QueryCode.OPAQUEFILE, _getfilepath(verFolder) + \
                                                    _eosargs(userid) + '&mgm.pcmd=stat')
            infov = infov.decode()
            log.debug('msg="Invoked stat on version folder" filepath="%s" result="%s"' % (_getfilepath(verFolder), infov))
            if '[SUCCESS]' not in str(rcv) or 'retc=' in infov:
                raise IOError
        statxvdata = infov.split()
    except IOError:
        log.warning('msg="Failed to mkdir/stat version folder" rc="%s"' % rcv)
        statxvdata = statxdata
    # return the metadata of the given file, with the inode taken from the version folder (see above for the encoding)
    endpoint = _geturlfor(endpoint)
    inode = endpoint[7:] if endpoint.find('.') == -1 else endpoint[7:endpoint.find('.')]
    inode += '-' + b64encode(statxvdata[2].encode()).decode()
    log.debug('msg="Invoked stat return" inode="%s" filepath="%s"' % (inode, _getfilepath(verFolder)))
    return {
        'inode': inode,
        'filepath': filepath,
        'ownerid': statxdata[5] + ':' + statxdata[6],
        'size': int(statxdata[8]),
        'mtime': int(statxdata[12])
    }


def setxattr(endpoint, filepath, _userid, key, value):
    '''Set the extended attribute <key> to <value> via a special open.
    The userid is overridden to make sure it also works on shared files.'''
    _xrootcmd(endpoint, 'attr', 'set', '0:0', 'mgm.attr.key=user.' + key + '&mgm.attr.value=' + str(value) + \
              '&mgm.path=' + _getfilepath(filepath, encodeamp=True))


def getxattr(endpoint, filepath, _userid, key):
    '''Get the extended attribute <key> via a special open.
    The userid is overridden to make sure it also works on shared files.'''
    try:
        res = _xrootcmd(endpoint, 'attr', 'get', '0:0', \
                        'mgm.attr.key=user.' + key + '&mgm.path=' + _getfilepath(filepath, encodeamp=True))
        # if no error, the response comes in the format <key>="<value>"
        return res.split('"')[1]
    except (IndexError, IOError):
        return None


def rmxattr(endpoint, filepath, _userid, key):
    '''Remove the extended attribute <key> via a special open.
    The userid is overridden to make sure it also works on shared files.'''
    _xrootcmd(endpoint, 'attr', 'rm', '0:0', 'mgm.attr.key=user.' + key + '&mgm.path=' + _getfilepath(filepath, encodeamp=True))


def setlock(endpoint, filepath, userid, appname, value):
    '''Set a lock as an xattr with the given value metadata and appname as holder.
    The special option "c" (create-if-not-exists) is used to be atomic'''
    try:
        log.debug('msg="Invoked setlock" filepath="%s" value="%s"' % (filepath, value))
        setxattr(endpoint, filepath, userid, common.LOCKKEY, common.genrevalock(appname, value) + '&mgm.option=c')
    except IOError as e:
        if EXCL_XATTR_MSG in str(e):
            raise IOError(common.EXCL_ERROR)


def getlock(endpoint, filepath, userid):
    '''Get the lock metadata as an xattr'''
    l = getxattr(endpoint, filepath, userid, common.LOCKKEY)
    if l:
        return common.retrieverevalock(l)
    return None         # no pre-existing lock found, or error attempting to read it: assume it does not exist


def refreshlock(endpoint, filepath, userid, appname, value):
    '''Refresh the lock value as an xattr'''
    log.debug('msg="Invoked refreshlock" filepath="%s" value="%s"' % (filepath, value))
    l = getlock(endpoint, filepath, userid)
    if not l:
        raise IOError('File was not locked')
    if l['app_name'] != appname and l['app_name'] != 'wopi':
        raise IOError('File is locked by %s' % l['app_name'])
    # this is non-atomic, but the lock was already held
    setxattr(endpoint, filepath, userid, common.LOCKKEY, common.genrevalock(appname, value))


def unlock(endpoint, filepath, userid, _appname, value):
    '''Remove a lock as an xattr'''
    log.debug('msg="Invoked unlock" filepath="%s" value="%s' % (filepath, value))
    rmxattr(endpoint, filepath, userid, common.LOCKKEY)


def readfile(endpoint, filepath, userid):
    '''Read a file via xroot on behalf of the given userid. Note that the function is a generator, managed by Flask.'''
    log.debug('msg="Invoking readFile" filepath="%s"' % filepath)
    with XrdClient.File() as f:
        fileurl = _geturlfor(endpoint) + '/' + homepath + filepath + _eosargs(userid)
        tstart = time.time()
        rc, _ = f.open(fileurl, OpenFlags.READ)
        tend = time.time()
        if not rc.ok:
            # the file could not be opened: check the case of ENOENT and log it as info to keep the logs cleaner
            if common.ENOENT_MSG in rc.message:
                log.info('msg="File not found on read" filepath="%s"' % filepath)
                yield IOError(common.ENOENT_MSG)
            else:
                log.warning('msg="Error opening the file for read" filepath="%s" code="%d" error="%s"' % \
                            (filepath, rc.shellcode, rc.message.strip('\n')))
                yield IOError(rc.message)
        else:
            log.info('msg="File open for read" filepath="%s" elapsedTimems="%.1f"' % (filepath, (tend-tstart)*1000))
            chunksize = config.getint('io', 'chunksize')
            rc, statInfo = f.stat()
            chunksize = min(chunksize, statInfo.size)
            # the actual read is buffered and managed by the Flask server
            for chunk in f.readchunks(offset=0, chunksize=chunksize):
                yield chunk


def writefile(endpoint, filepath, userid, content, islock=False):
    '''Write a file via xroot on behalf of the given userid. The entire content is written
         and any pre-existing file is deleted (or moved to the previous version if supported).
         With islock=True, the write explicitly disables versioning, and the file is opened with
         O_CREAT|O_EXCL, preventing race conditions.'''
    size = len(content)
    log.debug('msg="Invoking writeFile" filepath="%s" userid="%s" size="%d" islock="%s"' % (filepath, userid, size, islock))
    f = XrdClient.File()
    tstart = time.time()
    rc, _ = f.open(_geturlfor(endpoint) + '/' + homepath + filepath + _eosargs(userid, not islock, size),
                   OpenFlags.NEW if islock else OpenFlags.DELETE)
    tend = time.time()
    if not rc.ok:
        if islock and 'File exists' in rc.message:
            # racing against an existing file
            log.info('msg="File exists on write but islock flag requested" filepath="%s"' % filepath)
            raise IOError(common.EXCL_ERROR)
        # any other failure is reported as is
        log.warning('msg="Error opening the file for write" filepath="%s" error="%s"' % (filepath, rc.message.strip('\n')))
        raise IOError(rc.message.strip('\n'))
    # write the file. In a future implementation, we should find a way to only update the required chunks...
    rc, _ = f.write(content, offset=0, size=size)
    if not rc.ok:
        log.warning('msg="Error writing the file" filepath="%s" error="%s"' % (filepath, rc.message.strip('\n')))
        raise IOError(rc.message.strip('\n'))
    rc, _ = f.truncate(size)
    if not rc.ok:
        log.warning('msg="Error truncating the file" filepath="%s" error="%s"' % (filepath, rc.message.strip('\n')))
        raise IOError(rc.message.strip('\n'))
    rc, _ = f.close()
    if not rc.ok:
        log.warning('msg="Error closing the file" filepath="%s" error="%s"' % (filepath, rc.message.strip('\n')))
        raise IOError(rc.message.strip('\n'))
    log.info('msg="File written successfully" filepath="%s" elapsedTimems="%.1f" islock="%s"' % \
             (filepath, (tend-tstart)*1000, islock))


def renamefile(endpoint, origfilepath, newfilepath, userid):
    '''Rename a file via a special open from origfilepath to newfilepath on behalf of the given userid.'''
    _xrootcmd(endpoint, 'file', 'rename', userid, 'mgm.path=' + _getfilepath(origfilepath, encodeamp=True) + \
              '&mgm.file.source=' + _getfilepath(origfilepath, encodeamp=True) + \
              '&mgm.file.target=' + _getfilepath(newfilepath, encodeamp=True))


def removefile(endpoint, filepath, userid, force=False):
    '''Remove a file via a special open on behalf of the given userid.
    If force then pass the f option, that is skip the recycle bin.
    This is useful for lock files, but as it requires root access the userid is overridden.'''
    if force:
        userid = '0:0'
    _xrootcmd(endpoint, 'rm', None, userid, 'mgm.path=' + _getfilepath(filepath, encodeamp=True) + \
              ('&mgm.option=f' if force else ''))
