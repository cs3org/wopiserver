'''
ioplocks.py

Implementation of the interoperable (iop) locking used for OnlyOffice and Office Desktop applications.
'''

import time
import http
import core.wopiutils as utils
import core.commoniface as commiface

# convenience references to global entities
st = None
srv = None
log = None


def ioplock(filename, userid, endpoint, isquery):
    '''Lock or query a given filename, see below for the specs of these APIs'''
    log.info('msg="cboxLock: start processing" filename="%s" request="%s" userid="%s"' %
             (filename, "query" if isquery else "create", userid))

    # first make sure the file itself exists
    try:
        filestat = st.statx(endpoint, filename, userid, versioninv=1)
    except IOError:
        log.warning('msg="cboxLock: target not found or not a file" filename="%s"' % filename)
        return 'File not found or file is a directory', http.client.NOT_FOUND

    # probe if a WOPI lock already exists and expire it if too old:
    # need to craft a special access token
    acctok = {}
    acctok['filename'] = filename
    acctok['endpoint'] = endpoint
    acctok['userid'] = userid
    utils.retrieveWopiLock(0, 'GETLOCK', '', acctok)

    # then probe the existence of a MS Office lock
    try:
        mslockstat = st.stat(endpoint, utils.getMicrosoftOfficeLockName(filename), userid)
        log.info('msg="cboxLock: found existing Microsoft Office lock" filename="%s" lockmtime="%ld"' %
                 (filename, mslockstat['mtime']))
        return 'Previous lock exists', http.client.CONFLICT
    except IOError:
        pass

    if isquery:
        return queryLock(filestat, filename, userid, endpoint)
    return createLock(filestat, filename, userid, endpoint)


def queryLock(filestat, filename, userid, endpoint):
    '''Query for a lock on a given filename.
    Used for OnlyOffice as they do not use WOPI: this way better interoperability is ensured.
    Request arguments:
    - string filename: the full path of the filename to be opened
    - string userid (optional): the user identity to create the file, defaults to 'root:root'
    - string endpoint (optional): the storage endpoint to be used to look up the file or the storage id, in case of
      multi-instance underlying storage; defaults to 'default'
    The call returns:
    - HTTP UNAUTHORIZED (401) if the 'Authorization: Bearer' secret is not provided in the header (cf. /wopi/cbox/open)
    - HTTP CONFLICT (409) if the file got modified since the lock was created
    - HTTP NOT_FOUND (404) if no lock exists
    - HTTP OK (200) if no file modification took place since the lock was created
    In the latter case, a unique lock ID is returned, which is the timestamp when the lock was first created.
    '''
    # read the requested LibreOffice-compatible lock
    try:
        lock = next(st.readfile(endpoint, utils.getLibreOfficeLockName(filename), userid))
        if isinstance(lock, IOError):
            raise lock
        # lock is there, check last mtime
        lockstat = st.stat(endpoint, utils.getLibreOfficeLockName(filename), userid)
    except (IOError, StopIteration) as e:
        # be optimistic, any error here (including no content in the lock file) is like ENOENT
        log.info('msg="cboxLock: lock being queried not found" filename="%s" reason="%s"' %
                 (filename, 'empty lock' if isinstance(e, StopIteration) else str(e)))
        return 'Previous lock not found', http.client.NOT_FOUND
    if filestat['mtime'] > lockstat['mtime']:
        # we were asked to query an existing lock, but the file was modified in between (e.g. by a sync client):
        # notify potential conflict
        log.warning('msg="cboxLock: file got modified after LibreOffice-compatible lock file was created" ' \
                    'filename="%s" request="query"' % filename)
        return 'File modified since open time', http.client.CONFLICT
    # now check content
    lock = lock.decode('UTF-8')
    if 'OnlyOffice Online Editor' not in lock:
        log.info('msg="cboxLock: found existing LibreOffice lock" filename="%s" holder="%s" lockmtime="%ld" request="query"' %
                 (filename, lock.split(',')[1] if ',' in lock else lock, lockstat['mtime']))
        return 'Previous lock exists', http.client.CONFLICT
    # if the lock was created for OnlyOffice, it's OK (OnlyOffice will handle the collaborative session)
    try:
        # extract the creation timestamp on the pre-existing lock if any (see below how the lock is constructed)
        lockid = int(lock.split(';\n')[1].strip(';'))
    except (IndexError, ValueError):
        # lock got corrupted and did not contain the extra creation timestamp
        log.warning('msg="cboxLock: found malformed LibreOffice lock" filename="%s" holder="%s" lockmtime="%ld" request="query"' %
                    (filename, lock.split(',')[1] if ',' in lock else lock, lockstat['mtime']))
        return 'Previous lock exists', http.client.CONFLICT
    log.info('msg="cboxLock: lock file still valid" filename="%s" mtime="%ld" lockid="%ld" lockmtime="%ld" request="query"' %
             (filename, filestat['mtime'], lockid, lockstat['mtime']))
    return str(lockid), http.client.OK


def createLock(filestat, filename, userid, endpoint):
    '''Lock a given filename so that a later WOPI lock call would detect a conflict.
    Used for OnlyOffice as they do not use WOPI: this way better interoperability is ensured.
    It creates a LibreOffice-compatible lock, which is checked by the WOPI lock call
    as well as by LibreOffice.
    Request arguments:
    - string filename: the full path of the filename to be opened
    - string userid (optional): the user identity to create the file, defaults to 'root:root'
    - string endpoint (optional): the storage endpoint to be used to look up the file or the storage id, in case of
      multi-instance underlying storage; defaults to 'default'
    The call returns:
    - HTTP UNAUTHORIZED (401) if the 'Authorization: Bearer' secret is not provided in the header (cf. /wopi/cbox/open)
    - HTTP CONFLICT (409) if a previous lock already exists
    - HTTP NOT_FOUND (404) if the file to be locked does not exist or is a directory
    - HTTP INTERNAL_SERVER_ERROR (500) if writing the lock file failed, though no lock existed
    - HTTP OK (200) if the operation succeeded.
    '''

    # create or refresh a LibreOffice-compatible lock, but with an extra line that contains the timestamp when it was
    # first created (i.e. now or whatever was found on the previous one, provided it's more recent than the token validity).
    # This is used by the classical (non-WOPI) OnlyOffice integration.
    try:
        lockid = int(time.time())
        lolockcontent = ',OnlyOffice Online Editor,%s,%s,ExtWebApp;\n%d;' % \
                        (srv.wopiurl, time.strftime('%d.%m.%Y %H:%M', time.localtime(time.time())), lockid)
        # try to write in exclusive mode (and if a valid WOPI lock exists, assume the corresponding LibreOffice lock
        # is still there so the write will fail)
        st.writefile(endpoint, utils.getLibreOfficeLockName(filename), userid, lolockcontent, islock=True)
        log.info('msg="cboxLock: created LibreOffice-compatible lock file" filename="%s" fileid="%s" lockid="%ld"' %
                 (filename, filestat['inode'], lockid))
        return str(lockid), http.client.OK
    except IOError as e:
        if commiface.EXCL_ERROR not in str(e):
            # writing failed
            log.error('msg="cboxLock: unable to store LibreOffice-compatible lock file" filename="%s" reason="%s"' %
                      (filename, e))
            return 'Error locking file', http.client.INTERNAL_SERVER_ERROR
        # otherwise, a lock existed: try and read it
        try:
            lock = next(st.readfile(endpoint, utils.getLibreOfficeLockName(filename), userid))
            if isinstance(lock, IOError):
                raise lock
        except (IOError, StopIteration) as e:
            #  CERNBOX-1279: another thread was faster in creating the lock, but it's still in flight (StopIteration = no content)!
            log.warning('msg="cboxLock: detected race condition, attempting to re-read LibreOffice-compatible lock" ' \
                        'filename="%s" reason="%s"' % (filename, 'empty lock' if isinstance(e, StopIteration) else str(e)))
            # let's just try again in a short while (not too short though: 2 secs were not enough in testing)
            time.sleep(5)
            try:
                lock = next(st.readfile(endpoint, utils.getLibreOfficeLockName(filename), userid))
                if isinstance(lock, IOError):
                    raise lock
            except (IOError, StopIteration) as e:
                # give up
                log.warning('msg="cboxLock: unable to read existing LibreOffice lock" filename="%s" reason="%s"' %
                            (filename, 'empty lock' if isinstance(e, StopIteration) else str(e)))
                return 'Previous lock exists', http.client.CONFLICT
        lock = lock.decode('UTF-8')
        if 'OnlyOffice Online Editor' not in lock:
            # a previous lock existed and it's not held by us, fail with conflict
            log.warning('msg="cboxLock: found existing LibreOffice lock" filename="%s" holder="%s" request="create"' %
                        (filename, lock.split(',')[1] if ',' in lock else lock))
            return 'Previous lock exists', http.client.CONFLICT
        # otherwise, extract the previous timestamp and refresh the lock itself
        # (this is equivalent to a touch, needed to make the mtime check on query valid, see above)
        # XXX note that here we can't tell if the file was externally modified in between and the lock is actually stale,
        # because by construction the file's mtime is more recent also when being saved by OnlyOffice just before
        # refreshing the lock! To solve this, we'd need to check an xattr set by OnlyOffice/ocproxy on save (and deleted by
        # the sync client), similarly to the WOPI lock logic below.
        try:
            lockid = int(lock.split(';\n')[1].strip(';'))
            if time.time() - lockid > srv.tokenvalidity:
                # the previous timestamp is older than the access token validity (one day typically):
                # force a new lockid, the old one must be stale
                lockid = int(time.time())
            lolockcontent = ',OnlyOffice Online Editor,%s,%s,ExtWebApp;\n%d;' % \
                            (srv.wopiurl, time.strftime('%d.%m.%Y %H:%M', time.localtime(time.time())), lockid)
            st.writefile(endpoint, utils.getLibreOfficeLockName(filename), userid, lolockcontent, islock=False)
            log.info('msg="cboxLock: refreshed LibreOffice-compatible lock file" filename="%s" fileid="%s" mtime="%ld" lockid="%ld"' %
                     (filename, filestat['inode'], filestat['mtime'], lockid))
            return str(lockid), http.client.OK
        except IndexError as e:
            log.error('msg="cboxLock: unable to refresh LibreOffice-compatible lock file" filename="%s" lock="%s" reason="%s"' %
                      (filename, lock, e))
        except IOError as e:
            # this is unexpected, return failure
            log.error('msg="cboxLock: unable to refresh LibreOffice-compatible lock file" filename="%s" reason="%s"' %
                      (filename, e))
            return 'Error relocking file', http.client.INTERNAL_SERVER_ERROR


def iopunlock(filename, userid, endpoint):
    '''Unlock a given filename. Used for OnlyOffice as they do not use WOPI (see cboxLock).'''
    log.info('msg="cboxUnlock: start processing" filename="%s"' % filename)
    try:
        # probe if a WOPI/LibreOffice lock exists with the expected signature
        lock = next(st.readfile(endpoint, utils.getLibreOfficeLockName(filename), userid))
        if isinstance(lock, IOError):
            # typically ENOENT, any other error is grouped here
            log.warning('msg="cboxUnlock: lock file not found" filename="%s"' % filename)
            return 'Lock not found', http.client.NOT_FOUND
        lock = lock.decode('UTF-8')
        if 'OnlyOffice Online Editor' in lock:
            # remove the LibreOffice-compatible lock file
            st.removefile(endpoint, utils.getLibreOfficeLockName(filename), userid, 1)
            # and log this along with the previous lockid for reference
            lockid = int(lock.split(';\n')[1].strip(';'))
            log.info('msg="cboxUnlock: successfully removed LibreOffice-compatible lock file" filename="%s" lockid="%ld"' %
                     (filename, lockid))
            return 'OK', http.client.OK
        # else another lock exists
        log.warning('msg="cboxUnlock: lock file held by another application" filename="%s" holder="%s"' %
                    (filename, lock.split(',')[1] if ',' in lock else lock))
        return 'Lock held by another application', http.client.CONFLICT
    except (IOError, StopIteration) as e:
        log.error('msg="cboxUnlock: remote error with the requested lock" filename="%s" reason="%s"' %
                  (filename, 'empty lock' if isinstance(e, StopIteration) else str(e)))
        return 'Error unlocking file', http.client.INTERNAL_SERVER_ERROR
