"""
cs3iface.py

CS3 API based interface for the IOP WOPI server

Main author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
"""

import os
from configparser import ConfigParser

import cs3.storage.provider.v1beta1.resources_pb2 as cs3spr
import cs3.gateway.v1beta1.gateway_api_pb2 as cs3gw
import cs3.rpc.v1beta1.code_pb2 as cs3code
from cs3client.cs3client import CS3Client
from cs3client.cs3resource import Resource
from cs3client.auth import Auth
import cs3client.exceptions
import core.commoniface as common

# key used if the `lockasattr` option is true, in order to store the lock payload without ensuring any lock semantic
LOCK_ATTR_KEY = "wopi.advlock"

# module-wide state
ctx = {}  # "map" to store some module context: cf. init()
log = None
client = None  # client to interact with the CS3 API


def init(inconfig, inlog):
    """Init module-level variables"""
    global log  # pylint: disable=global-statement
    log = inlog
    global config  # pylint: disable=global-statement
    config = ConfigParser()
    config["cs3client"] = {}
    config["cs3client"]["host"] = inconfig.get("cs3", "revagateway")
    config["cs3client"]["chunk_size"] = inconfig.get("io", "chunksize")
    config["cs3client"]["ssl_verify"] = inconfig.get("cs3", "sslverify", fallback='True')
    config["cs3client"]["lock_expiration"] = inconfig.get("general", "wopilockexpiration")
    config["cs3client"]["lock_as_attr"] = inconfig.get("cs3", "lockasattr", fallback='False')
    config["cs3client"]["lock_not_impl"] = 'False'
    config["cs3client"]["grpc_timeout"] = inconfig.get("cs3", "grpctimeout", fallback='10')
    config["cs3client"]["http_timeout"] = inconfig.get("cs3", "httptimeout", fallback='10')
    global client  # pylint: disable=global-statement
    client = CS3Client(config, "cs3client", log)


def healthcheck():
    """Probes the storage and returns a status message. For cs3 storage, we execute a call to ListAuthProviders"""
    try:
        Auth(client).list_auth_providers()
        log.debug('msg="Executed ListAuthProviders as health check" endpoint="%s"' % (config["cs3client"]["host"]))
        return "OK"
    except ConnectionError as e:
        log.error('msg="Health check: connection error in calling ListAuthProviders" endpoint="%s" error="%s"' %
                  (config["cs3client"]["host"], e))
        return "FAIL"
    except Exception as e:
        log.error('msg="Health check: failed to call ListAuthProviders" endpoint="%s" error="%s"' %
                  (config["cs3client"]["host"], e))
        return "FAIL"


def getuseridfromcreds(token, wopiuser):
    """Maps a Reva token and wopiuser to the credentials to be used to access the storage.
    For the CS3 API case this is the token, and wopiuser is expected to be `username!userid_as_returned_by_stat`
    """
    return token, wopiuser.split("@")[0] + "!" + wopiuser


def authenticate_for_test(userid, userpwd):
    """Use basic authentication against Reva for testing purposes"""
    authReq = cs3gw.AuthenticateRequest(type="basic", client_id=userid, client_secret=userpwd)
    authRes = client._gateway.Authenticate(authReq)  # pylint: disable=protected-access
    log.debug(f'msg="Authenticated user" userid="{authRes.user.id}"')
    if authRes.status.code != cs3code.CODE_OK:
        raise IOError("Failed to authenticate as user " + userid + ": " + authRes.status.message)
    return authRes.token


def stat(endpoint, fileref, userid):
    resource = Resource.from_file_ref_and_endpoint(fileref, endpoint)
    statInfo = client.file.stat(Auth.check_token(userid), resource)
    if statInfo.type == cs3spr.RESOURCE_TYPE_CONTAINER:
        log.info(
            'msg="Invoked stat" endpoint="%s" fileref="%s" trace="%s" result="ISDIR"'
            % (endpoint, fileref, statInfo.status.trace)
        )
        raise IOError("Is a directory")
    if statInfo.type not in (
        cs3spr.RESOURCE_TYPE_FILE,
        cs3spr.RESOURCE_TYPE_SYMLINK,
    ):
        log.warning(
            'msg="Invoked stat" endpoint="%s" fileref="%s" unexpectedtype="%d"' % (endpoint, fileref, statInfo.type)
        )
        raise IOError("Unexpected type %d" % statInfo.type)

    inode = common.encodeinode(statInfo.id.storage_id, statInfo.id.opaque_id)
    if statInfo.path[0] == "/":
        # we got an absolute path from Reva, use it
        filepath = statInfo.path
    else:
        # we got a relative path (actually, just the basename): build an hybrid path that can be used to reference
        # the file, using the parent_id that per specs MUST be available
        filepath = statInfo.parent_id.opaque_id + "/" + os.path.basename(statInfo.path)
    return {
        "inode": inode,
        "filepath": filepath,
        "ownerid": statInfo.owner.opaque_id + "@" + statInfo.owner.idp,
        "size": statInfo.size,
        "mtime": statInfo.mtime.seconds,
        "etag": statInfo.etag.strip('"'),
        "xattrs": statInfo.arbitrary_metadata.metadata,
    }


def statx(endpoint, fileref, userid):
    """Get extended stat info (inode, filepath, ownerid, size, mtime, etag). Equivalent to stat."""
    return stat(endpoint, fileref, userid)


def setxattr(endpoint, filepath, userid, key, value, lockmd):
    """Set the extended attribute <key> to <value> using the given userid as access token"""
    lock_id = None
    if lockmd:
        _, lock_id = lockmd
    resource = Resource.from_file_ref_and_endpoint(filepath, endpoint)
    client.file.set_xattr(Auth.check_token(userid), resource, key, str(value), lock_id)


def rmxattr(endpoint, filepath, userid, key, lockmd):
    """Remove the extended attribute <key> using the given userid as access token"""
    lock_id = None
    if lockmd:
        _, lock_id = lockmd
    resource = Resource.from_file_ref_and_endpoint(filepath, endpoint)
    client.file.remove_xattr(Auth.check_token(userid), resource, key, lock_id)


def readfile(endpoint, filepath, userid, lockid):
    """Read a file using the given userid as access token. Note that the function is a generator, managed by the app server."""
    resource = Resource.from_file_ref_and_endpoint(filepath, endpoint)
    data = client.file.read_file(Auth.check_token(userid), resource, lockid)
    for chunk in data:
        yield chunk


def writefile(endpoint, filepath, userid, content, size, lockmd, islock=False, noversion=False):
    """Write a file using the given userid as access token. The entire content is written
    and any pre-existing file is deleted (or moved to the previous version if noversion=False).
    The islock flag is currently not supported. The backend should at least support
    writing the file with O_CREAT|O_EXCL flags to prevent races."""
    app_name = lock_id = ''
    if lockmd:
        app_name, lock_id = lockmd
    if islock:
        log.warning('msg="islock flag not supported for CS3 storage" filepath="%s"' % filepath)
    resource = Resource.from_file_ref_and_endpoint(filepath, endpoint)
    client.file.write_file(Auth.check_token(userid), resource, content, size,
                           app_name, lock_id, disable_versioning=noversion)


def renamefile(endpoint, filepath, newfilepath, userid, lockmd):
    """Rename a file from origfilepath to newfilepath using the given userid as access token."""
    lock_id = None
    if lockmd:
        _, lock_id = lockmd
    resource = Resource.from_file_ref_and_endpoint(filepath, endpoint)
    new_resource = Resource.from_file_ref_and_endpoint(newfilepath, endpoint)
    client.file.rename_file(Auth.check_token(userid), resource, new_resource, lock_id)


def removefile(endpoint, filepath, userid, force=False):
    """Remove a file using the given userid as access token.
    The force argument is ignored for now for CS3 storage."""
    resource = Resource.from_file_ref_and_endpoint(filepath, endpoint)
    client.file.remove_file(Auth.check_token(userid), resource)


def setlock(endpoint, filepath, userid, appname, value):
    """Set a lock to filepath with the given value metadata and appname as holder"""
    resource = Resource.from_file_ref_and_endpoint(filepath, endpoint)
    client.file.set_lock(Auth.check_token(userid), resource, app_name=appname, lock_id=value)


def refreshlock(endpoint, filepath, userid, appname, value, oldvalue=None):
    """Refresh the lock metadata for the given filepath"""
    resource = Resource.from_file_ref_and_endpoint(filepath, endpoint)
    client.file.refresh_lock(
        Auth.check_token(userid), resource, app_name=appname, lock_id=value, existing_lock_id=oldvalue
    )


def getlock(endpoint, filepath, userid):
    """Get the lock metadata for the given filepath"""
    resource = Resource.from_file_ref_and_endpoint(filepath, endpoint)
    try:
        return client.file.get_lock(Auth.check_token(userid), resource)
    except cs3client.exceptions.NotFoundException:
        return None


def unlock(endpoint, filepath, userid, appname, value):
    """Remove the lock for the given filepath"""
    resource = Resource.from_file_ref_and_endpoint(filepath, endpoint)
    client.file.unlock(Auth.check_token(userid), resource, app_name=appname, lock_id=value)
