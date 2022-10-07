'''
commoniface.py

Common entities used by all storage interfaces for the IOP WOPI server.
Includes functions to store and retrieve Reva-compatible locks.

Main author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

import time
import json
from base64 import urlsafe_b64encode, urlsafe_b64decode
from binascii import Error as B64Error


# standard file missing message
ENOENT_MSG = 'No such file or directory'

# standard error thrown when attempting to overwrite a file/xattr in O_EXCL mode
EXCL_ERROR = 'File exists and islock flag requested'

# error thrown on refreshlock when the payload does not match
LOCK_MISMATCH_ERROR = 'Existing lock payload does not match'

# standard error thrown when attempting an operation without the required access rights
ACCESS_ERROR = 'Operation not permitted'

# name of the xattr storing the Reva lock
LOCKKEY = 'iop.lock'

# the prefix used for the lock-id payload to be WebDAV compatible:
# see https://github.com/cs3org/wopiserver/pull/51#issuecomment-1038798545 for more details;
# the UUID is fully random and hard coded to identify WOPI locks, no need to have it dynamic
WEBDAV_LOCK_PREFIX = 'opaquelocktoken:797356a8-0500-4ceb-a8a0-c94c8cde7eba'

# reference to global config
config = None


# Manipulate Reva-compliant locks, i.e. JSON structs with the following format:
# {
#   "lock_id": "id1234",
#   "type": 2,
#   "user": {
#     "idp": "https://your-idprovider.org",
#     "opaque_id": "username",
#     "type": 1
#   },
#   "app_name": "your_app",
#   "expiration": {
#     "seconds": 1665446400
#   }
# }

def genrevalock(appname, value):
    '''Return a base64-encoded lock compatible with the Reva implementation of the CS3 Lock API
    cf. https://github.com/cs3org/cs3apis/blob/main/cs3/storage/provider/v1beta1/resources.proto'''
    return urlsafe_b64encode(
        json.dumps(
            {
                "lock_id": value,
                "type": 2,  # LOCK_TYPE_WRITE
                "app_name": appname if appname else "wopi",
                "user": {},
                "expiration": {
                    "seconds": int(time.time())
                    + config.getint("general", "wopilockexpiration")
                },
            }
        ).encode()
    ).decode()


def retrieverevalock(rawlock):
    '''Restores the JSON payload from a base64-encoded Reva lock'''
    try:
        return json.loads(urlsafe_b64decode(rawlock + '==').decode())
    except (B64Error, json.JSONDecodeError) as e:
        raise IOError("Unable to parse existing lock: " + str(e))


def encodeinode(endpoint, inode):
    '''Encodes a given endpoint and inode to be used as a safe WOPISrc: endpoint is assumed to already be URL safe'''
    return endpoint + '-' + urlsafe_b64encode(inode.encode()).decode()


def validatelock(filepath, appname, oldlock, oldvalue, op, log):
    '''Common logic for validating locks in the xrootd and local storage interfaces.
       Duplicates some logic implemented in Reva for the cs3 storage interface'''
    try:
        if not oldlock:
            raise IOError('File was not locked or lock had expired')
        if oldvalue and oldlock['lock_id'] != oldvalue:
            raise IOError(LOCK_MISMATCH_ERROR)
        if appname and oldlock['app_name'] != appname \
        and oldlock['app_name'] != 'wopi' and appname != 'wopi':    # TODO deprecated, to be removed after CERNBox rollout
            raise IOError('File is locked by %s' % oldlock['app_name'])
    except IOError as e:
        log.warning('msg="Failed to %s" filepath="%s" appname="%s" reason="%s"' %
                    (op, filepath, appname, e))
        raise
