'''
commoniface.py

Common entities used by all storage interfaces for the IOP WOPI server.
Includes functions to store and retrieve Reva-compatible locks.

Author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

import time
import json
from base64 import urlsafe_b64encode, urlsafe_b64decode


# standard file missing message
ENOENT_MSG = 'No such file or directory'

# standard error thrown when attempting to overwrite a file/xattr in O_EXCL mode
EXCL_ERROR = 'File exists and islock flag requested'

# standard error thrown when attempting an operation without the required access rights
ACCESS_ERROR = 'Operation not permitted'

# name of the xattr storing the Reva lock
LOCKKEY = 'user.iop.lock'

def genrevalock(appname, value):
    '''Return a base64-encoded lock compatible with the Reva implementation of the CS3 Lock API
       cf. https://github.com/cs3org/cs3apis/blob/main/cs3/storage/provider/v1beta1/resources.proto'''
    return urlsafe_b64encode(json.dumps(
        {'type': 'LOCK_TYPE_SHARED',
         'h': appname if appname else 'wopi',
         'md': value,
         'mtime': int(time.time()),
        }).encode()).decode()

def retrieverevalock(rawlock):
    '''Restores the JSON payload from a base64-encoded Reva lock'''
    return json.loads(urlsafe_b64decode(rawlock).decode())
