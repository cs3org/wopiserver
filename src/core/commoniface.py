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
LOCKKEY = 'iop.lock'

# reference to global config
config = None


# Manipulate Reva-compliant locks, i.e. JSON structs with the following format:
#{
#   "lock_id": "id1234",
#   "type": 2,
#   "user": {
#      "idp": "https://your-idprovider.org",
#      "opaque_id": "username",
#      "type": 1
#   },
#   "app_name": "your_app",
#   "expiration": {
#      "seconds": 1665446400
#   }
#}

def genrevalock(appname, value):
    '''Return a base64-encoded lock compatible with the Reva implementation of the CS3 Lock API
       cf. https://github.com/cs3org/cs3apis/blob/main/cs3/storage/provider/v1beta1/resources.proto'''
    return urlsafe_b64encode(json.dumps(
        {'lock_id': value,
         'type': 2,    # LOCK_TYPE_WRITE
         'app_name': appname if appname else 'wopi',
         'user': {},
         'expiration': {
             'seconds': int(time.time()) + config.getint('general', 'wopilockexpiration')
         },
        }).encode()).decode()


def retrieverevalock(rawlock):
    '''Restores the JSON payload from a base64-encoded Reva lock'''
    l = json.loads(urlsafe_b64decode(rawlock).decode())
    if 'h' in l:
        # temporary code to support the data structure from WOPI 8.0
        l['app_name'] = l['h']
        l['lock_id'] = 'opaquelocktoken:' + l['md']
        l['expiration'] = {}
        l['expiration']['seconds'] = l['exp']
    return l
