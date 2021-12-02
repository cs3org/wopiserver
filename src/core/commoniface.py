'''
commoniface.py

common entities used by all storage interfaces for the IOP WOPI server

Author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

import time
import json

# standard file missing message
ENOENT_MSG = 'No such file or directory'

# standard error thrown when attempting to overwrite a file/xattr in O_EXCL mode
EXCL_ERROR = 'File exists and islock flag requested'

# standard error thrown when attempting an operation without the required access rights
ACCESS_ERROR = 'Operation not permitted'

# name of the xattr storing the Reva lock
LOCKKEY = 'user.iop.lock'

def genrevalock(appname, value):
    '''Return a JSON-formatted lock compatible with the Reva implementation of the CS3 Lock API'''
    return json.dumps({'h': appname if appname else 'wopi', 't': int(time.time()), 'md': value})
