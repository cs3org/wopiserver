#!/usr/bin/python3
'''
Check the given file for WOPI extended attributes

Author: Giuseppe.LoPresti@cern.ch
CERN IT/ST
'''

import sys
import os
import getopt
import configparser
import logging
import jwt

storage = None

def usage(exitcode):
    '''Prints usage'''
    print('Usage : ' + sys.argv[0] + ' [-h|--help] <filename>')
    sys.exit(exitcode)


def storage_layer_import(storagetype):
    '''A convenience function to import the storage layer module specified in the config and make it globally available'''
    global storage        # pylint: disable=global-statement
    if storagetype in ['local', 'xroot', 'cs3']:
        storagetype += 'iface'
    else:
        raise ImportError('Unsupported/Unknown storage type %s' % storagetype)
    try:
        storage = __import__('core.' + storagetype, globals(), locals(), [storagetype])
    except ImportError:
        print("Missing module when attempting to import {}. Please make sure dependencies are met.", storagetype)
        raise


def _getLockName(fname):
    '''Generates a hidden filename used to store the WOPI locks. Copied from wopiserver.py.'''
    return os.path.dirname(fname) + os.path.sep + '.sys.wopilock.' + os.path.basename(fname) + '.'


# first parse the options
try:
    options, args = getopt.getopt(sys.argv[1:], 'hv', ['help', 'verbose'])
except getopt.GetoptError as e:
    print(e)
    usage(1)
verbose = False
for f, v in options:
    if f == '-h' or f == '--help':
        usage(0)
    elif f == '-v' or f == '--verbose':
        verbose = True
    else:
        print("unknown option : " + f)
        usage(1)

# deal with arguments
if len(args) < 1:
    print('Not enough arguments')
    usage(1)
if len(args) > 1:
    print('Too many arguments')
    usage(1)
filename = args[0]

# initialization
console = logging.StreamHandler()
console.setLevel(logging.ERROR)
logging.getLogger('').addHandler(console)

config = configparser.ConfigParser()
config.read_file(open('/etc/wopi/wopiserver.defaults.conf'))   # fails if the file does not exist
config.read('/etc/wopi/wopiserver.conf')
wopisecret = open(config.get('security', 'wopisecretfile')).read().strip('\n')
storage_layer_import(config.get('general', 'storagetype'))
storage.init(config, logging.getLogger(''))

# stat + getxattr the given file
try:
    instance = 'default'
    if filename.find('/eos/user/') == 0:
        instance = 'eoshome-' + filename[10] + '.cern.ch'
    statInfo = storage.statx(instance, filename, '0:0')
    try:
        wopiTime = storage.getxattr(instance, filename, '0:0', 'iop.wopi.lastwritetime')
        try:
            lockcontent = b''
            for line in storage.readfile(instance, _getLockName(filename), '0:0'):
                if isinstance(line, IOError):
                    raise line     # no pre-existing lock found, or error attempting to read it: assume it does not exist
                # the following check is necessary as it happens to get a str instead of bytes
                lockcontent += line if isinstance(line, type(lockcontent)) else line.encode()
            wopiLock = jwt.decode(lockcontent, wopisecret, algorithms=['HS256'])
            print('%s: inode = %s, mtime = %s, last WOPI write time = %s, locked: %s' % (
                filename, statInfo['inode'], statInfo['mtime'], wopiTime, wopiLock))
        except jwt.exceptions.DecodeError:
            print('%s: inode = %s, mtime = %s, last WOPI write time = %s, unreadable lock' % (
                filename, statInfo['inode'], statInfo['mtime'], wopiTime))
    except IOError:
        print('%s: inode = %s, mtime = %s, not being written by the WOPI server' % (
            filename, statInfo['inode'], statInfo['mtime']))
except IOError as e:
    print('%s: %s' % (filename, e))
