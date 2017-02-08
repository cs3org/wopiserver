#!/usr/bin/python
'''
Check the given file for WOPI extended attributes

Author: Giuseppe.LoPresti@cern.ch
CERN IT/ST
'''

import sys, getopt, ConfigParser, logging
import xrootiface

# usage function
def usage(exitcode):
  '''prints usage'''
  print 'Usage : ' + sys.argv[0] + ' [-h|--help] <filename>'
  sys.exit(exitcode)

# first parse the options
try:
  options, args = getopt.getopt(sys.argv[1:], 'hv', ['help', 'verbose'])
except Exception, e:
  print e
  usage(1)
verbose = False
for f, v in options:
  if f == '-h' or f == '--help':
    usage(0)
  elif f == '-v' or f == '--verbose':
    verbose = True
  else:
    print "unknown option : " + f
    usage(1)

# deal with arguments
if len(args) < 1:
  print 'Not enough arguments'
  usage(1)
if len(args) > 1:
  print 'Too many arguments'
  usage(1)
filename = args[0]

# initialization
console = logging.StreamHandler()
console.setLevel(logging.ERROR)
logging.getLogger('').addHandler(console)

config = ConfigParser.SafeConfigParser()
config.readfp(open('/etc/wopi/wopiserver.defaults.conf'))    # fails if the file does not exist
config.read('/etc/wopi/wopiserver.conf')
xrootiface.init(config, logging.getLogger(''))

# stat + getxattr the given file
try:
  statInfo = xrootiface.stat(filename, '0', '0')
  try:
    wopiTime = xrootiface.getxattr(filename, '0', '0', 'oc.wopi.lastwritetime')
    print '%s: mtime = %d, last WOPI write time = %s' % (filename, statInfo.modtime, wopiTime)
  except IOError:
    print '%s: mtime = %d, not written by the WOPI server' % (filename, statInfo.modtime)
except IOError, e:
  print '%s: %s' % (filename, e)

