#!/usr/bin/python3
'''
Call the /wopi/iop/open REST API on the given file and return a URL for direct editing it.
This tool is meant to be used from a WOPI server for opreations purposes, not externally.

Author: Giuseppe.LoPresti@cern.ch
CERN IT/ST
'''

import sys, os, getopt, configparser, requests
from wopiutils import ViewMode

# usage function
def usage(exitcode):
  '''Prints usage'''
  print('Usage : ' + sys.argv[0] + ' [-h|--help] [-v|--viewmode VIEW_ONLY|READ_ONLY|READ_WRITE] <filename> <userid|x-access-token>')
  sys.exit(exitcode)

# first parse the options
try:
  options, args = getopt.getopt(sys.argv[1:], 'hv:e:', ['help', 'viewmode', 'endpoint'])
except getopt.GetoptError as e:
  print(e)
  usage(1)
viewmode = ViewMode.READ_WRITE
endpoint = ''
for f, v in options:
  if f == '-h' or f == '--help':
    usage(0)
  elif f == '-v' or f == '--viewmode':
    try:
      viewmode = ViewMode('VIEW_MODE_' + v)
    except ValueError:
      print("Invalid argument for viewmode: " + v)
      usage(1)
  elif f == '-e' or f == '--endpoint':
    endpoint = v
  else:
    print("Unknown option: " + f)
    usage(1)

# deal with arguments
if len(args) < 2:
  print('Not enough arguments')
  usage(1)
if len(args) > 2:
  print('Too many arguments')
  usage(1)
filename = args[0]
userid = args[1]

# initialization
config = configparser.ConfigParser()
config.read_file(open('/etc/wopi/wopiserver.defaults.conf'))    # fails if the file does not exist
config.read('/etc/wopi/wopiserver.conf')
iopsecret = open(config.get('security', 'iopsecretfile')).read().strip('\n')
storagetype = config.get('general', 'storagetype')
if endpoint == '':
  # work out the endpoint
  if storagetype == 'cs3':
    # here we assume the filename has the form storageid:/path/to/file
    if ':/' in filename:
      endpoint, filename = filename.split(':')
    else:
      print("Invalid argument for filename, storageid:/full/path form required")
      usage(1)
  elif '/eos/user/' in filename:
    # shortcuts for eos (on xrootd)
    endpoint = 'root://eoshome-%s.cern.ch' % filename.split('/')[3]
  elif '/eos/project' in filename:
    endpoint = 'root://eosproject-%s.cern.ch' % filename.split('/')[3]

wopiurl = 'http%s://localhost:%d' % \
          ('s' if config.get('security', 'usehttps') == 'yes' else '', config.getint('general', 'port'))

# as we're going to issue https requests with verify=False, this is to suppress the warning...
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# get the application server URLs
apps = requests.get(wopiurl + '/wopi/cbox/endpoints', verify=False).json()

# open the file and get WOPI token
wopiheaders = {'Authorization': 'Bearer ' + iopsecret}
wopiparams = {'filename': filename, 'endpoint': endpoint,
              'viewmode': viewmode.value, 'username': 'Operator', 'folderurl': 'foo'}
if len(userid.split(':')) == 2:
  # assume userid is in the form `uid:gid`. If not, raises exceptions
  wopiparams['ruid'] = int(userid.split(':')[0])
  wopiparams['rgid'] = int(userid.split(':')[1])
else:
  # assume we've got an x-access-token
  wopiheaders['TokenHeader'] = userid
wopisrc = requests.get(wopiurl + '/wopi/iop/open', verify=False,
                       headers=wopiheaders, params=wopiparams)
if wopisrc.status_code != 200:
  print('WOPI open request failed:\n%s' % wopisrc.content.decode())
  sys.exit(-1)

# return the full URL to the user
try:
  url = apps[os.path.splitext(filename)[1]]['edit' if viewmode == ViewMode.READ_WRITE else 'view']
  url += '?' if '?' not in url else '&'
  print('App URL:\n%sWOPISrc=%s\n' % (url, wopisrc.content.decode()))
except KeyError:
  # no configured editor for this file type, skip
  pass
# in addition, return the WOPI URL and token as env vars for testing purposes
print('WOPI_URL=%s\nWOPI_TOKEN=%s\n' % tuple(wopisrc.content.decode().split('&access_token=')))
