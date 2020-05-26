#!/usr/bin/python3
'''
Call the /wopi/cbox/open REST API on the given file and return a URL for direct editing it

Author: Giuseppe.LoPresti@cern.ch
CERN IT/ST
'''

import sys, os, getopt, configparser, requests

# usage function
def usage(exitcode):
  '''Prints usage'''
  print('Usage : ' + sys.argv[0] + ' [-h|--help] <filename> <uid> <gid>')
  sys.exit(exitcode)

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
if len(args) < 3:
  print('Not enough arguments')
  usage(1)
if len(args) > 3:
  print('Too many arguments')
  usage(1)
filename = args[0]
ruid = args[1]
rgid = args[2]

# initialization
config = configparser.ConfigParser()
config.read_file(open('/etc/wopi/wopiserver.defaults.conf'))    # fails if the file does not exist
config.read('/etc/wopi/wopiserver.conf')
iopsecret = open(config.get('security', 'iopsecretfile')).read().strip('\n')
eos = 'root://eoshome-%s' % filename.split('/')[3]
wopiurl = 'http%s://localhost:%d' % \
          ('s' if config.get('security', 'usehttps') == 'yes' else '', config.getint('general', 'port'))

# as we're going to issue https requests with verify=False, this is to suppress the warning...
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# get the application server URLs
apps = requests.get(wopiurl + '/wopi/cbox/endpoints', verify=False).json()

# open the file and get WOPI token
wopisrc = requests.get(wopiurl + '/wopi/cbox/open', verify=False,
                       headers={'Authorization': 'Bearer ' + iopsecret},
                       params={'ruid': ruid, 'rgid': rgid, 'filename': filename, 'endpoint': eos,
                               'canedit': 'True', 'username': 'Operator', 'folderurl': 'foo'})
if wopisrc.status_code != 200:
  print('WOPI open request failed:\n%s' % wopisrc.content.decode())
  sys.exit(-1)

# return the full URL to the user
url = apps[os.path.splitext(filename)[1]]['edit']
url += '&' if '?' in url else '&'
print('%sWOPISrc=%s' % (url, wopisrc.content.decode()))
