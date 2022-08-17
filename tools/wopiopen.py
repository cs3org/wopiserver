#!/usr/bin/python3
'''
This tool can be used to test the openinapp workflow in a development environment.
An alternative is the CLI open-in-app command in Reva.
Call the /wopi/iop/openinapp REST API on the given file and return a URL for direct editing it.

Author: Giuseppe.LoPresti@cern.ch
CERN IT/ST
'''

import sys
import getopt
import configparser
import requests
sys.path.append('src')         # for tests out of the git repo
from core.wopiutils import ViewMode


# usage function
def usage(exitcode):
    '''Prints usage'''
    print('Usage : ' + sys.argv[0] + ' -a|--appname <app_name> -u|--appurl <app_url> [-i|--appinturl <app_url>] -k|--apikey <api_key> '
          '[-s|--storage <storage_endpoint>] [-v|--viewmode VIEW_ONLY|READ_ONLY|READ_WRITE] [-x|--x-access-token <reva_token>] <filename>')
    sys.exit(exitcode)


# first parse the options
try:
    options, args = getopt.getopt(sys.argv[1:], 'hv:s:a:i:u:x:k:', ['help', 'viewmode', 'storage', 'appname', 'appinturl', 'appurl', 'x-access-token', 'apikey'])
except getopt.GetoptError as e:
    print(e)
    usage(1)
viewmode = ViewMode.READ_WRITE
endpoint = ''
appname = ''
appurl = ''
appinturl = ''
revatoken = 'N/A'
apikey = ''
userid = '0:0'
for f, v in options:
    if f == '-h' or f == '--help':
        usage(0)
    elif f == '-v' or f == '--viewmode':
        try:
            viewmode = ViewMode('VIEW_MODE_' + v)
        except ValueError:
            print("Invalid argument for viewmode: " + v)
            usage(1)
    elif f == '-s' or f == '--storage':
        endpoint = v
    elif f == '-i' or f == '--appinturl':
        appinturl = v
    elif f == '-u' or f == '--appurl':
        appurl = v
    elif f == '-a' or f == '--appname':
        appname = v
    elif f == '-x' or f == '--x-access-token':
        # if we need to interact with Reva, this must be a real access token, otherwise it can be omitted
        revatoken = v
    elif f == '-k' or f == '--apikey':
        apikey = v
    else:
        print("Unknown option: " + f)
        usage(1)

# deal with arguments
if len(args) != 1:
    print('Filename argument must be specified')
    usage(1)
filename = args[0]

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
            userid = 'operator@cs3org'
        else:
            print("Invalid argument for filename, storageid:/full/path form required")
            usage(1)
    elif '/eos/user/' in filename:
        # shortcuts for eos (on xrootd)
        endpoint = 'root://eoshome-%s.cern.ch' % filename.split('/')[3]
        userid = filename.split('/')[4]
    elif '/eos/project' in filename:
        print("eosproject storages not supported, please use eoshome")
        usage(1)
    else:
        endpoint = 'default'   # good for test purposes on local storage
if appurl == '' or appname == '':
    print("Missing appname or appurl arguments")
    usage(1)
if appinturl == '':
    appinturl = appurl

wopiurl = 'http%s://localhost:%d' % \
          ('s' if config.get('security', 'usehttps') == 'yes' else '', config.getint('general', 'port'))

# as we're going to issue https requests with verify=False, this is to suppress the warning...
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# open the file and get WOPI token
wopiheaders = {'Authorization': 'Bearer ' + iopsecret}
wopiparams = {'fileid': filename, 'endpoint': endpoint,
              'viewmode': viewmode.value, 'username': 'Operator', 'userid': userid, 'folderurl': '/',
              'appurl': appurl, 'appinturl': appinturl, 'appname': appname}
wopiheaders['TokenHeader'] = revatoken
# for bridged apps, also set the API key
if appname == 'CodiMD' or appname == 'Etherpad':
    wopiheaders['ApiKey'] = apikey
print("Input parameters: %s\n" % wopiparams)
wopiopeninapp = requests.get(wopiurl + '/wopi/iop/openinapp', verify=False,
                             headers=wopiheaders, params=wopiparams)
if wopiopeninapp.status_code != 200:
    print('WOPI open request failed:\n%s' % wopiopeninapp.content.decode())
    sys.exit(-1)

# print the full payload
print(wopiopeninapp.content.decode())
