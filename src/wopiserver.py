#!/usr/bin/env python3
'''
wopiserver.py

The Web-application Open Platform Interface (WOPI) gateway for the ScienceMesh IOP

Author: Giuseppe Lo Presti (@glpatcern), CERN/IT-ST
Contributions: see README.md
'''

import sys
import os
import time
import socket
import configparser
from platform import python_version
import logging
import logging.handlers
import urllib.parse
import http.client
import json
try:
    import flask                   # Flask app server
    from werkzeug.exceptions import NotFound as Flask_NotFound
    from werkzeug.exceptions import MethodNotAllowed as Flask_MethodNotAllowed
    import jwt                     # JSON Web Tokens support
    from prometheus_flask_exporter import PrometheusMetrics    # Prometheus support
except ImportError:
    print("Missing modules, please install dependencies with `pip3 install -f requirements.txt`")
    raise
import core.wopi
import core.discovery
import core.ioplocks
import core.wopiutils as utils
import bridge

# the following constant is replaced on the fly when generating the docker image
WOPISERVERVERSION = 'git'

# alias of the storage layer module, see function below
storage = None

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
        print("Missing module when attempting to import %s.py. Please make sure dependencies are met." % storagetype)
        raise


class Wopi:
    '''A singleton container for all state information of the WOPI server'''
    app = flask.Flask("wopiserver")
    metrics = PrometheusMetrics(app, group_by='endpoint')
    port = 0
    lastConfigReadTime = time.time()
    loglevels = {"Critical": logging.CRITICAL,  # 50
                 "Error":    logging.ERROR,     # 40
                 "Warning":  logging.WARNING,   # 30
                 "Info":     logging.INFO,      # 20
                 "Debug":    logging.DEBUG      # 10
                }
    log = utils.JsonLogger(app.logger)
    openfiles = {}
    endpoints = {}

    @classmethod
    def init(cls):
        '''Initialises the application, bails out in case of failures. Note this is not a __init__ method'''
        try:
            # detect hostname, or take it from the environment if set e.g. by docker
            hostname = os.environ.get('HOST_HOSTNAME')
            if not hostname:
                hostname = socket.gethostname()
            # configure the logging
            loghandler = logging.FileHandler('/var/log/wopi/wopiserver.log')
            loghandler.setFormatter(logging.Formatter(
                fmt='{"time": "%(asctime)s", "host": "' + hostname + \
                    '", "level": "%(levelname)s", "process": "%(name)s", %(message)s}',
                datefmt='%Y-%m-%dT%H:%M:%S'))
            cls.app.logger.handlers = [loghandler]
            # read the configuration
            cls.config = configparser.ConfigParser()
            with open('/etc/wopi/wopiserver.defaults.conf') as fdef:
                cls.config.read_file(fdef)
            cls.config.read('/etc/wopi/wopiserver.conf')
            # load the requested storage layer
            storage_layer_import(cls.config.get('general', 'storagetype'))
            # prepare the Flask web app
            cls.port = int(cls.config.get('general', 'port'))
            cls.log.setLevel(cls.loglevels[cls.config.get('general', 'loglevel')])
            try:
                cls.nonofficetypes = cls.config.get('general', 'nonofficetypes').split()
            except (TypeError, configparser.NoOptionError) as e:
                cls.nonofficetypes = []
            with open(cls.config.get('security', 'wopisecretfile')) as s:
                cls.wopisecret = s.read().strip('\n')
            with open(cls.config.get('security', 'iopsecretfile')) as s:
                cls.iopsecret = s.read().strip('\n')
            cls.tokenvalidity = cls.config.getint('general', 'tokenvalidity')
            storage.init(cls.config, cls.log)                          # initialize the storage layer
            cls.useHttps = cls.config.get('security', 'usehttps').lower() == 'yes'
            cls.wopiurl = cls.config.get('general', 'wopiurl')
            if cls.config.has_option('general', 'lockpath'):
                cls.lockpath = cls.config.get('general', 'lockpath')
            else:
                cls.lockpath = ''
            _ = cls.config.get('general', 'downloadurl')   # make sure this is defined
            # initialize the bridge
            bridge.WB.init(cls.config, cls.log)
            # initialize the submodules
            # TODO improve handling of globals across the whole code base
            utils.srv = core.ioplocks.srv = core.wopi.srv = core.discovery.srv = cls
            utils.log = core.ioplocks.log = core.wopi.log = core.discovery.log = cls.log
            utils.st = core.ioplocks.st = core.wopi.st = storage
        except (configparser.NoOptionError, OSError) as e:
            # any error we get here with the configuration is fatal
            cls.log.fatal('msg="Failed to initialize the service, aborting" error="%s"' % e)
            print("Failed to initialize the service: %s\n" % e, file=sys.stderr)
            sys.exit(22)


    @classmethod
    def refreshconfig(cls):
        '''Re-read the configuration file every 300 secs to catch any runtime parameter change'''
        if time.time() > cls.lastConfigReadTime + 300:
            cls.lastConfigReadTime = time.time()
            cls.config.read('/etc/wopi/wopiserver.conf')
            # refresh some general parameters
            cls.tokenvalidity = cls.config.getint('general', 'tokenvalidity')
            cls.log.setLevel(cls.loglevels[cls.config.get('general', 'loglevel')])


    @classmethod
    def run(cls):
        '''Runs the Flask app in either standalone (https) or embedded (http) mode'''
        if cls.useHttps:
            cls.log.info('msg="WOPI Server starting in standalone secure mode" port="%d" wopiurl="%s" version="%s"' %
                         (cls.port, cls.wopiurl, WOPISERVERVERSION))
            cls.app.run(host='0.0.0.0', port=cls.port, threaded=True, debug=(cls.config.get('general', 'loglevel') == 'Debug'),
                        ssl_context=(cls.config.get('security', 'wopicert'), cls.config.get('security', 'wopikey')))
        else:
            cls.log.info('msg="WOPI Server starting in unsecure/embedded mode" port="%d" wopiurl="%s" version="%s"' %
                         (cls.port, cls.wopiurl, WOPISERVERVERSION))
            cls.app.run(host='0.0.0.0', port=cls.port, threaded=True, debug=(cls.config.get('general', 'loglevel') == 'Debug'))



@Wopi.app.errorhandler(Exception)
def handleException(ex):
    '''Generic method to log any uncaught exception'''
    if isinstance(ex, (Flask_NotFound, Flask_MethodNotAllowed)):
        return ex
    return utils.logGeneralExceptionAndReturn(ex, flask.request)


@Wopi.app.route("/", methods=['GET'])
def redir():
    '''A simple redirect to the page below'''
    return flask.redirect("/wopi")

@Wopi.app.route("/wopi", methods=['GET'])
def index():
    '''Return a default index page with some user-friendly information about this service'''
    Wopi.log.debug('msg="Accessed index page" client="%s"' % flask.request.remote_addr)
    return """
      <html><head><title>ScienceMesh WOPI Server</title></head>
      <body>
      <div align="center" style="color:#000080; padding-top:50px; font-family:Verdana; size:11">
      This is the ScienceMesh IOP <a href=http://wopi.readthedocs.io>WOPI</a> server to support online office-like editors.<br>
      To use this service, please log in to your EFSS Storage and click on a supported document.</div>
      <div style="position: absolute; bottom: 10px; left: 10px; width: 99%%;"><hr>
      <i>ScienceMesh WOPI Server %s at %s. Powered by Flask %s for Python %s</i>.
      </body>
      </html>
      """ % (WOPISERVERVERSION, socket.getfqdn(), flask.__version__, python_version())


#
# open-in-app endpoint
#
@Wopi.app.route("/wopi/iop/open", methods=['GET'])
@Wopi.metrics.do_not_track()
@Wopi.metrics.counter('open_by_ext', 'Number of /open calls by file extension',
                      labels={'open_type': lambda:
                         flask.request.args['filename'].split('.')[-1] \
                         if 'filename' in flask.request.args and '.' in flask.request.args['filename'] \
                         else ('noext' if 'filename' in flask.request.args else 'fileid')
                      })
def iopOpen():
    '''Generates a WOPISrc target and an access token to be passed to a WOPI-compatible Office-like app
    for accessing a given file for a given user.
    Required headers:
    - Authorization: a bearer shared secret to protect this call as it provides direct access to any user's file
    - TokenHeader: an x-access-token to serve as user identity towards Reva
      - OR int ruid, rgid as query parameters: a real Unix user identity (id:group); this is for legacy compatibility
    Request arguments:
    - enum viewmode: how the user should access the file, according to utils.ViewMode/the CS3 app provider API
      - OR bool canedit: True if full access should be given to the user, otherwise read-only access is granted
    - string username (optional): user's full display name, typically shown by the Office app
    - string filename OR fileid: the full path of the filename to be opened, or its fileid
    - string folderurl: the URL to come back to the containing folder for this file, typically shown by the Office app
    - string endpoint (optional): the storage endpoint to be used to look up the file or the storage id, in case of
      multi-instance underlying storage; defaults to 'default'
    - string appname (optional): the application engine to be used to open the file, previously registered
      via /wopi/iop/registerapp. When provided, the return is a HTTP redirect to the full URL, otherwise only
      the WOPISrc and access_token parts of the URL are returned in the body.
    '''
    Wopi.refreshconfig()
    req = flask.request
    # if running in https mode, first check if the shared secret matches ours
    if req.headers.get('Authorization') != 'Bearer ' + Wopi.iopsecret:
        Wopi.log.warning('msg="iopOpen: unauthorized access attempt, missing authorization token" ' \
                         'client="%s" clientAuth="%s"' % (req.remote_addr, req.headers.get('Authorization')))
        return 'Client not authorized', http.client.UNAUTHORIZED
    # now validate the user identity and deny root access
    try:
        if 'TokenHeader' in req.headers:
            userid = req.headers['TokenHeader']
        else:
            # backwards compatibility
            userid = 'N/A'
            ruid = int(req.args['ruid'])
            rgid = int(req.args['rgid'])
            userid = '%d:%d' % (ruid, rgid)
            if ruid == 0 or rgid == 0:
                raise ValueError
    except ValueError:
        Wopi.log.warning('msg="iopOpen: invalid or missing user/token in request" client="%s" user="%s"' %
                         (req.remote_addr, userid))
        return 'Client not authorized', http.client.UNAUTHORIZED
    fileid = urllib.parse.unquote(req.args['filename']) if 'filename' in req.args else req.args.get('fileid', '')
    if fileid == '':
        Wopi.log.warning('msg="iopOpen: either filename or fileid must be provided" client="%s"' % req.remote_addr)
        return 'Invalid argument', http.client.BAD_REQUEST
    if 'viewmode' in req.args:
        try:
            viewmode = utils.ViewMode(req.args['viewmode'])
        except ValueError:
            Wopi.log.warning('msg="iopOpen: invalid viewmode parameter" client="%s" viewmode="%s"' %
                             (req.remote_addr, req.args['viewmode']))
            return 'Invalid argument', http.client.BAD_REQUEST
    else:
        # backwards compatibility
        viewmode = utils.ViewMode.READ_WRITE if 'canedit' in req.args and req.args['canedit'].lower() == 'true' \
                   else utils.ViewMode.READ_ONLY
    username = req.args.get('username', '')
    folderurl = urllib.parse.unquote(req.args.get('folderurl', '%%2F'))   # defaults to `/`
    endpoint = req.args.get('endpoint', 'default')
    appname = urllib.parse.unquote(req.args.get('appname', 'default'))
    try:
        inode, fname, acctok = utils.generateAccessToken(userid, fileid, viewmode, username, folderurl, endpoint, appname)
        # generate the URL-encoded payload for the app engine
        url = '%s&access_token=%s' % (utils.generateWopiSrc(inode), acctok)      # no need to URL-encode the JWT token
        if appname not in core.discovery.apps:
            return url
        return flask.redirect('%s&WOPISrc=%s' % (core.discovery.apps[appname][os.path.splitext(fname)[1]]['edit' if viewmode == utils.ViewMode.READ_WRITE else 'view'], url))
    except IOError as e:
        Wopi.log.info('msg="iopOpen: remote error on generating token" client="%s" user="%s" ' \
                      'friendlyname="%s" mode="%s" endpoint="%s" reason="%s"' %
                      (req.remote_addr, userid, username, viewmode, endpoint, e))
        return 'Remote error, file not found or file is a directory', http.client.NOT_FOUND


@Wopi.app.route("/wopi/cbox/open", methods=['GET'])
def cboxOpen():
    '''CERNBox-specific endpoint for /open, provided for backwards compatibility'''
    return iopOpen()


@Wopi.app.route("/wopi/iop/open/list", methods=['GET'])
def iopGetOpenFiles():
    '''Returns a list of all currently opened files, for operations purposes only.
    This call is protected by the same shared secret as the /wopi/iop/open call.'''
    req = flask.request
    if req.headers.get('Authorization') != 'Bearer ' + Wopi.iopsecret:
        Wopi.log.warning('msg="iopGetOpenFiles: unauthorized access attempt, missing authorization token" ' \
                         'client="%s"' % req.remote_addr)
        return 'Client not authorized', http.client.UNAUTHORIZED
    # first convert the sets into lists, otherwise sets cannot be serialized in JSON format
    jlist = {}
    for f in list(Wopi.openfiles.keys()):
        jlist[f] = (Wopi.openfiles[f][0], tuple(Wopi.openfiles[f][1]))
    # dump the current list of opened files in JSON format
    Wopi.log.info('msg="iopGetOpenFiles: returning list of open files" client="%s"' % req.remote_addr)
    return flask.Response(json.dumps(jlist), mimetype='application/json')


#
# WOPI discovery endpoints
#
@Wopi.app.route("/wopi/cbox/endpoints", methods=['GET'])
@Wopi.metrics.do_not_track()
def cboxEndPoints():
    '''Returns the office apps end-points registered with this WOPI server. This is used by the EFSS
    client to discover which Apps frontends can be used with this WOPI server.
    Note that if the end-points are relocated and the corresponding configuration entry updated,
    the WOPI server must be restarted.'''
    # TODO this endpoint should be moved to the Apps Registry service in Reva
    Wopi.log.info('msg="cboxEndPoints: returning all registered office apps end-points" client="%s" mimetypesCount="%d"' %
                  (flask.request.remote_addr, len(Wopi.endpoints)))
    return flask.Response(json.dumps(Wopi.endpoints), mimetype='application/json')


@Wopi.app.route("/wopi/iop/discoverapp", methods=['POST'])
@Wopi.metrics.do_not_track()
def iopDiscoverApp():
    '''Discover a new WOPI app
    Required headers:
    - Authorization: a bearer shared secret to protect this call
    Request arguments:
    - appname: a human-readable string to identify the app
    - appurl: the (URL-encoded) URL of the app engine. It is expected that the WOPI discovery info can be gathered
      by querying appurl + '/hosting/discovery' according to the WOPI specs, or that the app is supported via
      the bridge extensions
    - appinturl (optional): if provided, the internal URL to be used for reaching the app (defaults to the appurl)
    The call returns:
    - HTTP UNAUTHORIZED (401) if the 'Authorization: Bearer' secret is not provided in the header (cf. /wopi/cbox/open)
    - HTTP NOT_FOUND (404) if there was an error contacting the appurl
    - HTTP BAD_REQUEST (400) if the appurl is not a WOPI-compatible or supported application
    - HTTP OK (200) if the appplication was properly registered: in this case, all supported file extensions
      are returned as a JSON list
    '''
    req = flask.request
    if req.headers.get('Authorization') != 'Bearer ' + Wopi.iopsecret:
        Wopi.log.warning('msg="iopRegisterApp: unauthorized access attempt, missing authorization token" ' \
                         'client="%s"' % req.remote_addr)
        return 'Client not authorized', http.client.UNAUTHORIZED
    return core.discovery.registerapp(req.args.get('appname', 'unnamed'), \
                                      urllib.parse.unquote(req.args.get('appurl', 'http://invalid')),
                                      urllib.parse.unquote(req.args.get('appinturl', '')))


#
# WOPI protocol implementation
#
@Wopi.app.route("/wopi/files/<fileid>", methods=['GET'])
def wopiCheckFileInfo(fileid):
    '''Implements the CheckFileInfo WOPI call'''
    return core.wopi.checkFileInfo(fileid)


@Wopi.app.route("/wopi/files/<fileid>/contents", methods=['GET'])
def wopiGetFile(fileid):
    '''Implements the GetFile WOPI call'''
    return core.wopi.getFile(fileid)


@Wopi.app.route("/wopi/files/<fileid>", methods=['POST'])
def wopiFilesPost(fileid):
    '''A dispatcher metod for all POST operations on files'''
    Wopi.refreshconfig()
    try:
        acctok = jwt.decode(flask.request.args['access_token'], Wopi.wopisecret, algorithms=['HS256'])
        if acctok['exp'] < time.time():
            raise jwt.exceptions.ExpiredSignatureError
        headers = flask.request.headers
        op = headers['X-WOPI-Override']       # must be one of the following strings, throws KeyError if missing
        if op != 'GET_LOCK' and utils.ViewMode(acctok['viewmode']) != utils.ViewMode.READ_WRITE:
            # protect this call if the WOPI client does not have privileges
            return 'Attempting to perform a write operation using a read-only token', http.client.UNAUTHORIZED
        if op in ('LOCK', 'REFRESH_LOCK'):
            return core.wopi.lock(fileid, headers, acctok)
        if op == 'UNLOCK':
            return core.wopi.unlock(fileid, headers, acctok)
        if op == 'GET_LOCK':
            return core.wopi.getLock(fileid, headers, acctok)
        if op == 'PUT_RELATIVE':
            return core.wopi.putRelative(fileid, headers, acctok)
        if op == 'DELETE':
            return core.wopi.deleteFile(fileid, headers, acctok)
        if op == 'RENAME_FILE':
            return core.wopi.renameFile(fileid, headers, acctok)
        #elif op == 'PUT_USER_INFO':   https://wopirest.readthedocs.io/en/latest/files/PutUserInfo.html
        # Any other op is unsupported
        Wopi.log.warning('msg="Unknown/unsupported operation" operation="%s"' % op)
        return 'Not supported operation found in header', http.client.NOT_IMPLEMENTED
    except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError) as e:
        Wopi.log.warning('msg="Signature verification failed" client="%s" requestedUrl="%s" error="%s" token="%s"' %
                         (flask.request.remote_addr, flask.request.base_url, e, flask.request.args['access_token']))
        return 'Invalid access token', http.client.NOT_FOUND


@Wopi.app.route("/wopi/files/<fileid>/contents", methods=['POST'])
def wopiPutFile(fileid):
    '''Implements the PutFile WOPI call'''
    return core.wopi.putFile(fileid)


#
# iop lock endpoints
#
@Wopi.app.route("/wopi/cbox/lock", methods=['GET', 'POST'])
@Wopi.metrics.counter('lock_by_ext', 'Number of /lock calls by file extension',
                      labels={'open_type': lambda:
                          (flask.request.args['filename'].split('.')[-1] \
                           if 'filename' in flask.request.args and '.' in flask.request.args['filename'] \
                           else 'noext') if flask.request.method == 'POST' else 'query'
                          })
def cboxLock():
    '''Lock a given filename so that a later WOPI lock call would detect a conflict.
    Used for OnlyOffice as they do not use WOPI: this way better interoperability is ensured.
    It creates a LibreOffice-compatible lock, which is checked by the WOPI lock call
    as well as by LibreOffice.
    Method: POST to create a lock, GET to query for it
    Request arguments:
    - string filename: the full path of the filename to be opened
    - string userid (optional): the user identity to create the file, defaults to 'root:root'
    - string endpoint (optional): the storage endpoint to be used to look up the file or the storage id, in case of
      multi-instance underlying storage; defaults to 'default'
    '''
    req = flask.request
    # first check if the shared secret matches ours
    if req.headers.get('Authorization') != 'Bearer ' + Wopi.iopsecret:
        Wopi.log.warning('msg="cboxLock: unauthorized access attempt, missing authorization token" '
                         'client="%s"' % req.remote_addr)
        return 'Client not authorized', http.client.UNAUTHORIZED
    filename = req.args['filename']
    userid = req.args['userid'] if 'userid' in req.args else '0:0'
    endpoint = req.args['endpoint'] if 'endpoint' in req.args else 'default'
    return core.ioplocks.lock(filename, userid, endpoint, req.method == 'GET')


@Wopi.app.route("/wopi/cbox/unlock", methods=['POST'])
def cboxUnlock():
    '''Unlock a given filename. Used for OnlyOffice as they do not use WOPI (see cboxLock).
    Request arguments:
    - string filename: the full path of the filename to be opened
    - string userid (optional): the user identity to create the file, defaults to 'root:root'
    - string endpoint (optional): the storage endpoint to be used to look up the file or the storage id, in case of
      multi-instance underlying storage; defaults to 'default'
    The call returns:
    - HTTP UNAUTHORIZED (401) if the 'Authorization: Bearer' secret is not provided in the header (cf. /wopi/cbox/open)
    - HTTP CONFLICT (409) if a lock exists, but held by another application
    - HTTP NOT_FOUND (404) if no lock was found for the given file
    - HTTP INTERNAL_SERVER_ERROR (500) if some other I/O error occurred with the given lock file
    - HTTP OK (200) if a lock for OnlyOffice existed. In this case it is removed.
    '''
    req = flask.request
    # first check if the shared secret matches ours
    if req.headers.get('Authorization') != 'Bearer ' + Wopi.iopsecret:
        Wopi.log.warning('msg="cboxUnlock: unauthorized access attempt, missing authorization token" ' \
                         'client="%s"' % req.remote_addr)
        return 'Client not authorized', http.client.UNAUTHORIZED
    filename = req.args['filename']
    userid = req.args['userid'] if 'userid' in req.args else '0:0'
    endpoint = req.args['endpoint'] if 'endpoint' in req.args else 'default'
    return core.ioplocks.unlock(filename, userid, endpoint)


#
# Bridge functionality
#
@Wopi.app.route("/wopi/bridge/open", methods=["GET"])
def bridgeOpen():
    return bridge.appopen()


@Wopi.app.route("/wopi/bridge/<docid>", methods=["POST"])
@Wopi.metrics.do_not_track()
def bridgeSave(docid):
    return bridge.appsave(docid)


@Wopi.app.route("/wopi/bridge/save", methods=["GET"])
@Wopi.metrics.do_not_track()
def bridgeSave_old():
    docid = flask.request.args.get('id')
    return bridge.appsave(docid)


@Wopi.app.route("/wopi/bridge/list", methods=["GET"])
def bridgeList():
    return bridge.applist()


#
# deprecated
#
@Wopi.app.route("/wopi/cbox/download", methods=['GET'])
def cboxDownload():
    '''Returns the file's content for a given valid access token. Used as a download URL,
       so that the file's path is never explicitly visible.'''
    # TODO this endpoint should be removed altogether: the download should be directly served by Reva
    try:
        acctok = jwt.decode(flask.request.args['access_token'], Wopi.wopisecret, algorithms=['HS256'])
        if acctok['exp'] < time.time():
            raise jwt.exceptions.ExpiredSignatureError
        resp = flask.Response(storage.readfile(acctok['endpoint'], acctok['filename'], acctok['userid']), \
                              mimetype='application/octet-stream')
        resp.headers['Content-Disposition'] = 'attachment; filename="%s"' % os.path.basename(acctok['filename'])
        resp.status_code = http.client.OK
        Wopi.log.info('msg="cboxDownload: direct download succeeded" filename="%s" user="%s" token="%s"' %
                      (acctok['filename'], acctok['userid'], flask.request.args['access_token'][-20:]))
        return resp
    except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError) as e:
        Wopi.log.warning('msg="Signature verification failed" client="%s" requestedUrl="%s" token="%s"' %
                         (flask.request.remote_addr, flask.request.base_url, flask.request.args['access_token']))
        return 'Invalid access token', http.client.NOT_FOUND
    except IOError as e:
        Wopi.log.info('msg="Requested file not found" filename="%s" token="%s" error="%s"' %
                      (acctok['filename'], flask.request.args['access_token'][-20:], e))
        return 'File not found', http.client.NOT_FOUND
    except KeyError as e:
        Wopi.log.error('msg="Invalid access token or request argument" error="%s"' % e)
        return 'Invalid access token', http.client.UNAUTHORIZED



#
# Start the Flask endless listening loop
#
if __name__ == '__main__':
    Wopi.init()
    core.discovery.initappsregistry()    # TODO to be removed
    Wopi.run()
