'''
wopimetrics.py

Prometheus metrics of the WOPI server, exposed on the authenticated /metrics endpoint.
Labels only take values from fixed sets: never label with user, file name, inode, path, token or session.
'''

import os
import hmac
import logging
import functools
import http.client
import flask
import prometheus_client
from prometheus_client.core import GaugeMetricFamily
from prometheus_flask_exporter import PrometheusMetrics

# all metrics are registered on the registry used by the PrometheusMetrics exporter
registry = prometheus_client.REGISTRY

# the known app names, as configured in the app providers; any other appname is accounted as `other`
DEFAULTAPPS = 'MS365 Collabora CodiMD EuroOffice Etherpad'
OTHER = 'other'

# map of ViewMode values to the `mode` label
_MODES = {
    'VIEW_MODE_READ_WRITE': 'write',
    'VIEW_MODE_READ_ONLY': 'read',
    'VIEW_MODE_VIEW_ONLY': 'view',
    'VIEW_MODE_PREVIEW': 'preview',
    'VIEW_MODE_EMBEDDED': 'embedded',
}

# the fine-grained file types, with templates folded into the type they are a template of
_FILETYPES = ('doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp', 'md', 'zmd')
_TEMPLATES = {'dot': 'doc', 'dotx': 'docx', 'xlt': 'xls', 'xltx': 'xlsx', 'pot': 'ppt', 'potx': 'pptx',
              'ott': 'odt', 'ots': 'ods', 'otp': 'odp'}

# the user types, see utils.UserType, plus public links
_USERTYPES = ('regular', 'federated', 'ocm', 'anonymous')
PUBLINK = 'publink'

# the reasons of known false positive conflicts with MS365
_MS365REASONS = ('The file is locked by MS365', 'Cannot overwrite file locked by MS365')

# the storage operations being timed
STORAGEOPS = ('stat', 'read', 'write', 'lock', 'unlock', 'xattr', 'remove', 'rename', 'other')

# module-wide state, set by init()
_apps = DEFAULTAPPS.split()
_token = None
_loghandler = None
_srv = None

opens = prometheus_client.Counter(
    'wopi_opens', 'Number of access tokens generated to open a file',
    ['app', 'mode', 'filetype', 'user_type'], registry=registry)
saves = prometheus_client.Counter(
    'wopi_saves', 'Number of PutFile operations, with result ok, error, or recovery when a copy was stored locally',
    ['app', 'filetype', 'result'], registry=registry)
sessions = prometheus_client.Counter(
    'wopi_sessions', 'Number of WOPI calls with a valid access token', ['app'], registry=registry)
conflicts = prometheus_client.Counter(
    'wopi_conflicts', 'Number of lock conflicts returned to the apps, by kind: external lock, '
    'known MS365 false positive, or other', ['app', 'kind'], registry=registry)
storagelatency = prometheus_client.Histogram(
    'wopi_storage_request_duration_seconds', 'Latency of the requests to the storage', ['op'],
    buckets=(.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30), registry=registry)
conflictresolution = prometheus_client.Histogram(
    'wopi_conflict_resolution_seconds', 'Time taken by a conflicted session to get resolved',
    buckets=(1, 5, 15, 30, 60, 120, 300, 600, 1800, 3600, 4 * 3600, 24 * 3600), registry=registry)
logmessages = prometheus_client.Counter(
    'wopi_log_messages', 'Number of log messages at level WARNING or above', ['level'], registry=registry)


class _StateCollector:
    '''Exposes gauges computed at scrape time from the in-memory maps of the WOPI server'''
    def collect(self):
        openfiles = GaugeMetricFamily('wopi_open_files', 'Number of files currently open', labels=['app', 'mode'])
        csessions = GaugeMetricFamily('wopi_conflicted_sessions', 'Number of conflicted sessions', labels=['state'])
        users = GaugeMetricFamily('wopi_active_users', 'Number of users who opened a file since the server started')
        if _srv:
            counts = {}
            # take a copy of the values as the maps are updated concurrently by the server threads
            for f in list(_srv.openfiles.values()):
                counts[(f[2], f[3])] = counts.get((f[2], f[3]), 0) + 1
            for (app, mode), n in counts.items():
                openfiles.add_metric([app, mode], n)
            for state in ('pending', 'resolved'):
                csessions.add_metric([state], len(_srv.conflictsessions[state]))
            users.add_metric([], len(_srv.allusers))
        yield openfiles
        yield csessions
        yield users


class _LogCounter(logging.Handler):
    '''A logging handler counting the messages at level WARNING or above'''
    def __init__(self):
        super().__init__(level=logging.WARNING)

    def emit(self, record):
        logmessages.labels(record.levelname.lower()).inc()


registry.register(_StateCollector())
# expose the log counters from zero
for _level in ('warning', 'error', 'critical'):
    logmessages.labels(_level)


def init(config, logger, srv=None):
    '''Initializes the metrics from the configuration: loads the /metrics token and attaches the log counter
    to the given logger. Can be called again to reload the configuration'''
    global _apps, _token, _loghandler, _srv    # pylint: disable=global-statement
    if srv:
        _srv = srv
    _apps = config.get('monitoring', 'metricsapps', fallback=DEFAULTAPPS).split()
    _token = None
    tokenfile = config.get('monitoring', 'metricstokenfile', fallback='')
    if tokenfile:
        with open(tokenfile) as f:
            _token = f.read().strip() or None
        if not _token:
            raise ValueError(f'Empty metrics token in {tokenfile}')
    if _loghandler:
        # drop the handler attached by a previous call
        _loghandler[0].removeHandler(_loghandler[1])
    _loghandler = (logger, _LogCounter())
    logger.addHandler(_loghandler[1])


def authenticate(view):
    '''Decorator for the /metrics view: 404 if no token is configured, 401 if the bearer token does not match.
    The rejected requests are not tracked in the default request metrics either'''
    @PrometheusMetrics.do_not_track()
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if not _token:
            return 'Not found', http.client.NOT_FOUND
        auth = flask.request.headers.get('Authorization', '')
        if not auth.startswith('Bearer ') or not hmac.compare_digest(auth[7:].encode(), _token.encode()):
            return 'Client not authorized', http.client.UNAUTHORIZED
        return view(*args, **kwargs)
    return wrapper


def normapp(appname):
    '''Normalizes the given appname to one of the configured app names, or `other`'''
    if not appname:
        return OTHER
    if appname in _apps:
        return appname
    for a in _apps:
        if a.lower() in appname.lower():
            return a
    return OTHER


def filetype(filename):
    '''Maps the extension of the given filename to the fine-grained file types, or `others`'''
    fext = os.path.splitext(filename)[1][1:].lower()
    fext = _TEMPLATES.get(fext, fext)
    return fext if fext in _FILETYPES else 'others'


def viewmode(vm):
    '''Maps a ViewMode (or its value) to the `mode` label'''
    return _MODES.get(getattr(vm, 'value', vm), OTHER)


def usertype(ut, folderurl=''):
    '''Maps a UserType (or its value) and the folderurl to the `user_type` label'''
    if '/files/link/public/' in (folderurl or ''):
        return PUBLINK
    ut = getattr(ut, 'value', ut)
    return ut if ut in _USERTYPES else 'regular'


def countopen(appname, vm, filename, ut, folderurl):
    opens.labels(normapp(appname), viewmode(vm), filetype(filename), usertype(ut, folderurl)).inc()


def countsave(acctok, result):
    saves.labels(normapp(acctok.get('appname')), filetype(acctok['filename']), result).inc()


def countsession(appname):
    sessions.labels(normapp(appname)).inc()


def countconflict(appname, retrievedlock, reason, externallocks):
    if retrievedlock in externallocks:
        kind = 'external'
    elif reason in _MS365REASONS:
        kind = 'ms365'
    else:
        kind = 'other'
    conflicts.labels(normapp(appname), kind).inc()


def observeresolution(seconds):
    conflictresolution.observe(max(seconds, 0))


def _storageop(op):
    return storagelatency.labels(op if op in STORAGEOPS else OTHER)


def observestorage(op, seconds):
    _storageop(op).observe(seconds)


def timestorage(op):
    '''Context manager timing a storage operation'''
    return _storageop(op).time()
