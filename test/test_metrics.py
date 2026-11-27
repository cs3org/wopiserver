'''
test_metrics.py

Unit tests of the Prometheus metrics exposed on /metrics, using Flask's test client
against the local storage interface. Run with `pytest` from the root of the git repo.
'''

import sys
import os
import time
import shutil
import secrets
import tempfile
import unittest
import configparser
from unittest import mock
from prometheus_client.parser import text_string_to_metric_families
sys.path.append('src')         # for tests out of the git repo
sys.path.append('/app')        # for tests within the Docker image
import wopiserver  # noqa: E402
import core.wopi  # noqa: E402
import core.wopiutils as utils  # noqa: E402
import core.localiface as localiface  # noqa: E402
import core.commoniface as commoniface  # noqa: E402
import core.wopimetrics as wopimetrics  # noqa: E402

Wopi = wopiserver.Wopi

WOPI_FAMILIES = ('wopi_opens', 'wopi_saves', 'wopi_sessions', 'wopi_conflicts',
                 'wopi_storage_request_duration_seconds', 'wopi_open_files', 'wopi_conflicted_sessions',
                 'wopi_active_users', 'wopi_conflict_resolution_seconds', 'wopi_log_messages')


def _makeconfig(tmpdir, tokenfile=None):
    config = configparser.ConfigParser()
    config.read_dict({
        'general': {
            'storagetype': 'local',
            'port': '8880',
            'loglevel': 'Debug',
            'wopiurl': 'http://localhost:8880',
            'tokenvalidity': '86400',
            'wopilockexpiration': '1800',
        },
        'security': {'usehttps': 'no'},
        'io': {'chunksize': '4096'},
        'apps': {},
        'local': {'storagehomepath': os.path.join(tmpdir, 'storage')},
        'monitoring': {'metricstokenfile': tokenfile} if tokenfile else {},
    })
    return config


class TestMetrics(unittest.TestCase):
    '''Tests for the native usage metrics of the WOPI server'''

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix='wopiserver-test-')
        os.makedirs(os.path.join(cls.tmpdir, 'storage'))
        os.makedirs(os.path.join(cls.tmpdir, 'recovery'))
        cls.token = secrets.token_urlsafe(32)
        cls.tokenfile = os.path.join(cls.tmpdir, 'metricstoken')
        with open(cls.tokenfile, 'w') as f:
            f.write(cls.token + '\n')
        cls.config = _makeconfig(cls.tmpdir, cls.tokenfile)

        # set up the server state as Wopi.init() does, without reading /etc/wopi
        Wopi.config = cls.config
        Wopi.log.setLevel('DEBUG')
        Wopi.lastConfigReadTime = time.time() + 1e9    # never re-read the config from /etc/wopi
        Wopi.wopisecret = secrets.token_hex(16)
        Wopi.iopsecret = secrets.token_hex(16)
        Wopi.port = 8880
        Wopi.useHttps = False
        Wopi.wopiurl = 'http://localhost:8880'
        Wopi.homepath = '/'
        Wopi.recoverypath = os.path.join(cls.tmpdir, 'recovery')
        Wopi.wopiproxy = ''
        Wopi.wopiproxykey = None
        Wopi.proxiedappname = ''
        Wopi.nonofficetypes = []
        Wopi.codetypes = ['.odt', '.ods', '.odp']
        # the storage interfaces keep module-wide state, shared with the other tests
        cls.savedstorage = (localiface.config, localiface.log, localiface.homepath, commoniface.config)
        localiface.init(cls.config, Wopi.log)
        wopiserver.storage = localiface
        utils.WOPIVER = 'test'
        utils.srv = core.wopi.srv = Wopi
        utils.log = core.wopi.log = Wopi.log
        utils.st = core.wopi.st = localiface
        wopimetrics.init(cls.config, Wopi.log.logger, Wopi)
        cls.client = Wopi.app.test_client()

    @classmethod
    def tearDownClass(cls):
        localiface.config, localiface.log, localiface.homepath, commoniface.config = cls.savedstorage
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def setUp(self):
        Wopi.openfiles.clear()
        Wopi.conflictsessions['pending'].clear()
        Wopi.conflictsessions['resolved'].clear()

    # helpers

    def _scrape(self):
        '''Scrapes /metrics and returns the parsed families and a {(name, labels): value} map of the samples'''
        resp = self.client.get('/metrics', headers={'Authorization': 'Bearer ' + self.token})
        self.assertEqual(resp.status_code, 200)
        families = {}
        samples = {}
        for fam in text_string_to_metric_families(resp.get_data(as_text=True)):
            families[fam.name] = fam
            for s in fam.samples:
                samples[(s.name, tuple(sorted(s.labels.items())))] = s.value
        return families, samples

    def _value(self, name, **labels):
        _, samples = self._scrape()
        return samples.get((name, tuple(sorted(labels.items()))), 0.0)

    def _sum(self, name, **labels):
        '''Sum of all samples of the given name matching the given labels'''
        _, samples = self._scrape()
        return sum(v for (n, lbls), v in samples.items()
                   if n == name and all(dict(lbls).get(k) == lv for k, lv in labels.items()))

    def _mkfile(self, name, content=b'some content'):
        with open(os.path.join(self.tmpdir, 'storage', name), 'wb') as f:
            f.write(content)
        return '/' + name

    def _open(self, fname, appname='MS365', viewmode='VIEW_MODE_READ_WRITE', folderurl='/', usertype='regular'):
        '''Calls /wopi/iop/openinapp and returns (fileid, access token)'''
        resp = self.client.get('/wopi/iop/openinapp', query_string={
            'fileid': fname, 'viewmode': viewmode, 'appname': appname, 'appurl': 'https://app.example.org/edit',
            'folderurl': folderurl, 'usertype': usertype, 'username': 'Test User', 'userid': 'testuser',
        }, headers={'Authorization': 'Bearer ' + Wopi.iopsecret, 'TokenHeader': 'reva-token'})
        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        acctok = resp.get_json()['form-parameters']['access_token']
        wopisrc = resp.get_json()['app-url'].split('WOPISrc=')[1]
        fileid = wopisrc.split('%2F')[-1]
        return fileid, acctok

    def _wopipost(self, fileid, acctok, op, lock, session=None, oldlock=None):
        headers = {'X-WOPI-Override': op, 'X-WOPI-Lock': lock}
        if session:
            headers['X-WOPI-SessionId'] = session
        if oldlock:
            headers['X-WOPI-OldLock'] = oldlock
        return self.client.post(f'/wopi/files/{fileid}', query_string={'access_token': acctok}, headers=headers)

    def _putfile(self, fileid, acctok, lock, data=b'new content'):
        return self.client.post(f'/wopi/files/{fileid}/contents', query_string={'access_token': acctok},
                                headers={'X-WOPI-Lock': lock}, data=data)

    # /metrics authentication

    def test_metrics_no_token(self):
        resp = self.client.get('/metrics')
        self.assertEqual(resp.status_code, 401)
        self.assertNotIn(b'wopi_', resp.get_data())

    def test_metrics_wrong_token(self):
        resp = self.client.get('/metrics', headers={'Authorization': 'Bearer not-the-token'})
        self.assertEqual(resp.status_code, 401)
        resp = self.client.get('/metrics', headers={'Authorization': self.token})
        self.assertEqual(resp.status_code, 401)

    def test_metrics_right_token(self):
        families, _ = self._scrape()
        for fam in WOPI_FAMILIES:
            self.assertIn(fam, families)
        # the legacy counter is gone, replaced by wopi_opens_total
        self.assertNotIn('open_by_app', families)
        # the default per-endpoint request metrics are still there
        self.assertIn('flask_http_request_duration_seconds', families)

    def test_metrics_disabled(self):
        try:
            wopimetrics.init(_makeconfig(self.tmpdir), Wopi.log.logger)
            resp = self.client.get('/metrics', headers={'Authorization': 'Bearer ' + self.token})
            self.assertEqual(resp.status_code, 404)
        finally:
            wopimetrics.init(self.config, Wopi.log.logger)
        self._scrape()

    # opens

    def test_opens(self):
        fn = self._mkfile('open.docx')
        labels = {'app': 'MS365', 'mode': 'write', 'filetype': 'docx', 'user_type': 'regular'}
        before = self._value('wopi_opens_total', **labels)
        stats = self._value('wopi_storage_request_duration_seconds_count', op='stat')
        self._open(fn)
        self.assertEqual(self._value('wopi_opens_total', **labels), before + 1)
        self.assertGreater(self._value('wopi_storage_request_duration_seconds_count', op='stat'), stats)
        self.assertGreaterEqual(self._value('wopi_active_users'), 1)

    def test_opens_publink(self):
        fn = self._mkfile('publink.xlsx')
        labels = {'app': 'Collabora', 'mode': 'read', 'filetype': 'xlsx', 'user_type': 'publink'}
        before = self._value('wopi_opens_total', **labels)
        self._open(fn, appname='Collabora', viewmode='VIEW_MODE_READ_ONLY', usertype='anonymous',
                   folderurl='https://cernbox.example.org/files/link/public/AbCdEf')
        self.assertEqual(self._value('wopi_opens_total', **labels), before + 1)

    def test_opens_unknown_app_and_template(self):
        fn = self._mkfile('template.potx')
        labels = {'app': 'other', 'mode': 'view', 'filetype': 'pptx', 'user_type': 'federated'}
        before = self._value('wopi_opens_total', **labels)
        self._open(fn, appname='SomeUnknownApp', viewmode='VIEW_MODE_VIEW_ONLY', usertype='federated')
        self.assertEqual(self._value('wopi_opens_total', **labels), before + 1)
        _, samples = self._scrape()
        self.assertFalse([k for k in samples if ('app', 'SomeUnknownApp') in k[1]])

    # sessions, saves and open files

    def test_save_and_open_files(self):
        fn = self._mkfile('save.docx')
        fileid, acctok = self._open(fn)
        sessions = self._value('wopi_sessions_total', app='MS365')
        saves = self._value('wopi_saves_total', app='MS365', filetype='docx', result='ok')
        self.assertEqual(self._value('wopi_open_files', app='MS365', mode='write'), 0)

        resp = self._wopipost(fileid, acctok, 'LOCK', 'lock-save', session='s-save')
        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        self.assertEqual(self._value('wopi_open_files', app='MS365', mode='write'), 1)

        resp = self._putfile(fileid, acctok, 'lock-save')
        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        self.assertEqual(self._value('wopi_saves_total', app='MS365', filetype='docx', result='ok'), saves + 1)
        self.assertEqual(self._value('wopi_open_files', app='MS365', mode='write'), 1)

        resp = self._wopipost(fileid, acctok, 'UNLOCK', 'lock-save', session='s-save')
        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        self.assertEqual(self._value('wopi_open_files', app='MS365', mode='write'), 0)
        # LOCK, PutFile, UNLOCK
        self.assertEqual(self._value('wopi_sessions_total', app='MS365'), sessions + 3)

    def test_save_recovery(self):
        fn = self._mkfile('recovery.docx')
        fileid, acctok = self._open(fn)
        resp = self._wopipost(fileid, acctok, 'LOCK', 'lock-rec')
        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        labels = {'app': 'MS365', 'filetype': 'docx'}
        rec = self._value('wopi_saves_total', result='recovery', **labels)
        ok = self._value('wopi_saves_total', result='ok', **labels)
        with mock.patch.object(localiface, 'writefile', side_effect=IOError('Simulated storage failure')):
            resp = self._putfile(fileid, acctok, 'lock-rec')
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(len(os.listdir(Wopi.recoverypath)), 1)
        self.assertEqual(self._value('wopi_saves_total', result='recovery', **labels), rec + 1)
        self.assertEqual(self._value('wopi_saves_total', result='ok', **labels), ok)

    def test_save_error(self):
        fn = self._mkfile('error.docx')
        fileid, acctok = self._open(fn)
        resp = self._wopipost(fileid, acctok, 'LOCK', 'lock-err')
        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        labels = {'app': 'MS365', 'filetype': 'docx', 'result': 'error'}
        err = self._value('wopi_saves_total', **labels)
        recpath = Wopi.recoverypath
        Wopi.recoverypath = os.path.join(self.tmpdir, 'missing-recovery-dir')
        try:
            with mock.patch.object(localiface, 'writefile', side_effect=IOError('Simulated storage failure')):
                resp = self._putfile(fileid, acctok, 'lock-err')
        finally:
            Wopi.recoverypath = recpath
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(self._value('wopi_saves_total', **labels), err + 1)

    # conflicts

    def test_conflict_external(self):
        fn = self._mkfile('ext.docx')
        fileid, acctok = self._open(fn)
        # an MS Office for Desktop lock appears after the file was opened online
        self._mkfile('~$ext.docx', b'desktop lock')
        before = self._value('wopi_conflicts_total', app='MS365', kind='external')
        resp = self._putfile(fileid, acctok, 'lock-ext')
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(self._value('wopi_conflicts_total', app='MS365', kind='external'), before + 1)

    def test_conflict_ms365_and_resolution(self):
        fn = self._mkfile('ms365.docx')
        fileid, acctok = self._open(fn)
        resp = self._wopipost(fileid, acctok, 'LOCK', 'lock-one', session='s-one')
        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        ms365 = self._value('wopi_conflicts_total', app='MS365', kind='ms365')
        other = self._value('wopi_conflicts_total', app='MS365', kind='other')
        resolutions = self._value('wopi_conflict_resolution_seconds_count')

        # a different lock from another session: the false positive 'The file is locked by MS365'
        resp = self._wopipost(fileid, acctok, 'LOCK', 'lock-two', session='s-two')
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.headers['X-WOPI-LockFailureReason'], 'The file is locked by MS365')
        self.assertEqual(self._value('wopi_conflicts_total', app='MS365', kind='ms365'), ms365 + 1)
        self.assertEqual(self._value('wopi_conflicted_sessions', state='pending'), 1)

        # an unlock with the wrong lock is any other conflict
        resp = self._wopipost(fileid, acctok, 'UNLOCK', 'lock-wrong', session='s-three')
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(self._value('wopi_conflicts_total', app='MS365', kind='other'), other + 1)

        # the conflicted session joins with the right lock: it gets resolved
        resp = self._wopipost(fileid, acctok, 'LOCK', 'lock-one', session='s-two')
        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        self.assertEqual(self._value('wopi_conflicted_sessions', state='resolved'), 1)
        self.assertEqual(self._value('wopi_conflict_resolution_seconds_count'), resolutions + 1)

    # log messages

    def test_log_messages(self):
        errors = self._value('wopi_log_messages_total', level='error')
        total = self._sum('wopi_log_messages_total')
        Wopi.log.info('msg="Metrics test: an info message"')
        self.assertEqual(self._sum('wopi_log_messages_total'), total)
        Wopi.log.error('msg="Metrics test: an error message"')
        self.assertEqual(self._value('wopi_log_messages_total', level='error'), errors + 1)

    # unit tests of the label normalization

    def test_normalization(self):
        self.assertEqual(wopimetrics.normapp('MS365'), 'MS365')
        self.assertEqual(wopimetrics.normapp('Collabora Online'), 'Collabora')
        self.assertEqual(wopimetrics.normapp(''), 'other')
        self.assertEqual(wopimetrics.normapp(None), 'other')
        self.assertEqual(wopimetrics.filetype('/a/b/Report.DOCX'), 'docx')
        self.assertEqual(wopimetrics.filetype('/a/b/notes.zmd'), 'zmd')
        self.assertEqual(wopimetrics.filetype('/a/b/letter.dot'), 'doc')
        self.assertEqual(wopimetrics.filetype('/a/b/archive.tar.gz'), 'others')
        self.assertEqual(wopimetrics.filetype('/a/b/noext'), 'others')


if __name__ == '__main__':
    unittest.main()
