'''
test_storageiface.py

Basic unit testing of the storage interfaces. To run them, please make sure the
wopiserver-test.conf is correctly configured (see /README.md). The storage layer
to be tested can be overridden by the WOPI_STORAGE env variable.

Main author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

import unittest
import logging
import configparser
import sys
import os
import time
from threading import Thread
from getpass import getpass
sys.path.append('src')         # for tests out of the git repo
sys.path.append('/app')        # for tests within the Docker image
from core.commoniface import EXCL_ERROR, ENOENT_MSG  # noqa: E402

databuf = 'ebe5tresbsrdthbrdhvdtr'


class TestStorage(unittest.TestCase):
    '''Simple tests for the storage layers of the WOPI server. See README for how to run the tests for each storage provider'''
    initialized = False
    storagetype = None
    log = None

    @classmethod
    def globalinit(cls):
        '''One-off initialization of the test environment: create mock logging and import the library'''
        loghandler = logging.FileHandler('/tmp/wopiserver-test.log')
        loghandler.setFormatter(logging.Formatter(fmt='%(asctime)s %(name)s[%(process)d] %(levelname)-8s %(message)s',
                                                  datefmt='%Y-%m-%dT%H:%M:%S'))
        cls.log = logging.getLogger('wopiserver.test')
        cls.log.addHandler(loghandler)
        cls.log.setLevel(logging.DEBUG)
        config = configparser.ConfigParser()
        try:
            with open('test/wopiserver-test.conf') as fdconf:
                config.read_file(fdconf)
            storagetype = os.environ.get('WOPI_STORAGE')
            if not storagetype:
                storagetype = config.get('general', 'storagetype')
            cls.userid = config.get(storagetype, 'userid')
            cls.endpoint = config.get(storagetype, 'endpoint')
            cls.storagetype = storagetype
        except (KeyError, configparser.NoOptionError):
            print("Missing option or missing configuration, check the wopiserver-test.conf file")
            raise

        # this is adapted from wopiserver.py::storage_layer_import
        if storagetype in ['local', 'xroot', 'cs3']:
            storagetype += 'iface'
        else:
            raise ImportError(f'Unsupported/Unknown storage type {storagetype}')
        try:
            cls.storage = __import__('core.' + storagetype, globals(), locals(), [storagetype])
            cls.storage.init(config, cls.log)
            cls.homepath = ''
            cls.username = ''
            if 'cs3' in storagetype:
                # we need to login for this case
                cls.username = cls.userid
                pwd = getpass(f"Please type {cls.username}'s password to access the storage: ")
                cls.userid = cls.storage.authenticate_for_test(cls.username, pwd)
                cls.homepath = config.get('cs3', 'storagehomepath')
        except ImportError:
            print(f"Missing module when attempting to import {storagetype}. Please make sure dependencies are met.")
            raise
        print(f'Global initialization succeded for storage interface {storagetype}, starting unit tests')
        cls.initialized = True

    def __init__(self, *args, **kwargs):
        '''Initialization of a test'''
        super().__init__(*args, **kwargs)
        if not TestStorage.initialized:
            TestStorage.globalinit()
        self.userid = TestStorage.userid
        self.endpoint = TestStorage.endpoint
        self.storage = TestStorage.storage
        self.homepath = TestStorage.homepath
        self.username = TestStorage.username
        self.log = TestStorage.log

    def test_stat(self):
        '''Call stat() and assert the path matches'''
        self.storage.writefile(self.endpoint, self.homepath + '/test.txt', self.userid, databuf, -1, None)
        statInfo = self.storage.stat(self.endpoint, self.homepath + '/test.txt', self.userid)
        self.assertIsInstance(statInfo, dict)
        self.assertTrue('mtime' in statInfo, 'Missing mtime from stat output')
        self.assertTrue('size' in statInfo, 'Missing size from stat output')
        self.storage.removefile(self.endpoint, self.homepath + '/test.txt', self.userid)

    def test_statx_fileid(self):
        '''Call statx() and test if fileid-based stat is supported'''
        self.storage.writefile(self.endpoint, self.homepath + '/test.txt', self.userid, databuf, -1, None)
        statInfo = self.storage.statx(self.endpoint, self.homepath + '/test.txt', self.userid)
        self.assertTrue('inode' in statInfo, 'Missing inode from statx output')
        self.assertTrue('filepath' in statInfo, 'Missing filepath from statx output')
        self.assertTrue('ownerid' in statInfo, 'Missing ownerid from stat output')
        self.assertTrue('size' in statInfo, 'Missing size from stat output')
        self.assertTrue('mtime' in statInfo, 'Missing mtime from stat output')
        self.assertTrue('etag' in statInfo, 'Missing etag from stat output')
        self.assertTrue('xattrs' in statInfo, 'Missing xattrs from stat output')
        self.storage.removefile(self.endpoint, self.homepath + '/test.txt', self.userid)

    def test_statx_invariant_fileid(self):
        '''Call statx() before and after updating a file, and assert the inode did not change'''
        self.storage.writefile(self.endpoint, self.homepath + '/test&upd.txt', self.userid, databuf, -1, None)
        statInfo = self.storage.statx(self.endpoint, self.homepath + '/test&upd.txt', self.userid)
        self.assertIsInstance(statInfo, dict)
        inode = statInfo['inode']
        self.storage.writefile(self.endpoint, self.homepath + '/test&upd.txt', self.userid, databuf, -1, None)
        statInfo = self.storage.statx(self.endpoint, self.homepath + '/test&upd.txt', self.userid)
        self.assertIsInstance(statInfo, dict)
        self.assertEqual(statInfo['inode'], inode, 'Fileid is not invariant to multiple write operations')
        self.storage.removefile(self.endpoint, self.homepath + '/test&upd.txt', self.userid)

    def test_stat_nofile(self):
        '''Call stat() and assert the exception is as expected'''
        with self.assertRaises(IOError) as context:
            self.storage.stat(self.endpoint, self.homepath + '/hopefullynotexisting', self.userid)
        self.assertIn(ENOENT_MSG, str(context.exception))

    def test_statx_nofile(self):
        '''Call statx() and assert the exception is as expected'''
        with self.assertRaises(IOError) as context:
            self.storage.statx(self.endpoint, self.homepath + '/hopefullynotexisting', self.userid)
        self.assertIn(ENOENT_MSG, str(context.exception))

    def test_readfile_bin(self):
        '''Writes a binary file and reads it back, validating that the content matches'''
        self.storage.writefile(self.endpoint, self.homepath + '/test.txt', self.userid, databuf, -1, None)
        content = ''
        for chunk in self.storage.readfile(self.endpoint, self.homepath + '/test.txt', self.userid, None):
            content += chunk.decode('utf-8')
        self.assertEqual(content, databuf, f'File test.txt should contain the string "{databuf}"')
        self.storage.removefile(self.endpoint, self.homepath + '/test.txt', self.userid)

    def test_readfile_text(self):
        '''Writes a text file and reads it back, validating that the content matches'''
        content = 'bla\n'
        self.storage.writefile(self.endpoint, self.homepath + '/test.txt', self.userid, content, -1, None)
        content = ''
        for chunk in self.storage.readfile(self.endpoint, self.homepath + '/test.txt', self.userid, None):
            content += chunk.decode('utf-8')
        self.assertEqual(content, 'bla\n', 'File test.txt should contain the text "bla\\n"')
        self.storage.removefile(self.endpoint, self.homepath + '/test.txt', self.userid)

    def test_readfile_empty(self):
        '''Writes an empty file and reads it back, validating that the read does not fail'''
        content = ''
        self.storage.writefile(self.endpoint, self.homepath + '/test.txt', self.userid, content, -1, None)
        for chunk in self.storage.readfile(self.endpoint, self.homepath + '/test.txt', self.userid, None):
            content += chunk.decode('utf-8')
        self.assertEqual(content, '', 'File test.txt should be empty')
        self.storage.removefile(self.endpoint, self.homepath + '/test.txt', self.userid)

    def test_read_nofile(self):
        '''Test reading of a non-existing file'''
        with self.assertRaises(IOError) as context:
            next(self.storage.readfile(self.endpoint, self.homepath + '/hopefullynotexisting', self.userid, None))
        self.assertIn(ENOENT_MSG, str(context.exception))

    def test_write_remove_specialchars(self):
        '''Test write and removal of a file with special chars'''
        self.storage.writefile(self.endpoint, self.homepath + '/testwrite&rm', self.userid, databuf, -1, None)
        statInfo = self.storage.stat(self.endpoint, self.homepath + '/testwrite&rm', self.userid)
        self.assertIsInstance(statInfo, dict)
        self.storage.removefile(self.endpoint, self.homepath + '/testwrite&rm', self.userid)
        with self.assertRaises(IOError):
            self.storage.stat(self.endpoint, self.homepath + '/testwrite&rm', self.userid)

    def test_write_noversion(self):
        '''Writes a text file and overwrites it again with the noversion flag on, validating that the content matches (no check is performed on the versioned file)'''
        content = 'bla\n'
        self.storage.writefile(self.endpoint, self.homepath + '/test.txt', self.userid, content, -1, None)
        content = 'blabla\n'
        self.storage.writefile(self.endpoint, self.homepath + '/test.txt', self.userid, content, -1, None, noversion=True)
        content = ''
        for chunk in self.storage.readfile(self.endpoint, self.homepath + '/test.txt', self.userid, None):
            content += chunk.decode('utf-8')
        self.assertEqual(content, 'blabla\n', 'File test.txt should contain the text "bla\\n"')
        self.storage.removefile(self.endpoint, self.homepath + '/test.txt', self.userid)

    def test_write_islock(self):
        '''Test double write with the islock flag'''
        if self.storagetype == 'cs3':
            self.log.warning('Skipping test_write_islock for storagetype cs3')
            return
        try:
            self.storage.removefile(self.endpoint, self.homepath + '/testoverwrite', self.userid)
        except IOError:
            pass
        self.storage.writefile(self.endpoint, self.homepath + '/testoverwrite', self.userid, databuf, -1, None, islock=True)
        statInfo = self.storage.stat(self.endpoint, self.homepath + '/testoverwrite', self.userid)
        self.assertIsInstance(statInfo, dict)
        with self.assertRaises(IOError) as context:
            self.storage.writefile(self.endpoint, self.homepath + '/testoverwrite', self.userid, databuf, -1, None, islock=True)
        self.assertIn(EXCL_ERROR, str(context.exception))
        self.storage.removefile(self.endpoint, self.homepath + '/testoverwrite', self.userid)

    def test_write_race(self):
        '''Test multithreaded double write with the islock flag. Might fail as it relies on tight timing'''
        if self.storagetype == 'cs3':
            self.log.warning('Skipping test_write_race for storagetype cs3')
            return
        try:
            self.storage.removefile(self.endpoint, self.homepath + '/testwriterace', self.userid)
        except IOError:
            pass
        t = Thread(target=self.storage.writefile,
                   args=[self.endpoint, self.homepath + '/testwriterace', self.userid, databuf, -1, None],
                   kwargs={'islock': True})
        t.start()
        with self.assertRaises(IOError) as context:
            time.sleep(0.001)
            self.storage.writefile(self.endpoint, self.homepath + '/testwriterace', self.userid, databuf, -1, None, islock=True)
        self.assertIn(EXCL_ERROR, str(context.exception))
        t.join()
        self.storage.removefile(self.endpoint, self.homepath + '/testwriterace', self.userid)

    def test_lock(self):
        '''Test setting lock'''
        try:
            self.storage.removefile(self.endpoint, self.homepath + '/testlock', self.userid)
        except IOError:
            pass
        self.storage.writefile(self.endpoint, self.homepath + '/testlock', self.userid, databuf, -1, None)
        statInfo = self.storage.stat(self.endpoint, self.homepath + '/testlock', self.userid)
        self.assertIsInstance(statInfo, dict)
        self.storage.setlock(self.endpoint, self.homepath + '/testlock', self.userid, 'test app', 'testlock')
        l = self.storage.getlock(self.endpoint, self.homepath + '/testlock', self.userid)  # noqa: E741
        self.assertIsInstance(l, dict)
        self.assertEqual(l['lock_id'], 'testlock')
        self.assertEqual(l['app_name'], 'test app')
        self.assertIsInstance(l['expiration'], dict)
        self.assertIsInstance(l['expiration']['seconds'], int)
        with self.assertRaises(IOError) as context:
            self.storage.setlock(self.endpoint, self.homepath + '/testlock', self.userid, 'mismatched app', 'mismatchlock')
        self.assertIn(EXCL_ERROR, str(context.exception))
        self.storage.unlock(self.endpoint, self.homepath + '/testlock', self.userid, 'test app', 'testlock')
        self.storage.removefile(self.endpoint, self.homepath + '/testlock', self.userid)

    def test_refresh_lock(self):
        '''Test refreshing lock'''
        try:
            self.storage.removefile(self.endpoint, self.homepath + '/testrlock', self.userid)
        except IOError:
            pass
        self.storage.writefile(self.endpoint, self.homepath + '/testrlock', self.userid, databuf, -1, None)
        statInfo = self.storage.stat(self.endpoint, self.homepath + '/testrlock', self.userid)
        self.assertIsInstance(statInfo, dict)
        with self.assertRaises(IOError) as context:
            self.storage.refreshlock(self.endpoint, self.homepath + '/testrlock', self.userid, 'test app', 'testlock')
        self.assertEqual(EXCL_ERROR, str(context.exception))
        self.storage.setlock(self.endpoint, self.homepath + '/testrlock', self.userid, 'test app', 'testlock')
        with self.assertRaises(IOError) as context:
            self.storage.refreshlock(self.endpoint, self.homepath + '/testrlock', self.userid, 'test app', 'newlock', 'mismatch')
        self.assertEqual(EXCL_ERROR, str(context.exception))
        self.storage.refreshlock(self.endpoint, self.homepath + '/testrlock', self.userid, 'test app', 'newlock', 'testlock')
        l = self.storage.getlock(self.endpoint, self.homepath + '/testrlock', self.userid)  # noqa: E741
        self.assertIsInstance(l, dict)
        self.assertEqual(l['lock_id'], 'newlock')
        self.assertEqual(l['app_name'], 'test app')
        self.assertIsInstance(l['expiration'], dict)
        self.assertIsInstance(l['expiration']['seconds'], int)
        self.storage.refreshlock(self.endpoint, self.homepath + '/testrlock', self.userid, 'test app', 'newlock')
        with self.assertRaises(IOError) as context:
            self.storage.refreshlock(self.endpoint, self.homepath + '/testrlock', self.userid, 'mismatched app', 'newlock')
        self.assertIn(EXCL_ERROR, str(context.exception))
        self.storage.removefile(self.endpoint, self.homepath + '/testrlock', self.userid)

    def test_lock_race(self):
        '''Test multithreaded setting lock. Might fail as it relies on tight timing'''
        try:
            self.storage.removefile(self.endpoint, self.homepath + '/testlockrace', self.userid)
        except IOError:
            pass
        self.storage.writefile(self.endpoint, self.homepath + '/testlockrace', self.userid, databuf, -1, None)
        statInfo = self.storage.stat(self.endpoint, self.homepath + '/testlockrace', self.userid)
        self.assertIsInstance(statInfo, dict)
        t = Thread(target=self.storage.setlock,
                   args=[self.endpoint, self.homepath + '/testlockrace', self.userid, 'test app', 'testlock'])
        t.start()
        with self.assertRaises(IOError) as context:
            time.sleep(0.001)
            self.storage.setlock(self.endpoint, self.homepath + '/testlockrace', self.userid, 'test app 2', 'testlock2')
        self.assertIn(EXCL_ERROR, str(context.exception))
        self.storage.removefile(self.endpoint, self.homepath + '/testlockrace', self.userid)

    def test_lock_operations(self):
        '''Test file operations on a locked file'''
        try:
            self.storage.removefile(self.endpoint, self.homepath + '/testlockop', self.userid)
        except IOError:
            pass
        self.storage.writefile(self.endpoint, self.homepath + '/testlockop', self.userid, databuf, -1, None)
        statInfo = self.storage.stat(self.endpoint, self.homepath + '/testlockop', self.userid)
        self.assertIsInstance(statInfo, dict)
        self.storage.setlock(self.endpoint, self.homepath + '/testlockop', self.userid, 'test app', 'testlock')
        self.storage.writefile(self.endpoint, self.homepath + '/testlockop', self.userid, databuf, -1, ('test app', 'testlock'))
        with self.assertRaises(IOError):
            # Note that different interfaces raise exceptions on either mismatching app xor mismatching lock payload,
            # this is why we test that both mismatch. Could be improved, though we specifically care about the lock paylaod.
            self.storage.writefile(self.endpoint, self.homepath + '/testlockop', self.userid, databuf, -1,
                                   ('mismatch app', 'mismatchlock'))
        # with xattrs, it's fine to set them without lock context (the lock should apply to files' contents only)
        # BUT the CS3 API does have the possibility to fail a setxattr in case of lock mismatch, so we allow that
        # (cf. https://buf.build/cs3org-buf/cs3apis/docs/main:cs3.storage.provider.v1beta1#cs3.storage.provider.v1beta1.ProviderAPI.SetArbitraryMetadata)  # noqa: E501
        try:
            self.storage.setxattr(self.endpoint, self.homepath + '/testlockop', self.userid, 'testkey', 123,
                                  ('mismatch app', 'mismatchlock'))
        except IOError as e:
            if str(e) == EXCL_ERROR:
                pass
        try:
            self.storage.setxattr(self.endpoint, self.homepath + '/testlockop', self.userid, 'testkey', 123, None)
        except IOError as e:
            if str(e) == EXCL_ERROR:
                pass
        try:
            self.storage.rmxattr(self.endpoint, self.homepath + '/testlockop', self.userid, 'testkey', None)
        except IOError as e:
            if str(e) == EXCL_ERROR:
                pass
        self.storage.refreshlock(self.endpoint, self.homepath + '/testlockop', self.userid, 'test app', 'testlock')
        with self.assertRaises(IOError):
            self.storage.refreshlock(self.endpoint, self.homepath + '/testlockop', self.userid, 'mismatched app', 'mismatchlock')
        next(self.storage.readfile(self.endpoint, self.homepath + '/testlockop', self.userid, None))
        with self.assertRaises(IOError):
            self.storage.writefile(self.endpoint, self.homepath + '/testlockop', self.userid, databuf, -1, None)
        self.storage.renamefile(self.endpoint, self.homepath + '/testlockop', self.homepath + '/testlockop_renamed',
                                self.userid, ('test app', 'testlock'))
        self.storage.removefile(self.endpoint, self.homepath + '/testlockop_renamed', self.userid)

    def test_expired_locks(self):
        '''Test lock operations on expired locks'''
        try:
            self.storage.removefile(self.endpoint, self.homepath + '/testelock', self.userid)
        except IOError:
            pass
        self.storage.writefile(self.endpoint, self.homepath + '/testelock', self.userid, databuf, -1, None)
        statInfo = self.storage.stat(self.endpoint, self.homepath + '/testelock', self.userid)
        self.assertIsInstance(statInfo, dict)
        self.storage.setlock(self.endpoint, self.homepath + '/testelock', self.userid, 'test app', 'testlock')
        time.sleep(3.1)
        l = self.storage.getlock(self.endpoint, self.homepath + '/testelock', self.userid)  # noqa: E741
        self.assertEqual(l, None)
        self.storage.setlock(self.endpoint, self.homepath + '/testelock', self.userid, 'test app', 'testlock2')
        time.sleep(3.1)
        self.storage.setlock(self.endpoint, self.homepath + '/testelock', self.userid, 'test app', 'testlock3')
        l = self.storage.getlock(self.endpoint, self.homepath + '/testelock', self.userid)  # noqa: E741
        self.assertIsInstance(l, dict)
        self.assertEqual(l['lock_id'], 'testlock3')
        time.sleep(3.1)
        with self.assertRaises(IOError) as context:
            self.storage.refreshlock(self.endpoint, self.homepath + '/testelock', self.userid, 'test app', 'testlock4')
        self.assertEqual(EXCL_ERROR, str(context.exception))
        self.storage.setlock(self.endpoint, self.homepath + '/testelock', self.userid, 'test app', 'testlock5')
        time.sleep(3.1)
        with self.assertRaises(IOError) as context:
            self.storage.unlock(self.endpoint, self.homepath + '/testelock', self.userid, 'test app', 'testlock5')
        self.assertEqual(EXCL_ERROR, str(context.exception))
        self.storage.removefile(self.endpoint, self.homepath + '/testelock', self.userid)

    def test_remove_nofile(self):
        '''Test removal of a non-existing file'''
        with self.assertRaises(IOError) as context:
            self.storage.removefile(self.endpoint, self.homepath + '/hopefullynotexisting', self.userid)
        self.assertIn(ENOENT_MSG, str(context.exception))

    def test_xattr(self):
        '''Test all xattr methods with special chars'''
        self.storage.writefile(self.endpoint, self.homepath + '/test&xattr.txt', self.userid, databuf, -1, None)
        self.storage.setxattr(self.endpoint, self.homepath + '/test&xattr.txt', self.userid, 'testkey', 123, None)
        self.storage.setlock(self.endpoint, self.homepath + '/test&xattr.txt', self.userid, 'test app', 'xattrlock')
        self.storage.setxattr(self.endpoint, self.homepath + '/test&xattr.txt', self.userid, 'testkey', 123,
                              ('test app', 'xattrlock'))
        fmd = self.storage.statx(self.endpoint, self.homepath + '/test&xattr.txt', self.userid)
        self.assertEqual(fmd['xattrs']['testkey'], '123')
        self.storage.rmxattr(self.endpoint, self.homepath + '/test&xattr.txt', self.userid, 'testkey', ('test app', 'xattrlock'))
        fmd = self.storage.statx(self.endpoint, self.homepath + '/test&xattr.txt', self.userid)
        self.assertIsNone(fmd['xattrs'].get('testkey'))
        self.storage.removefile(self.endpoint, self.homepath + '/test&xattr.txt', self.userid)

    def test_rename_statx(self):
        '''Test renaming and statx of a file with special chars'''
        self.storage.writefile(self.endpoint, self.homepath + '/test.txt', self.userid, databuf, -1, None)
        statInfo = self.storage.statx(self.endpoint, self.homepath + '/test.txt', self.userid)
        pathref = statInfo['filepath'][:statInfo['filepath'].rfind('/')]

        self.storage.renamefile(self.endpoint, self.homepath + '/test.txt', self.homepath + '/test&ren.txt', self.userid, None)
        statInfo = self.storage.statx(self.endpoint, self.homepath + '/test&ren.txt', self.userid)
        self.assertEqual(statInfo['filepath'], pathref + '/test&ren.txt')
        self.storage.renamefile(self.endpoint, self.homepath + '/test&ren.txt', self.homepath + '/test.txt', self.userid, None)
        statInfo = self.storage.statx(self.endpoint, self.homepath + '/test.txt', self.userid)
        self.assertEqual(statInfo['filepath'], pathref + '/test.txt')
        self.storage.removefile(self.endpoint, self.homepath + '/test.txt', self.userid)


if __name__ == '__main__':
    unittest.main()
