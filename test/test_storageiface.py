'''
test_storageiface.py

Basic unit testing of the storage interfaces. To run them, please make sure the
wopiserver-test.conf is correctly configured (see /README.md). The storage layer
to be tested can be overridden by the WOPI_STORAGE env variable.
'''

import unittest
import logging
import configparser
import sys
import os
from threading import Thread
sys.path.append('src')     # for tests out of the git repo
sys.path.append('/app')    # for tests within the Docker image
from core.commoniface import EXCL_ERROR, ENOENT_MSG

class TestStorage(unittest.TestCase):
  '''Simple tests for the storage layers of the WOPI server. See README for how to run the tests for each storage provider'''

  @classmethod
  def globalinit(cls):
    '''One-off initialization of the test environment: create mock logging and import the library'''
    loghandler = logging.FileHandler('/tmp/wopiserver-test.log')
    loghandler.setFormatter(logging.Formatter(fmt='%(asctime)s %(name)s[%(process)d] %(levelname)-8s %(message)s',
                                              datefmt='%Y-%m-%dT%H:%M:%S'))
    log = logging.getLogger('wopiserver.test')
    log.addHandler(loghandler)
    log.setLevel(logging.DEBUG)
    config = configparser.ConfigParser()
    try:
      with open('test/wopiserver-test.conf') as fdconf:
        config.read_file(fdconf)
      storagetype = os.environ.get('WOPI_STORAGE')
      if not storagetype:
        storagetype = config.get('general', 'storagetype')
      cls.userid = config.get(storagetype, 'userid')
      cls.endpoint = config.get(storagetype, 'endpoint')
    except (KeyError, configparser.NoOptionError):
      print("Missing option or missing configuration, check the wopiserver-test.conf file")
      raise

    # this is adapted from wopiserver.py::storage_layer_import
    if storagetype in ['local', 'xroot', 'cs3']:
      storagetype += 'iface'
    else:
      raise ImportError('Unsupported/Unknown storage type %s' % storagetype)
    try:
      cls.storage = __import__('core.' + storagetype, globals(), locals(), [storagetype])
      cls.storage.init(config, log)
      cls.homepath = ''
      cls.username = ''
      if 'cs3' in storagetype:
        # we need to login for this case
        cls.username = cls.userid
        cls.userid = cls.storage.authenticate_for_test(cls.userid, config.get('cs3', 'userpwd'))
        cls.homepath = config.get('cs3', 'storagehomepath')
    except ImportError:
      print("Missing module when attempting to import %s. Please make sure dependencies are met." % storagetype)
      raise
    print('Global initialization succeded for storage interface %s, starting unit tests' % storagetype)

  def __init__(self, *args, **kwargs):
    '''Initialization of a test'''
    super(TestStorage, self).__init__(*args, **kwargs)
    self.userid = TestStorage.userid
    self.endpoint = TestStorage.endpoint
    self.storage = TestStorage.storage
    self.homepath = TestStorage.homepath
    self.username = TestStorage.username

  def test_stat(self):
    '''Call stat() and assert the path matches'''
    buf = b'bla\n'
    self.storage.writefile(self.endpoint, self.homepath + '/test.txt', self.userid, buf)
    statInfo = self.storage.stat(self.endpoint, self.homepath + '/test.txt', self.userid)
    self.assertIsInstance(statInfo, dict)
    self.assertTrue('mtime' in statInfo, 'Missing mtime from stat output')
    self.assertTrue('size' in statInfo, 'Missing size from stat output')
    self.storage.removefile(self.endpoint, self.homepath + '/test.txt', self.userid)

  def test_statx_fileid(self):
    '''Call statx() and test if fileid-based stat is supported'''
    buf = b'bla\n'
    self.storage.writefile(self.endpoint, self.homepath + '/test.txt', self.userid, buf)
    statInfo = self.storage.statx(self.endpoint, self.homepath + '/test.txt', self.userid)
    if self.endpoint in str(statInfo['inode']):
      # detected CS3 storage, test if fileid-based stat is supported
      # (notably, homepath is not part of the fileid)
      statInfoId = self.storage.stat(self.endpoint, 'fileid-' + self.username + '%2Ftest.txt', self.userid)
      self.assertTrue(statInfo['inode'] == statInfoId['inode'])
    self.storage.removefile(self.endpoint, self.homepath + '/test.txt', self.userid)

  def test_statx_invariant_fileid(self):
    '''Call statx() before and after updating a file, and assert the inode did not change'''
    buf = b'bla\n'
    self.storage.writefile(self.endpoint, self.homepath + '/test.txt', self.userid, buf)
    statInfo = self.storage.statx(self.endpoint, self.homepath + '/test.txt', self.userid, versioninv=1)
    self.assertIsInstance(statInfo, dict)
    inode = statInfo['inode']
    buf = b'blabla\n'
    self.storage.writefile(self.endpoint, self.homepath + '/test.txt', self.userid, buf)
    statInfo = self.storage.statx(self.endpoint, self.homepath + '/test.txt', self.userid, versioninv=1)
    self.assertIsInstance(statInfo, dict)
    self.assertEqual(statInfo['inode'], inode, 'Fileid is not invariant to multiple write operations')
    self.storage.removefile(self.endpoint, self.homepath + '/test.txt', self.userid)

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
    content = b'bla'
    self.storage.writefile(self.endpoint, self.homepath + '/test.txt', self.userid, content)
    content = ''
    for chunk in self.storage.readfile(self.endpoint, self.homepath + '/test.txt', self.userid):
      self.assertNotIsInstance(chunk, IOError, 'raised by storage.readfile')
      content += chunk.decode('utf-8')
    self.assertEqual(content, 'bla', 'File test.txt should contain the string "bla"')
    self.storage.removefile(self.endpoint, self.homepath + '/test.txt', self.userid)

  def test_readfile_text(self):
    '''Writes a text file and reads it back, validating that the content matches'''
    content = 'bla\n'
    self.storage.writefile(self.endpoint, self.homepath + '/test.txt', self.userid, content)
    content = ''
    for chunk in self.storage.readfile(self.endpoint, self.homepath + '/test.txt', self.userid):
      self.assertNotIsInstance(chunk, IOError, 'raised by storage.readfile')
      content += chunk.decode('utf-8')
    self.assertEqual(content, 'bla\n', 'File test.txt should contain the text "bla\\n"')
    self.storage.removefile(self.endpoint, self.homepath + '/test.txt', self.userid)

  def test_readfile_empty(self):
    '''Writes an empty file and reads it back, validating that the read does not fail'''
    content = ''
    self.storage.writefile(self.endpoint, self.homepath + '/test.txt', self.userid, content)
    for chunk in self.storage.readfile(self.endpoint, self.homepath + '/test.txt', self.userid):
      self.assertNotIsInstance(chunk, IOError, 'raised by storage.readfile')
      content += chunk.decode('utf-8')
    self.assertEqual(content, '', 'File test.txt should be empty')
    self.storage.removefile(self.endpoint, self.homepath + '/test.txt', self.userid)

  def test_read_nofile(self):
    '''Test reading of a non-existing file'''
    readex = next(self.storage.readfile(self.endpoint, self.homepath + '/hopefullynotexisting', self.userid))
    self.assertIsInstance(readex, IOError, 'readfile returned %s' % readex)
    self.assertEqual(str(readex), ENOENT_MSG, 'readfile returned %s' % readex)

  def test_write_remove_specialchars(self):
    '''Test write and removal of a file with special chars'''
    buf = b'ebe5tresbsrdthbrdhvdtr'
    self.storage.writefile(self.endpoint, self.homepath + '/testwrite&rm', self.userid, buf)
    statInfo = self.storage.stat(self.endpoint, self.homepath + '/testwrite&rm', self.userid)
    self.assertIsInstance(statInfo, dict)
    self.storage.removefile(self.endpoint, self.homepath + '/testwrite&rm', self.userid)
    with self.assertRaises(IOError):
      self.storage.stat(self.endpoint, self.homepath + '/testwrite&rm', self.userid)

  def test_write_islock(self):
    '''Test double write with the islock flag'''
    buf = b'ebe5tresbsrdthbrdhvdtr'
    try:
      self.storage.removefile(self.endpoint, self.homepath + '/testoverwrite', self.userid)
    except IOError:
      pass
    self.storage.writefile(self.endpoint, self.homepath + '/testoverwrite', self.userid, buf, islock=True)
    statInfo = self.storage.stat(self.endpoint, self.homepath + '/testoverwrite', self.userid)
    self.assertIsInstance(statInfo, dict)
    with self.assertRaises(IOError) as context:
      self.storage.writefile(self.endpoint, self.homepath + '/testoverwrite', self.userid, buf, islock=True)
    self.assertIn(EXCL_ERROR, str(context.exception))
    self.storage.removefile(self.endpoint, self.homepath + '/testoverwrite', self.userid)

  def test_write_race(self):
    '''Test multithreaded double write with the islock flag'''
    buf = b'ebe5tresbsrdthbrdhvdtr'
    try:
      self.storage.removefile(self.endpoint, self.homepath + '/testwriterace', self.userid)
    except IOError:
      pass
    t = Thread(target=self.storage.writefile,
               args=[self.endpoint, self.homepath + '/testwriterace', self.userid, buf], kwargs={'islock': True})
    t.start()
    with self.assertRaises(IOError) as context:
      self.storage.writefile(self.endpoint, self.homepath + '/testwriterace', self.userid, buf, islock=True)
    self.assertIn(EXCL_ERROR, str(context.exception))
    t.join()
    self.storage.removefile(self.endpoint, self.homepath + '/testwriterace', self.userid)

  def test_lock(self):
    '''Test setting locks'''
    buf = b'ebe5tresbsrdthbrdhvdtr'
    try:
      self.storage.removefile(self.endpoint, self.homepath + '/testlock', self.userid)
    except IOError:
      pass
    self.storage.writefile(self.endpoint, self.homepath + '/testlock', self.userid, buf)
    statInfo = self.storage.stat(self.endpoint, self.homepath + '/testlock', self.userid)
    self.assertIsInstance(statInfo, dict)
    self.storage.setlock(self.endpoint, self.homepath + '/testlock', self.userid, 'testlock')
    l = self.storage.getlock(self.endpoint, self.homepath + '/testlock', self.userid)
    self.assertEqual(l, 'testlock')
    with self.assertRaises(IOError) as context:
      self.storage.setlock(self.endpoint, self.homepath + '/testlock', self.userid, 'testlock2')
    self.assertIn(EXCL_ERROR, str(context.exception))
    self.storage.unlock(self.endpoint, self.homepath + '/testlock', self.userid, 'myapp')
    self.storage.removefile(self.endpoint, self.homepath + '/testlock', self.userid)

  def test_refresh_lock(self):
    '''Test refreshing lock'''
    try:
      self.storage.removefile(self.endpoint, self.homepath + '/testrlock', self.userid)
    except IOError:
      pass
    self.storage.writefile(self.endpoint, self.homepath + '/testrlock', self.userid, databuf)
    statInfo = self.storage.stat(self.endpoint, self.homepath + '/testrlock', self.userid)
    self.assertIsInstance(statInfo, dict)
    with self.assertRaises(IOError) as context:
      self.storage.refreshlock(self.endpoint, self.homepath + '/testrlock', self.userid, 'myapp', 'testlock')
    self.assertIn('File was not locked', str(context.exception))
    self.storage.setlock(self.endpoint, self.homepath + '/testrlock', self.userid, 'myapp', 'testlock')
    self.storage.refreshlock(self.endpoint, self.homepath + '/testrlock', self.userid, 'myapp', 'testlock2')
    l = self.storage.getlock(self.endpoint, self.homepath + '/testrlock', self.userid)
    self.assertIsInstance(l, dict)
    self.assertEqual(l['md'], 'testlock2')
    self.assertEqual(l['h'], 'myapp')
    with self.assertRaises(IOError) as context:
      self.storage.refreshlock(self.endpoint, self.homepath + '/testrlock', self.userid, 'myapp2', 'testlock2')
    self.assertIn('File is locked by myapp', str(context.exception))
    self.storage.removefile(self.endpoint, self.homepath + '/testrlock', self.userid)
>>>>>>> Refactoring: introduced a common storage interface module

  def test_lock_race(self):
    '''Test multithreaded setting locks'''
    buf = b'ebe5tresbsrdthbrdhvdtr'
    try:
      self.storage.removefile(self.endpoint, self.homepath + '/testlockrace', self.userid)
    except IOError:
      pass
    self.storage.writefile(self.endpoint, self.homepath + '/testlockrace', self.userid, buf)
    statInfo = self.storage.stat(self.endpoint, self.homepath + '/testlockrace', self.userid)
    self.assertIsInstance(statInfo, dict)
    t = Thread(target=self.storage.setlock,
               args=[self.endpoint, self.homepath + '/testlockrace', self.userid, 'testlock'])
    t.start()
    with self.assertRaises(IOError) as context:
      self.storage.setlock(self.endpoint, self.homepath + '/testlockrace', self.userid, 'testlock2')
    self.assertIn(EXCL_ERROR, str(context.exception))
    self.storage.removefile(self.endpoint, self.homepath + '/testlockrace', self.userid)

  def test_remove_nofile(self):
    '''Test removal of a non-existing file'''
    with self.assertRaises(IOError):
      self.storage.removefile(self.endpoint, self.homepath + '/hopefullynotexisting', self.userid)

  def test_xattr(self):
    '''Test all xattr methods with special chars'''
    buf = b'bla\n'
    self.storage.writefile(self.endpoint, self.homepath + '/test&xattr.txt', self.userid, buf)
    self.storage.setxattr(self.endpoint, self.homepath + '/test&xattr.txt', self.userid, 'testkey', 123)
    v = self.storage.getxattr(self.endpoint, self.homepath + '/test&xattr.txt', self.userid, 'testkey')
    self.assertEqual(v, '123')
    self.storage.rmxattr(self.endpoint, self.homepath + '/test&xattr.txt', self.userid, 'testkey')
    v = self.storage.getxattr(self.endpoint, self.homepath + '/test&xattr.txt', self.userid, 'testkey')
    self.assertEqual(v, None)
    self.storage.removefile(self.endpoint, self.homepath + '/test&xattr.txt', self.userid)

  def test_rename_statx(self):
    '''Test renaming and statx of a file with special chars'''
    buf = b'bla\n'
    self.storage.writefile(self.endpoint, self.homepath + '/test.txt', self.userid, buf)
    self.storage.renamefile(self.endpoint, self.homepath + '/test.txt', self.homepath + '/test&renamed.txt', self.userid)
    statInfo = self.storage.statx(self.endpoint, self.homepath + '/test&renamed.txt', self.userid)
    self.assertEqual(statInfo['filepath'], self.homepath + '/test&renamed.txt')
    self.storage.renamefile(self.endpoint, self.homepath + '/test&renamed.txt', self.homepath + '/test.txt', self.userid)
    statInfo = self.storage.statx(self.endpoint, self.homepath + '/test.txt', self.userid)
    self.assertEqual(statInfo['filepath'], self.homepath + '/test.txt')
    self.storage.removefile(self.endpoint, self.homepath + '/test.txt', self.userid)


if __name__ == '__main__':
  TestStorage.globalinit()
  unittest.main()
