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
import time
sys.path.append('../src')  # for tests out of the git repo
sys.path.append('/app')    # for tests within the Docker image


class TestStorage(unittest.TestCase):
  '''Simple tests for the storage layers of the WOPI server. See README for how to run the tests for each storage provider'''

  def __init__(self, *args, **kwargs):
    '''One-off initialization of the test environment: create mock logging and import the library'''
    super(TestStorage, self).__init__(*args, **kwargs)
    loghandler = logging.FileHandler('/tmp/wopiserver.log')
    loghandler.setFormatter(logging.Formatter(fmt='%(asctime)s %(name)s[%(process)d] %(levelname)-8s %(message)s',
                                              datefmt='%Y-%m-%dT%H:%M:%S'))
    log = logging.getLogger('wopiserver.test')
    log.addHandler(loghandler)
    log.setLevel(logging.DEBUG)
    config = configparser.ConfigParser()
    try:
      with open('wopiserver-test.conf') as fdconf:
        config.read_file(fdconf)
      storagetype = os.environ.get('WOPI_STORAGE')
      if not storagetype:
        storagetype = config.get('general', 'storagetype')
      self.userid = config.get(storagetype, 'userid')
      self.endpoint = config.get(storagetype, 'endpoint')
    except (KeyError, configparser.NoOptionError):
      print("Missing option or missing configuration, check the wopiserver-test.conf file")
      raise

    # this is taken from wopiserver.py::storage_layer_import
    if storagetype in ['local', 'xroot', 'cs3']:
      storagetype += 'iface'
    else:
      raise ImportError('Unsupported/Unknown storage type %s' % storagetype)
    try:
      self.storage = __import__(storagetype, globals(), locals())
      self.storage.init(config, log)
      self.homepath = ''
      if storagetype == 'cs3iface':
        # we need to login for this case
        self.username = self.userid
        self.userid = self.storage.authenticate_for_test(self.userid, config.get('cs3', 'userpwd'))
        self.homepath = config.get('cs3', 'storagehomepath')
    except ImportError:
      print("Missing module when attempting to import {}. Please make sure dependencies are met.", storagetype)
      raise


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
    if self.endpoint in statInfo['inode']:
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
    self.assertIn('No such file or directory', str(context.exception))

  def test_statx_nofile(self):
    '''Call statx() and assert the exception is as expected'''
    with self.assertRaises(IOError) as context:
      self.storage.statx(self.endpoint, self.homepath + '/hopefullynotexisting', self.userid)
    self.assertIn('No such file or directory', str(context.exception))

  def test_readfile(self):
    '''Writes a file and reads it back, validating that the content matches'''
    content = b'bla\n'
    self.storage.writefile(self.endpoint, self.homepath + '/test.txt', self.userid, content)
    content = ''
    for chunk in self.storage.readfile(self.endpoint, self.homepath + '/test.txt', self.userid):
      self.assertNotIsInstance(chunk, IOError, 'raised by storage.readfile')
      content += chunk.decode('utf-8')
    self.assertEqual(content, 'bla\n', 'File test.txt should contain the string "bla"')
    self.storage.removefile(self.endpoint, self.homepath + '/test.txt', self.userid)

  def test_read_nofile(self):
    '''Test reading of a non-existing file'''
    readex = next(self.storage.readfile(self.endpoint, self.homepath + '/hopefullynotexisting', self.userid))
    self.assertIsInstance(readex, IOError, 'readfile returned %s' % readex)
    self.assertEqual(str(readex), 'No such file or directory', 'readfile returned %s' % readex)

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
      self.storage.removefile(self.endpoint, '/testoverwrite', self.userid)
    except IOError:
      pass
    self.storage.writefile(self.endpoint, '/testoverwrite', self.userid, buf, islock=True)
    statInfo = self.storage.stat(self.endpoint, '/testoverwrite', self.userid)
    self.assertIsInstance(statInfo, dict)
    with self.assertRaises(IOError) as context:
      self.storage.writefile(self.endpoint, '/testoverwrite', self.userid, buf, islock=True)
    self.assertIn('File exists and islock flag requested', str(context.exception))
    self.storage.removefile(self.endpoint, '/testoverwrite', self.userid)

  def test_write_race(self):
    '''Test multithreaded double write with the islock flag'''
    buf = b'ebe5tresbsrdthbrdhvdtr'
    try:
      self.storage.removefile(self.endpoint, '/testwriterace', self.userid)
    except IOError:
      pass
    t = Thread(target=self.storage.writefile,
               args=[self.endpoint, '/testwriterace', self.userid, buf], kwargs={'islock': True})
    t.start()
    with self.assertRaises(IOError) as context:
      self.storage.writefile(self.endpoint, '/testwriterace', self.userid, buf, islock=True)
    self.assertIn('File exists and islock flag requested', str(context.exception))
    t.join()
    self.storage.removefile(self.endpoint, '/testwriterace', self.userid)

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
  unittest.main()
