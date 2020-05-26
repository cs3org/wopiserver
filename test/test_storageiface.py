'''
test_storageiface.py

Basic unit testing of the storage interfaces
'''

import unittest
import logging
import configparser
import sys
sys.path.append('../src')


class TestStorage(unittest.TestCase):
  '''Simple tests for the storage layers of the WOPI server'''

  def __init__(self, *args, **kwargs):
    '''One-off initialization of the test environment: create mock logging and import the library'''
    super(TestStorage, self).__init__(*args, **kwargs)
    loghandler = logging.FileHandler('/tmp/wopiserver.log')
    loghandler.setFormatter(logging.Formatter(fmt='%(asctime)s %(name)s[%(process)d] %(levelname)-8s %(message)s',
                                              datefmt='%Y-%m-%dT%H:%M:%S'))
    log = logging.getLogger('wopiserver.test')
    log.addHandler(loghandler)
    log.setLevel(logging.DEBUG)
    # read the configuration
    config = configparser.ConfigParser()
    try:
      with open('wopiserver-test.conf') as fdef:
        config.read_file(fdef)
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
    except ImportError:
      print("Missing module when attempting to import {}. Please make sure dependencies are met.", storagetype)
      raise


  def test_stat(self):
    '''Call stat() and assert the path matches'''
    buf = b'bla\n'
    self.storage.writefile(self.endpoint, '/test.txt', self.userid, buf)
    statInfo = self.storage.stat(self.endpoint, '/test.txt', self.userid)
    self.assertIsInstance(statInfo, dict)
    self.assertTrue('mtime' in statInfo, 'Missing mtime from stat output')
    self.assertTrue('size' in statInfo, 'Missing size from stat output')
    self.storage.removefile(self.endpoint, '/test.txt', self.userid)

  def test_statx_fileid(self):
    '''Call stat() and assert the path matches'''
    buf = b'bla\n'
    self.storage.writefile(self.endpoint, '/test.txt', self.userid, buf)
    statInfo = self.storage.statx(self.endpoint, '/test.txt', self.userid)
    self.assertIsInstance(statInfo, dict)
    fileid = statInfo['inode'].split(':')
    self.assertEqual(len(fileid), 2, 'This storage interface does not support stat by fileid')
    statInfo = self.storage.statx(fileid[0], fileid[1], self.userid)
    self.assertIsInstance(statInfo, dict)
    self.assertEqual(statInfo['filepath'], '/test.txt', 'Filepath should be /test.txt')
    self.storage.removefile(self.endpoint, '/test.txt', self.userid)

  def test_stat_nofile(self):
    '''Call stat() and assert the exception is as expected'''
    with self.assertRaises(IOError, msg='No such file or directory'):
      self.storage.stat(self.endpoint, '/hopefullynotexisting', self.userid)

  def test_statx_nofile(self):
    '''Call statx() and assert the exception is as expected'''
    with self.assertRaises(IOError, msg='No such file or directory'):
      self.storage.statx(self.endpoint, '/hopefullynotexisting', self.userid)

  def test_readfile(self):
    '''Writes a file and reads it back, validating that the content matches'''
    content = b'bla\n'
    self.storage.writefile(self.endpoint, '/test.txt', self.userid, content)
    content = ''
    for chunk in self.storage.readfile(self.endpoint, '/test.txt', self.userid):
      self.assertNotIsInstance(chunk, IOError, 'raised by storage.readfile')
      content += chunk.decode('utf-8')
    self.assertEqual(content, 'bla\n', 'File test.txt should contain the string "bla"')
    self.storage.removefile(self.endpoint, '/test.txt', self.userid)

  def test_read_nofile(self):
    '''Test reading of a non-existing file'''
    readex = next(self.storage.readfile(self.endpoint, '/hopefullynotexisting', self.userid))
    self.assertIsInstance(readex, IOError, 'readfile returned %s' % readex)
    self.assertEqual(str(readex), 'No such file or directory', 'readfile returned %s' % readex)

  def test_write_remove(self):
    '''Test write and removal of a file'''
    buf = b'ebe5tresbsrdthbrdhvdtr'
    self.storage.writefile(self.endpoint, '/testwrite', self.userid, buf)
    statInfo = self.storage.stat(self.endpoint, '/testwrite', self.userid)
    self.assertIsInstance(statInfo, dict)
    self.storage.removefile(self.endpoint, '/testwrite', self.userid)
    with self.assertRaises(IOError):
      self.storage.stat(self.endpoint, '/testwrite', self.userid)

  def test_remove_nofile(self):
    '''Test removal of a non-existing file'''
    with self.assertRaises(IOError):
      self.storage.removefile(self.endpoint, '/hopefullynotexisting', self.userid)

  def test_xattr(self):
    '''Test all xattr methods'''
    buf = b'bla\n'
    self.storage.writefile(self.endpoint, '/testxattr.txt', self.userid, buf)
    self.storage.setxattr(self.endpoint, '/testxattr.txt', self.userid, 'testkey', 'testvalue')
    v = self.storage.getxattr(self.endpoint, '/testxattr.txt', self.userid, 'testkey')
    self.assertEqual(v, 'testvalue')
    self.storage.rmxattr(self.endpoint, '/testxattr.txt', self.userid, 'testkey')
    v = self.storage.getxattr(self.endpoint, '/testxattr.txt', self.userid, 'testkey')
    self.assertEqual(v, None)
    self.storage.removefile(self.endpoint, '/testxattr.txt', self.userid)

  def test_rename_statx(self):
    '''Test renaming and statx of a file'''
    buf = b'bla\n'
    self.storage.writefile(self.endpoint, '/test.txt', self.userid, buf)
    self.storage.renamefile(self.endpoint, '/test.txt', '/test_renamed.txt', self.userid)
    statInfo = self.storage.statx(self.endpoint, '/test_renamed.txt', self.userid)
    self.assertEqual(statInfo['filepath'], '/test_renamed.txt')
    self.storage.renamefile(self.endpoint, '/test_renamed.txt', '/test.txt', self.userid)
    statInfo = self.storage.statx(self.endpoint, '/test.txt', self.userid)
    self.assertEqual(statInfo['filepath'], '/test.txt')
    self.storage.removefile(self.endpoint, '/test.txt', self.userid)


if __name__ == '__main__':
  unittest.main()
