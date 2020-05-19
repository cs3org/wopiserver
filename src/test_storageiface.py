# Basic unit testing of the storage interfaces
#
# The tests only assume that a file test.txt be present in the top-level folder
# of the storage being tested, with content = 'bla\n'. This assumption is
# there for the time being to progressively test functions without depending
# on writefile().

import unittest
import logging
import configparser

class TestStorage(unittest.TestCase):
  '''Simple tests for the storage layers of the WOPI server'''
  endpoint = '123e4567-e89b-12d3-a456-426655440000'
  userid = 'einstein'
  storage = None

  def setUp(self):
    '''Setup the test: create a mock logging and import the library'''
    loghandler = logging.FileHandler('/var/log/wopi/wopiserver.log')
    loghandler.setFormatter(logging.Formatter(fmt='%(asctime)s %(name)s[%(process)d] %(levelname)-8s %(message)s',
                                              datefmt='%Y-%m-%dT%H:%M:%S'))
    log = logging.getLogger('wopiserver.test')
    log.addHandler(loghandler)
    log.setLevel(logging.DEBUG)
    # read the configuration
    config = configparser.ConfigParser()
    try:
      with open('/etc/wopi/wopiserver.defaults.conf') as fdef:
        config.read_file(fdef)
      config.read('/etc/wopi/wopiserver.conf')
      storagetype = config.get('general', 'storagetype')
    except (KeyError, configparser.NoOptionError):
      print("Missing option or missing configuration, check your /etc/wopi/wopiserver.conf file")
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
    statInfo = self.storage.stat(self.endpoint, '/test.txt', self.userid)
    self.assertIsInstance(statInfo, dict)
    self.assertEqual(statInfo['filepath'], '/test.txt', 'Filepath should be /test.txt')

  def test_stat_nofile(self):
    '''Call stat() and assert the exception is as expected'''
    with self.assertRaises(IOError):
      self.storage.stat(self.endpoint, '/hopefullynotexisting', self.userid)

  def test_statx(self):
    '''Call statx() and assert the path matches'''
    statInfo = self.storage.statx(self.endpoint, '/test.txt', self.userid)
    self.assertIsInstance(statInfo, dict)
    self.assertEqual(statInfo['filepath'], '/test.txt', 'Filepath should be /test.txt')

  def test_readfile(self):
    '''Assume a test.txt file exists with content = "bla"'''
    content = ''
    for chunk in self.storage.readfile(self.endpoint, '/test.txt', self.userid):
      self.assertNotIsInstance(chunk, IOError, 'storage.readfile raised exception: %s' % chunk)
      content += chunk.decode('utf-8')
    self.assertEqual(content, 'bla\n', 'File test.txt should contain the string "bla"')

  def test_writefile(self):
    '''Write some stuff to a file and assert the file is created'''
    buf = b'ebe5tresbsrdthbrdhvdtr'
    self.storage.writefile(self.endpoint, '/testwrite', self.userid, buf)
    statInfo = self.storage.stat(self.endpoint, '/testwrite', self.userid)
    self.assertIsInstance(statInfo, dict)

  def test_writeremove(self):
    '''Test removal of a file'''
    self.storage.removefile(self.endpoint, '/testwrite', self.userid)

  def test_remove_nofile(self):
    '''Test removal of a non-existing file'''
    with self.assertRaises(IOError):
      self.storage.removefile(self.endpoint, '/hopefullynotexisting', self.userid)

  def test_xattr(self):
    '''Test all xattr methods'''
    self.storage.setxattr(self.endpoint, '/test.txt', self.userid, 'testkey', 'testvalue')
    v = self.storage.getxattr(self.endpoint, '/test.txt', self.userid, 'testkey')
    self.assertEqual(v, b'testvalue')
    self.storage.rmxattr(self.endpoint, '/test.txt', self.userid, 'testkey')
    v = self.storage.getxattr(self.endpoint, '/test.txt', self.userid, 'testkey')
    self.assertEqual(v, None)

  def test_rename(self):
    '''Test renaming and stat of a file'''
    self.storage.renamefile(self.endpoint, '/test.txt', '/test_renamed.txt', self.userid)
    statInfo = self.storage.stat(self.endpoint, '/test_renamed.txt', self.userid)
    self.assertEqual(statInfo['filepath'], '/test_renamed.txt')
    self.storage.renamefile(self.endpoint, '/test_renamed.txt', '/test.txt', self.userid)
    statInfo = self.storage.stat(self.endpoint, '/test.txt', self.userid)
    self.assertEqual(statInfo['filepath'], '/test.txt')


if __name__ == '__main__':
  unittest.main()
